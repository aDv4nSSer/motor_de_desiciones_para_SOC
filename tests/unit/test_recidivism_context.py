"""
H53: grupo `context` mínimo -- recidivismo por IP sobre el acumulador Redis
`risk:ip:{ip}` (response/recidivism.py) y su efecto en el score
(scoring/corroboration.py). Redis siempre falso (FakeZRedis), nunca real.

Semántica acordada el 7-oct-2026:
- Cuenta HORAS distintas con incidente T2+ en los 30 días previos, sin la
  hora del propio evento (una ráfaga no se cuenta a sí misma).
- Recidivismo 0 = disponible ("primera vez") pero no aporta al score ni al
  desacuerdo (evidencia unilateral).
- ml y context son una sola familia para P3: context no alcanza para "high"
  sin ti o signature.
- IPs propias/privadas/safelist quedan fuera (context no disponible).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from constants import (
    RECIDIVISM_BUCKET_SECONDS,
    RECIDIVISM_MAX_MEMBERS,
    RECIDIVISM_WINDOW_SECONDS,
)
from response.config import ResponseSettings
from response.recidivism import bucket_start, count_and_record, risk_key
from response.schemas import AlertLookupResult, EnrichmentResult, ResponseTask
from response.worker import process_task
from scoring.corroboration import compute_corroboration

IP = "91.92.42.88"
H = RECIDIVISM_BUCKET_SECONDS
T0 = 1_791_400_000.0 - (1_791_400_000.0 % H)  # inicio de un bucket


class FakeZRedis:
    """Sorted sets con la semántica de rangos que usa recidivism.py
    (incluido el "(" de límite exclusivo) y un pipeline que ejecuta en orden."""

    def __init__(self, fail: bool = False):
        self.z: dict[str, dict[str, float]] = {}
        self.ttl: dict[str, int] = {}
        self.fail = fail

    @staticmethod
    def _bound(v) -> tuple[float, bool]:
        if isinstance(v, str):
            if v == "-inf":
                return float("-inf"), False
            if v.startswith("("):
                return float(v[1:]), True
            return float(v), False
        return float(v), False

    def _in(self, score, lo, hi) -> bool:
        (lv, lx), (hv, hx) = self._bound(lo), self._bound(hi)
        return (score > lv if lx else score >= lv) and (score < hv if hx else score <= hv)

    def zcount(self, key, lo, hi):
        return sum(1 for s in self.z.get(key, {}).values() if self._in(s, lo, hi))

    def zadd(self, key, mapping):
        self.z.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zremrangebyscore(self, key, lo, hi):
        d = self.z.get(key, {})
        for m in [m for m, s in d.items() if self._in(s, lo, hi)]:
            del d[m]

    def zremrangebyrank(self, key, start, stop):
        d = self.z.get(key, {})
        ordered = sorted(d, key=d.get)
        n = len(ordered)
        stop = n + stop if stop < 0 else stop
        if stop < 0:  # como Redis: rango vacío, no borra nada
            return
        for m in ordered[start:stop + 1]:
            del d[m]

    def expire(self, key, seconds):
        self.ttl[key] = seconds
        return True

    def pipeline(self, transaction=True):
        outer = self

        class _Pipe:
            def __init__(self):
                self.ops = []

            def __getattr__(self, name):
                return lambda *a, **k: self.ops.append((name, a, k))

            def execute(self):
                if outer.fail:
                    raise redis.ConnectionError("Redis caído")
                return [getattr(outer, n)(*a, **k) for n, a, k in self.ops]

        return _Pipe()


def _ctx(result):
    return next(g for g in result.groups if g.name == "context")


def _corr(recidivism, enrichment=None, risk=0.83, **kw):
    return compute_corroboration(
        risk_score=risk, classtype="", classtype_override=False, attack_mapped=False,
        enrichment=enrichment, settings=ResponseSettings(**kw), recidivism_count=recidivism,
        context_unavailable_reason="sin dato" if recidivism is None else "",
    )


TI_FUERTE = EnrichmentResult(src_ip=IP, otx_available=True, otx_pulse_count=24, abuseipdb_available=False)


class TestAcumulador:
    def test_entidad_sin_historial_cuenta_0_y_registra_el_bucket(self) -> None:
        r = FakeZRedis()
        assert count_and_record(r, IP, T0 + 10, now=T0 + 10) == 0
        assert r.z[risk_key(IP)] == {str(int(T0)): T0}
        assert r.ttl[risk_key(IP)] == RECIDIVISM_WINDOW_SECONDS

    def test_misma_hora_no_se_cuenta_a_si_misma(self) -> None:
        r = FakeZRedis()
        count_and_record(r, IP, T0 + 10, now=T0 + 10)
        assert count_and_record(r, IP, T0 + 3000, now=T0 + 3000) == 0
        assert len(r.z[risk_key(IP)]) == 1

    def test_n_horas_previas_dentro_de_30_dias(self) -> None:
        r = FakeZRedis()
        for h in range(3):
            count_and_record(r, IP, T0 + h * H, now=T0 + h * H)
        assert count_and_record(r, IP, T0 + 5 * H, now=T0 + 5 * H) == 3

    def test_fuera_de_la_ventana_no_cuenta(self) -> None:
        r = FakeZRedis()
        old = T0 - RECIDIVISM_WINDOW_SECONDS - H
        r.z[risk_key(IP)] = {str(int(old)): old, str(int(T0 - H)): T0 - H}
        assert count_and_record(r, IP, T0 + 10, now=T0 + 10) == 1
        # Y la limpieza borra el vencido.
        assert str(int(old)) not in r.z[risk_key(IP)]

    def test_tope_de_miembros(self) -> None:
        r = FakeZRedis()
        for h in range(RECIDIVISM_MAX_MEMBERS + 10):
            count_and_record(r, IP, T0 + h * H, now=T0 + h * H)
        assert len(r.z[risk_key(IP)]) == RECIDIVISM_MAX_MEMBERS

    def test_redis_caido_devuelve_none_sin_lanzar(self) -> None:
        assert count_and_record(FakeZRedis(fail=True), IP, T0, now=T0) is None

    def test_bucket_start(self) -> None:
        assert bucket_start(T0 + H - 1) == T0 and bucket_start(T0 + H) == T0 + H


class TestGrupoContexto:
    def test_sin_historial_disponible_score_0_y_no_aporta(self) -> None:
        res = _corr(0, TI_FUERTE)
        g = _ctx(res)
        assert g.available is True and g.score == 0.0 and g.contributes is False
        assert "primera vez" in g.detail
        # No baja el score ni dispara desacuerdo: igual que sin el grupo.
        assert res.score == _corr(None, TI_FUERTE).score
        assert res.band == _corr(None, TI_FUERTE).band == "high"

    @pytest.mark.parametrize("n,expected", [(1, 0.2), (3, 0.6), (5, 1.0), (40, 1.0)])
    def test_normalizado_contra_la_saturacion(self, n, expected) -> None:
        g = _ctx(_corr(n))
        assert g.available is True and g.contributes is True
        assert g.score == pytest.approx(expected)
        assert f"recidivismo: {n} horas" in g.detail

    def test_redis_no_disponible_grupo_no_disponible(self) -> None:
        g = _ctx(_corr(None))
        assert g.available is False and "sin dato" in g.detail

    def test_ml_mas_context_saturado_no_llega_a_high(self) -> None:
        """P3 por familias: el recidivismo sale de decisiones del mismo ML."""
        res = _corr(40, risk=1.0)
        assert res.score == 100.0
        assert res.band == "medium"
        assert any("P3" in line for line in res.reasoning)

    def test_ml_mas_context_mas_ti_si_llega_a_high(self) -> None:
        assert _corr(5, TI_FUERTE, risk=0.9).band == "high"


class TestIntegracionWorker:
    def test_dos_t3_de_la_misma_ip_en_horas_distintas(self, mocker) -> None:
        fake = FakeZRedis()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        rdb.pipeline.side_effect = fake.pipeline
        mocker.patch("response.worker.enrich", return_value=TI_FUERTE)
        mocker.patch("response.worker.create_pending_approval")
        mocker.patch("response.worker.lookup_suricata_alert",
                     return_value=AlertLookupResult(status="no_match"))
        settings = ResponseSettings(r1_min_tier=2, r2_min_tier=3, response_mode="dry_run",
                                    stale_event_max_age_seconds=10 * 86400)
        now = time.time()

        def task(n, ts):
            return ResponseTask(trace_id=f"trace-rec-{n}", tier=3, risk_score=0.83, src_ip=IP,
                                dst_ip="200.54.12.139", L4_DST_PORT=443, ts=ts)

        first = process_task(task(1, now - 3 * H), settings, rdb, mocker.MagicMock())
        second = process_task(task(2, now), settings, rdb, mocker.MagicMock())

        assert first.recidivism_count == 0
        assert second.recidivism_count == 1
        g = next(g for g in second.corroboration_groups if g["name"] == "context")
        assert g["available"] is True and g["score"] == pytest.approx(0.2)
        (_s, fields), _ = rdb.xadd.call_args
        assert json.loads(fields["data"])["recidivism_count"] == 1
        # La decisión real no cambia: count=1 -> pendiente de aprobación en ambas.
        assert first.block.action == second.block.action

    def test_ip_privada_no_se_registra(self, mocker) -> None:
        fake = FakeZRedis()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        rdb.pipeline.side_effect = fake.pipeline
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult())
        mocker.patch("response.worker.lookup_suricata_alert",
                     return_value=AlertLookupResult(status="no_match"))
        rec = process_task(ResponseTask(trace_id="trace-rec-p", tier=3, risk_score=0.83,
                                        src_ip="10.30.30.2", dst_ip="10.10.10.3", L4_DST_PORT=22,
                                        ts=time.time()),
                           ResponseSettings(r1_min_tier=2, r2_min_tier=3), rdb, mocker.MagicMock())
        assert rec.recidivism_count is None and fake.z == {}
        g = next(g for g in rec.corroboration_groups if g["name"] == "context")
        assert g["available"] is False and "safelist" in g["detail"]
