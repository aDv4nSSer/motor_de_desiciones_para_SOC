"""
H56: AbuseIPDB solo se consulta cuando puede cambiar la decisión de R2.

- Debajo de r2_min_tier (T2 nunca bloquea) solo se lee la caché.
- Con ABUSEIPDB_NON_DECISIVE_SHARE = 0, un T3 sin corroboración de OTX no
  consulta: AbuseIPDB llevaría count a 1 como máximo.
- TTL asimétrico: 24 h si el score es malicioso, 6 h si no (test en
  test_ti_negative_cache.py).
- El log cuenta las llamadas reales por tier, para verificar post-deploy que
  T2 hace 0.

La prueba central es de INVARIANCIA sobre docs reales del 8-oct
(tests/fixtures/h56_replay_docs.json): con la misma respuesta de AbuseIPDB
para cada IP y sin límite de cuota, la decisión de R2 es idéntica con y sin
el cambio. Lo único que cambia es si AbuseIPDB se consultó.

Redis y las APIs siempre falsos; nunca se llama a AbuseIPDB ni OTX reales.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import response.enrichment as enr
from response.config import ResponseSettings
from response.enrichment import ABUSEIPDB_URL, BELOW_R2_NOTE, enrich
from response.schemas import ActionType, AlertLookupResult, BlockResult, ResponseTask
from response.worker import process_task

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "h56_replay_docs.json"
DOCS = json.loads(FIXTURE.read_text())["docs"]


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}

    def get(self, key):
        return self.kv.get(key)

    def setex(self, key, ttl, value):
        self.kv[key] = value

    def incr(self, key):
        self.kv[key] = str(int(self.kv.get(key) or 0) + 1)
        return int(self.kv[key])

    def expire(self, key, ttl):
        return True


class FakeTI:
    """httpx.get falso con un oráculo por IP: OTX devuelve los pulses del doc
    (None = timeout) y AbuseIPDB el score real observado. Cuenta llamadas."""

    def __init__(self, otx: dict[str, int | None], abuse: dict[str, int]):
        self.otx, self.abuse = otx, abuse
        self.calls = {"otx": 0, "abuseipdb": 0}

    def __call__(self, url, params=None, **kw):
        req = httpx.Request("GET", url)
        if url == ABUSEIPDB_URL:
            self.calls["abuseipdb"] += 1
            ip = params["ipAddress"]
            return httpx.Response(200, request=req, json={"data": {
                "abuseConfidenceScore": self.abuse.get(ip, 0), "totalReports": 1, "countryCode": "XX"}})
        self.calls["otx"] += 1
        ip = url.split("/IPv4/")[1].split("/")[0] if "/IPv4/" in url else url.split("/IPv6/")[1].split("/")[0]
        pulses = self.otx.get(ip, 0)
        if pulses is None:
            raise httpx.ReadTimeout("lento")
        return httpx.Response(200, request=req, json={"pulse_info": {"count": pulses}})


def _settings(**kw) -> ResponseSettings:
    base = {"abuseipdb_api_key": "k", "otx_api_key": "k", "crowdsec_lapi_url": "",
            "r1_min_tier": 2, "r2_min_tier": 3, "min_corroborating_sources_for_autoblock": 2,
            "response_mode": "dry_run"}
    base.update(kw)
    return ResponseSettings(**base)


@pytest.fixture(autouse=True)
def _limpio(mocker):
    enr._quota_seen, enr._quota_limit_warned, enr._calls_since_seen = None, False, 0
    enr._api_calls_by_tier.clear()
    mocker.patch("response.enrichment._reverse_dns", return_value=None)
    yield
    enr._api_calls_by_tier.clear()


def _ti(ip="1.2.3.4", pulses=24, score=90) -> FakeTI:
    return FakeTI({ip: pulses}, {ip: score})


class TestPoliticaPorTier:
    def test_t2_no_llama_a_la_api(self, mocker) -> None:
        ti = _ti()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        r = enrich("1.2.3.4", _settings(), FakeRedis(), tier=2)
        assert ti.calls == {"otx": 1, "abuseipdb": 0}  # OTX sigue igual
        assert r.abuseipdb_available is False
        assert f"abuseipdb: {BELOW_R2_NOTE}" in r.notes

    def test_t2_lee_la_cache(self, mocker) -> None:
        rdb = FakeRedis()
        rdb.kv["soc:enrich:1.2.3.4"] = json.dumps({"score": 77, "reports": 3, "country": "NL"})
        ti = _ti()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        r = enrich("1.2.3.4", _settings(), rdb, tier=2)
        assert ti.calls["abuseipdb"] == 0
        assert r.abuseipdb_available is True and r.abuseipdb_score == 77 and r.cached

    @pytest.mark.parametrize("tier,r2_min,calls", [(3, 3, 1), (2, 3, 0), (2, 2, 1), (1, 2, 0), (None, 3, 1)],
                             ids=["t3_en_borde", "t2_bajo_borde", "t2_con_r2_desde_t2", "t1_bajo_t2", "sin_tier_legado"])
    def test_borde_de_r2_min_tier(self, mocker, tier, r2_min, calls) -> None:
        ti = _ti()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        enrich("1.2.3.4", _settings(r2_min_tier=r2_min), FakeRedis(), tier=tier)
        assert ti.calls["abuseipdb"] == calls

    def test_t3_stale_sigue_sin_consultar(self, mocker) -> None:
        ti = _ti()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        enrich("1.2.3.4", _settings(), FakeRedis(), cache_only=True, tier=3)
        assert ti.calls == {"otx": 0, "abuseipdb": 0}

    def test_t3_otx_corrobora_y_abuseipdb_alto_llega_a_count_2(self, mocker) -> None:
        ti = _ti()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        r = enrich("1.2.3.4", _settings(), FakeRedis(), tier=3)
        assert ti.calls["abuseipdb"] == 1 and r.corroboration_count == 2


class TestContadorPorTier:
    def test_el_log_cuenta_las_llamadas_reales_por_tier(self, mocker, caplog) -> None:
        mocker.patch("response.enrichment.httpx.get", side_effect=FakeTI(
            {f"1.2.3.{i}": 24 for i in range(1, 6)}, {f"1.2.3.{i}": 90 for i in range(1, 6)}))
        rdb = FakeRedis()
        with caplog.at_level(logging.INFO, logger="response.r1"):
            for i, tier in enumerate((3, 2, 3, 2, 3), start=1):
                enrich(f"1.2.3.{i}", _settings(), rdb, tier=tier)
        lines = [r.message for r in caplog.records if r.message.startswith("AbuseIPDB API tier=")]
        assert len(lines) == 3 and all("tier=3" in m for m in lines)
        assert lines[-1].endswith("(proceso: T3=3)")  # T2 nunca aparece
        assert dict(enr._api_calls_by_tier) == {"T3": 3}

    def test_el_worker_pasa_el_tier(self, mocker) -> None:
        spy = mocker.patch("response.worker.enrich", wraps=enrich)
        mocker.patch("response.enrichment.httpx.get", side_effect=_ti("1.2.3.4"))
        mocker.patch("response.worker.lookup_suricata_alert", return_value=AlertLookupResult(status="no_match"))
        mocker.patch("response.worker.open_case", return_value={"case_id": "c"})
        rdb = mocker.MagicMock(**{"get.return_value": None})
        rdb.pipeline.return_value.execute.return_value = [0, 1, 0, 0, True]
        task = ResponseTask(trace_id="t-h56", tier=2, risk_score=0.6, src_ip="1.2.3.4",
                            dst_ip="200.54.12.139", L4_DST_PORT=80, ts=time.time())
        process_task(task, _settings(), rdb, mocker.MagicMock())
        assert spy.call_args.kwargs["tier"] == 2


def _replay(mocker, doc, new_policy: bool):
    """process_task real sobre un doc del fixture, con dependencias de IO
    falsas y cuota ilimitada. new_policy=False reproduce el comportamiento
    previo a H56: enrich sin tier y cupo no decisivo en 0.5."""
    ip = doc["src_ip"]
    ti = FakeTI({ip: doc["otx"]}, {ip: doc["abuseipdb_score"]})
    mocker.patch("response.enrichment.httpx.get", side_effect=ti)
    mocker.patch("response.enrichment.abuseipdb_window_budget", return_value=10**6)
    if new_policy:
        mocker.patch("response.worker.enrich", side_effect=enrich)
        mocker.patch("response.enrichment.ABUSEIPDB_NON_DECISIVE_SHARE", 0.0)
    else:
        mocker.patch("response.worker.enrich",
                     side_effect=lambda src, s, r, cache_only=False, tier=None: enrich(src, s, r, cache_only=cache_only))
        mocker.patch("response.enrichment.ABUSEIPDB_NON_DECISIVE_SHARE", 0.5)
    mocker.patch("response.worker.lookup_suricata_alert", return_value=AlertLookupResult(status="no_match"))
    block = mocker.patch("response.worker.respond_block", return_value=BlockResult(
        src_ip=ip, action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado", enforcer="dry_run"))
    pending = mocker.patch("response.worker.create_pending_approval")
    case = mocker.patch("response.worker.open_case", return_value={"case_id": "c"})
    rdb = FakeRedis()
    rdb.pipeline = mocker.MagicMock()
    rdb.pipeline.return_value.execute.return_value = [0, 1, 0, 0, True]
    rdb.xadd = mocker.MagicMock()
    task = ResponseTask(trace_id="t-replay", tier=doc["tier"], risk_score=doc["risk_score"], src_ip=ip,
                        dst_ip="200.54.12.139", L4_DST_PORT=doc["dst_port"] or 80, ts=time.time())
    rec = process_task(task, _settings(), rdb, mocker.MagicMock())
    decision = (rec.accion_recomendada, rec.block.action if rec.block else None,
                block.call_count, pending.call_count, case.call_count)
    return decision, ti.calls["abuseipdb"], rec.enrichment.abuseipdb_available


class TestInvarianciaSobreDocsReales:
    def test_fixture_cubre_los_estratos(self) -> None:
        tiers = {d["tier"] for d in DOCS}
        assert tiers == {2, 3} and len(DOCS) >= 150
        assert any(d["tier"] == 3 and (d["otx"] or 0) >= 1 and d["abuseipdb_score"] >= 50 for d in DOCS)
        assert any(d["tier"] == 3 and d["otx"] is None for d in DOCS)

    def test_la_decision_de_r2_no_cambia(self, mocker) -> None:
        diffs, calls_old, calls_new, blocks = [], 0, 0, 0
        for doc in DOCS:
            old, c_old, _ = _replay(mocker, doc, new_policy=False)
            new, c_new, _ = _replay(mocker, doc, new_policy=True)
            calls_old += c_old
            calls_new += c_new
            blocks += new[2]
            if old != new:
                diffs.append((doc["src_ip"], doc["tier"], old, new))
            if doc["tier"] == 2 or not (doc["otx"] or 0) >= 1:
                assert c_new == 0  # T2 y T3 no decisivos: sin consulta
        assert diffs == []
        assert blocks > 0                       # el fixture sí ejercita la rama de bloqueo
        assert calls_new < calls_old            # y la política nueva ahorra consultas
