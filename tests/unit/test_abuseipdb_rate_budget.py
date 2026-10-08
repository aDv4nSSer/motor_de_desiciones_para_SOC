"""
H52 (ampliación): reparto de la cuota diaria de AbuseIPDB con un token bucket
por ventana (`ti:rate:abuseipdb:{inicio}`) y prioridad a las consultas que
pueden cambiar la decisión de R2.

Diseño acordado el 2026-10-07 (no el literal del pedido original): OTX se
consulta primero; un cupo de AbuseIPDB es "decisivo" cuando OTX ya corrobora,
porque con el gate vigente (count >= 2) solo ahí AbuseIPDB puede llevar count
de 1 a 2. Las decisivas pueden usar todo el presupuesto de la ventana; las no
decisivas, solo ABUSEIPDB_NON_DECISIVE_SHARE. Saltear AbuseIPDB cuando OTX
corrobora (el pedido literal) volvía inalcanzable el gate.

Redis y las APIs siempre falsos; nunca se llama a AbuseIPDB ni OTX reales.
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from constants import ABUSEIPDB_NON_DECISIVE_SHARE, ABUSEIPDB_RATE_WINDOW_SECONDS
from response.config import ResponseSettings
from response.enrichment import (
    ABUSEIPDB_URL,
    _abuseipdb_lookup,
    _abuseipdb_rate_key,
    abuseipdb_window_budget,
    enrich,
)

T0 = 1_791_417_600.0  # 2026-10-08 00:00:00Z, inicio de una ventana


class FakeRedis:
    def __init__(self, fail_bucket: bool = False):
        self.kv: dict[str, str] = {}
        self.fail_bucket = fail_bucket

    def get(self, key):
        if self.fail_bucket and key.startswith("ti:rate:"):
            raise redis.ConnectionError("caído")
        return self.kv.get(key)

    def setex(self, key, ttl, value):
        self.kv[key] = value

    def incr(self, key):
        self.kv[key] = str(int(self.kv.get(key) or 0) + 1)
        return int(self.kv[key])

    def expire(self, key, ttl):
        return True


class FakeTI:
    """httpx.get falso: OTX devuelve `pulses` (o falla), AbuseIPDB un score.
    Cuenta las llamadas reales a cada API."""

    def __init__(self, pulses: int | None = 24, otx_error: Exception | None = None, abuse_score: int = 90):
        self.pulses, self.otx_error, self.abuse_score = pulses, otx_error, abuse_score
        self.calls = {"otx": 0, "abuseipdb": 0}

    def __call__(self, url, **kw):
        req = httpx.Request("GET", url)
        if url == ABUSEIPDB_URL:
            self.calls["abuseipdb"] += 1
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": self.abuse_score,
                                                      "totalReports": 9, "countryCode": "NL"}}, request=req)
        self.calls["otx"] += 1
        if self.otx_error:
            raise self.otx_error
        return httpx.Response(200, json={"pulse_info": {"count": self.pulses}}, request=req)


def _settings(**kw) -> ResponseSettings:
    base = {"abuseipdb_api_key": "k", "otx_api_key": "k", "crowdsec_lapi_url": ""}
    base.update(kw)
    return ResponseSettings(**base)


@pytest.fixture
def clock(mocker):
    now = {"t": T0 + 1}
    mocker.patch("response.enrichment.time.time", side_effect=lambda: now["t"])
    mocker.patch("response.enrichment._reverse_dns", return_value=None)
    return now


def _run(mocker, ip, rdb, ti, settings=None):
    mocker.patch("response.enrichment.httpx.get", side_effect=ti)
    return enrich(ip, settings or _settings(), rdb)


class TestPresupuesto:
    def test_derivado_de_la_cuota_configurada(self) -> None:
        assert abuseipdb_window_budget(_settings(abuseipdb_daily_quota=1000)) == 6
        assert abuseipdb_window_budget(_settings(abuseipdb_daily_quota=5000)) == 34
        assert abuseipdb_window_budget(_settings(abuseipdb_daily_quota=10)) == 1  # nunca 0
        # Nunca supera la cuota diaria.
        per_day = abuseipdb_window_budget(_settings()) * (86400 // ABUSEIPDB_RATE_WINDOW_SECONDS)
        assert per_day <= _settings().abuseipdb_daily_quota

    def test_bucket_vacio_omite_abuseipdb_y_otx_sigue(self, mocker, clock) -> None:
        rdb, ti = FakeRedis(), FakeTI(pulses=24)
        rdb.kv[_abuseipdb_rate_key(clock["t"])] = str(abuseipdb_window_budget(_settings()))
        r = _run(mocker, "1.2.3.4", rdb, ti)
        assert ti.calls == {"otx": 1, "abuseipdb": 0}
        assert r.otx_available is True and r.otx_pulse_count == 24
        assert r.abuseipdb_available is False
        assert any("omitido por throttling" in n and "presupuesto de la ventana agotado" in n for n in r.notes)
        assert r.corroboration_count == 1  # no disponible no cuenta ni a favor ni en contra

    def test_cache_hit_no_gasta_cupo(self, mocker, clock) -> None:
        rdb, ti = FakeRedis(), FakeTI()
        s = _settings()
        rdb.kv[f"{s.enrich_cache_prefix}1.2.3.4"] = '{"score": 90, "reports": 1, "country": "NL"}'
        _run(mocker, "1.2.3.4", rdb, ti, s)
        assert ti.calls["abuseipdb"] == 0
        assert _abuseipdb_rate_key(clock["t"]) not in rdb.kv


class TestPrioridad:
    def test_otx_corrobora_consulta_abuseipdb_y_llega_a_count_2(self, mocker, clock) -> None:
        rdb, ti = FakeRedis(), FakeTI(pulses=24, abuse_score=90)
        r = _run(mocker, "1.2.3.4", rdb, ti)
        assert ti.calls == {"otx": 1, "abuseipdb": 1}
        assert r.corroboration_count == 2  # el gate real sigue alcanzable

    @pytest.mark.parametrize("ti", [FakeTI(pulses=0), FakeTI(otx_error=httpx.ReadTimeout("lento"))],
                             ids=["otx_sin_pulses", "otx_timeout"])
    def test_otx_no_corrobora_no_gasta_cuota(self, mocker, clock, ti) -> None:
        """H56: ABUSEIPDB_NON_DECISIVE_SHARE = 0. Si OTX no corrobora, AbuseIPDB
        llevaría count a 1 como máximo: no cambia R2 y no se consulta."""
        assert ABUSEIPDB_NON_DECISIVE_SHARE == 0
        rdb = FakeRedis()
        r = _run(mocker, "1.2.3.4", rdb, ti)
        assert ti.calls["abuseipdb"] == 0
        assert r.abuseipdb_available is False
        assert any("no decisiva" in n for n in r.notes)
        assert not any(k.startswith("ti:rate:") for k in rdb.kv)  # tampoco toca el bucket

    def test_cupo_no_decisivo_agotado_reserva_el_resto_para_decisivas(self, mocker, clock) -> None:
        """Mecanismo de reserva (H52), con un share > 0 forzado: sigue
        disponible si se vuelve a habilitar el cupo no decisivo."""
        mocker.patch("response.enrichment.ABUSEIPDB_NON_DECISIVE_SHARE", 0.5)
        budget = abuseipdb_window_budget(_settings())
        share = int(budget * 0.5)
        rdb = FakeRedis()
        weak = FakeTI(pulses=0)
        for i in range(share + 2):
            r = _run(mocker, f"5.5.5.{i}", rdb, weak)
        assert weak.calls["abuseipdb"] == share
        assert any("cupo no decisivo de la ventana agotado" in n for n in r.notes)
        strong = FakeTI(pulses=24)
        for i in range(budget):
            _run(mocker, f"6.6.6.{i}", rdb, strong)
        assert strong.calls["abuseipdb"] == budget - share  # la reserva sí se usa


class TestCausasDistinguibles:
    def test_throttling_cuota_y_timeout_dejan_notas_distintas(self, mocker, clock) -> None:
        s = _settings()
        # throttling
        rdb = FakeRedis()
        rdb.kv[_abuseipdb_rate_key(clock["t"])] = "999"
        throttled = _abuseipdb_lookup("1.2.3.4", s, rdb, now=clock["t"]).notes
        # cuota (429 previo -> negative cache global)
        rdb = FakeRedis()
        rdb.kv[f"{s.enrich_cache_prefix}abuseipdb:quota_exhausted"] = "HTTP 429"
        quota = _abuseipdb_lookup("1.2.3.4", s, rdb, now=clock["t"]).notes
        # timeout
        mocker.patch("response.enrichment.httpx.get", side_effect=httpx.ReadTimeout("lento"))
        timeout = _abuseipdb_lookup("1.2.3.4", s, FakeRedis(), now=clock["t"]).notes
        assert any("omitido por throttling" in n for n in throttled)
        assert any("cuota diaria agotada" in n for n in quota)
        assert any("error: ReadTimeout" in n for n in timeout)
        assert not any("throttling" in n for n in quota + timeout)

    def test_redis_caido_en_el_bucket_no_consulta_ni_lanza(self, mocker, clock) -> None:
        ti = FakeTI()
        mocker.patch("response.enrichment.httpx.get", side_effect=ti)
        r = _abuseipdb_lookup("1.2.3.4", _settings(), FakeRedis(fail_bucket=True), now=clock["t"])
        assert ti.calls["abuseipdb"] == 0
        assert any("token bucket no disponible" in n for n in r.notes)


class TestSimulacionVolumen:
    def test_volumen_alto_6h_no_supera_el_reparto(self, mocker, clock) -> None:
        """30 IPs nuevas por minuto durante 6 h (mitad decisivas): las
        llamadas reales nunca pasan del presupuesto por ventana y el promedio
        queda por debajo de cuota/1440 (~0,69/min)."""
        rdb = FakeRedis()
        settings = _settings()
        budget = abuseipdb_window_budget(settings)
        strong, weak = FakeTI(pulses=24), FakeTI(pulses=0)
        per_window: dict[str, int] = {}
        minutes = 6 * 60
        for m in range(minutes):
            for i in range(30):
                clock["t"] = T0 + m * 60 + i
                ti = strong if i % 2 else weak
                before = ti.calls["abuseipdb"]
                _run(mocker, f"10.{m % 250}.{i}.{m // 250}".replace("10.", "8.", 1), rdb, ti, settings)
                if ti.calls["abuseipdb"] > before:
                    k = _abuseipdb_rate_key(clock["t"])
                    per_window[k] = per_window.get(k, 0) + 1
        total = strong.calls["abuseipdb"] + weak.calls["abuseipdb"]
        assert max(per_window.values()) <= budget
        assert total / minutes <= settings.abuseipdb_daily_quota / 1440
        assert total == budget * (minutes * 60 // ABUSEIPDB_RATE_WINDOW_SECONDS)  # usa todo el cupo, sin pasarse
