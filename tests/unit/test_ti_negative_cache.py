"""
H38 (C): negative caching de TI y corte temprano de CrowdSec.

- Un fallo de AbuseIPDB/OTX (timeout, error de red, HTTP != 429, JSON
  inválido) se cachea por IP ti_negative_cache_ttl: la tarea siguiente de
  la misma IP no vuelve a pagar el timeout de 4 s.
- El 429 de AbuseIPDB es cuota de cuenta: corta la fuente para TODAS las IPs
  hasta el reset (Retry-After / X-RateLimit-Reset / medianoche UTC).
- Un resultado de negative cache es "no disponible", nunca "limpio": no
  cuenta a favor ni en contra de la corroboración.
- CrowdSec no deserializa su caché (~2.8 MiB) para IPs no públicas.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.enrichment import (  # noqa: E402
    _abuseipdb_lookup,
    _crowdsec_lookup,
    _otx_lookup,
    count_corroborating_sources,
    enrich,
    quota_reset_seconds,
)

IP = "1.2.3.4"


class TTLRedis:
    """get/setex con registro del TTL de cada clave."""

    def __init__(self):
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.gets: list[str] = []

    def get(self, key):
        self.gets.append(key)
        return self.kv.get(key)

    def setex(self, key, ttl, value):
        self.kv[key] = value
        self.ttl[key] = ttl

    # Token bucket de AbuseIPDB (H52): contador por ventana.
    def incr(self, key):
        self.kv[key] = str(int(self.kv.get(key) or 0) + 1)
        return int(self.kv[key])

    def expire(self, key, ttl):
        self.ttl[key] = ttl
        return True


def _settings(**over) -> ResponseSettings:
    base = {"abuseipdb_api_key": "k", "otx_api_key": "k", "ti_negative_cache_ttl": 600,
            "crowdsec_lapi_url": "http://10.10.10.1:8081", "crowdsec_api_key": "k"}
    base.update(over)
    return ResponseSettings(**base)


def _resp(status: int, body: dict | None = None, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, json=body or {}, headers=headers or {},
                          request=httpx.Request("GET", "https://example.test"))


class TestNegativeCachePorIP:
    @pytest.mark.parametrize("lookup,provider", [(_abuseipdb_lookup, "abuseipdb"), (_otx_lookup, "otx")])
    def test_timeout_se_cachea_y_la_segunda_tarea_no_llama(self, mocker, lookup, provider) -> None:
        get = mocker.patch("response.enrichment.httpx.get", side_effect=httpx.ReadTimeout("lento"))
        rdb = TTLRedis()
        first = lookup(IP, _settings(), rdb)
        second = lookup(IP, _settings(), rdb)
        assert get.call_count == 1
        assert f"soc:enrich:neg:{provider}:{IP}" in rdb.kv
        assert rdb.ttl[f"soc:enrich:neg:{provider}:{IP}"] == 600
        for r in (first, second):
            assert getattr(r, f"{provider}_available") is False
        assert any("negative cache: ReadTimeout" in n for n in second.notes)
        assert second.cached is False  # no es un acierto de caché positivo

    @pytest.mark.parametrize("lookup,provider", [(_abuseipdb_lookup, "abuseipdb"), (_otx_lookup, "otx")])
    def test_http_5xx_tambien_se_cachea(self, mocker, lookup, provider) -> None:
        mocker.patch("response.enrichment.httpx.get", return_value=_resp(503))
        rdb = TTLRedis()
        lookup(IP, _settings(), rdb)
        assert rdb.kv[f"soc:enrich:neg:{provider}:{IP}"] == "HTTP 503"

    def test_otra_ip_no_hereda_el_fallo(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get", side_effect=httpx.ConnectError("x"))
        rdb = TTLRedis()
        _otx_lookup(IP, _settings(), rdb)
        _otx_lookup("5.6.7.8", _settings(), rdb)
        assert get.call_count == 2

    def test_exito_no_deja_negative_cache_y_sigue_cacheando_6h(self, mocker) -> None:
        mocker.patch("response.enrichment.httpx.get",
                     return_value=_resp(200, {"data": {"abuseConfidenceScore": 88, "totalReports": 4}}))
        rdb = TTLRedis()
        r = _abuseipdb_lookup(IP, _settings(), rdb)
        assert r.abuseipdb_score == 88
        assert not any(k.startswith("soc:enrich:neg:") for k in rdb.kv)
        assert rdb.ttl[f"soc:enrich:{IP}"] == 21600

    def test_cache_positivo_gana_al_negativo(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get")
        rdb = TTLRedis()
        rdb.kv[f"soc:enrich:{IP}"] = json.dumps({"score": 70, "reports": 2, "country": "CL"})
        rdb.kv[f"soc:enrich:neg:abuseipdb:{IP}"] = "ReadTimeout"
        assert _abuseipdb_lookup(IP, _settings(), rdb).abuseipdb_score == 70
        get.assert_not_called()


class TestCuotaAbuseIPDB:
    def test_429_corta_la_fuente_para_cualquier_ip(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get",
                           return_value=_resp(429, headers={"Retry-After": "29241"}))
        rdb = TTLRedis()
        _abuseipdb_lookup(IP, _settings(), rdb)
        other = _abuseipdb_lookup("5.6.7.8", _settings(), rdb)  # IP distinta
        assert get.call_count == 1
        assert rdb.ttl["soc:enrich:abuseipdb:quota_exhausted"] == 29241
        assert other.abuseipdb_available is False
        assert any("cuota diaria agotada" in n for n in other.notes)
        assert not any(k.startswith("soc:enrich:neg:abuseipdb") for k in rdb.kv)  # no es por IP

    def test_429_no_afecta_a_otx(self, mocker) -> None:
        rdb = TTLRedis()
        rdb.kv["soc:enrich:abuseipdb:quota_exhausted"] = "HTTP 429"
        get = mocker.patch("response.enrichment.httpx.get",
                           return_value=_resp(200, {"pulse_info": {"count": 2}}))
        assert _otx_lookup(IP, _settings(), rdb).otx_pulse_count == 2
        get.assert_called_once()

    def test_reset_por_retry_after(self) -> None:
        assert quota_reset_seconds(_resp(429, headers={"Retry-After": "3600"})) == 3600

    def test_reset_por_x_ratelimit_reset(self) -> None:
        now = 1_790_000_000.0
        assert quota_reset_seconds(_resp(429, headers={"X-RateLimit-Reset": str(int(now + 5000))}), now=now) == 5000

    def test_reset_sin_headers_es_medianoche_utc(self) -> None:
        now = datetime(2026, 10, 2, 21, 0, tzinfo=timezone.utc).timestamp()
        assert quota_reset_seconds(_resp(429), now=now) == 3 * 3600

    @pytest.mark.parametrize("retry,expected", [("5", 60), ("999999", 86400)])
    def test_reset_acotado(self, retry, expected) -> None:
        assert quota_reset_seconds(_resp(429, headers={"Retry-After": retry})) == expected


class TestCorroboracion:
    def test_negative_cache_no_cuenta_a_favor_ni_en_contra(self, mocker) -> None:
        """Igual que una fuente caída: available=False, fuera del conteo."""
        mocker.patch("response.enrichment.httpx.get", side_effect=httpx.ReadTimeout("x"))
        mocker.patch("response.enrichment._reverse_dns", return_value=None)
        from response.schemas import EnrichmentResult
        mocker.patch("response.enrichment._crowdsec_lookup",
                     side_effect=lambda ip, *_: EnrichmentResult(src_ip=ip))
        rdb = TTLRedis()
        enrich(IP, _settings(), rdb)
        cached = enrich(IP, _settings(), rdb)
        assert cached.abuseipdb_available is False and cached.otx_available is False
        assert count_corroborating_sources(cached, _settings()) == (0, [])


class TestCrowdSecIPNoPublica:
    @pytest.mark.parametrize("ip", ["10.10.10.3", "10.30.30.1", "127.0.0.1", "203.0.113.5"])
    def test_no_lee_la_cache_ni_llama_a_la_lapi(self, mocker, ip) -> None:
        fetch = mocker.patch("response.enrichment.fetch_decisions_stream")
        rdb = TTLRedis()
        r = _crowdsec_lookup(ip, _settings(), rdb)
        assert rdb.gets == []
        fetch.assert_not_called()
        assert r.crowdsec_observado is False

    def test_ip_publica_sigue_buscando(self, mocker) -> None:
        rdb = TTLRedis()
        rdb.kv["soc:enrich:crowdsec:decisions"] = json.dumps([{"ip": IP, "scenario": "ssh-bf", "duration": "4h"}])
        r = _crowdsec_lookup(IP, _settings(), rdb)
        assert r.crowdsec_observado is True
        assert r.crowdsec_scenario == "ssh-bf"


def test_costo_por_tarea_de_ip_privada_es_bajo(mocker) -> None:
    """Regresión del piso de 0.083 s/tarea de H38: con una caché de CrowdSec
    grande, una IP privada no debe pagar su deserialización."""
    rdb = TTLRedis()
    rdb.kv["soc:enrich:crowdsec:decisions"] = json.dumps(
        [{"ip": f"1.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", "scenario": "x", "duration": "1h"} for i in range(24000)])
    settings = _settings()  # fuera del loop: construir Settings lee el .env (~9 ms)
    t0 = time.perf_counter()
    for _ in range(50):
        _crowdsec_lookup("10.10.10.3", settings, rdb)
    assert (time.perf_counter() - t0) / 50 < 0.002


class TestSoloCacheParaEventosStale:
    """Opción 1 acordada: una tarea stale enriquece solo con lo cacheado."""

    def test_sin_cache_no_llama_a_ninguna_api_ni_dns_ni_lapi(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get")
        dns = mocker.patch("response.enrichment._reverse_dns")
        fetch = mocker.patch("response.enrichment.fetch_decisions_stream")
        r = enrich(IP, _settings(), TTLRedis(), cache_only=True)
        get.assert_not_called()
        dns.assert_not_called()
        fetch.assert_not_called()
        assert r.abuseipdb_available is False and r.otx_available is False
        assert "abuseipdb no disponible (evento stale, solo caché)" in r.notes
        assert "otx no disponible (evento stale, solo caché)" in r.notes
        assert "crowdsec no disponible (evento stale, solo caché)" in r.notes
        assert r.corroboration_count == 0

    def test_usa_la_cache_positiva_si_existe(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get")
        rdb = TTLRedis()
        rdb.kv[f"soc:enrich:{IP}"] = json.dumps({"score": 91, "reports": 12, "country": "NL"})
        rdb.kv[f"soc:enrich:otx:{IP}"] = json.dumps({"pulse_count": 3})
        rdb.kv["soc:enrich:crowdsec:decisions"] = json.dumps([{"ip": IP, "scenario": "ssh-bf", "duration": "1h"}])
        r = enrich(IP, _settings(), rdb, cache_only=True)
        get.assert_not_called()
        assert r.abuseipdb_score == 91 and r.otx_pulse_count == 3
        assert r.crowdsec_observado is True
        assert r.corroboration_count == 2  # la corroboración con datos cacheados sigue siendo real

    def test_respeta_negative_cache_y_cuota(self, mocker) -> None:
        mocker.patch("response.enrichment.httpx.get")
        rdb = TTLRedis()
        rdb.kv["soc:enrich:abuseipdb:quota_exhausted"] = "HTTP 429"
        rdb.kv[f"soc:enrich:neg:otx:{IP}"] = "ReadTimeout"
        r = enrich(IP, _settings(), rdb, cache_only=True)
        assert any("cuota diaria agotada" in n for n in r.notes)
        assert any("negative cache: ReadTimeout" in n for n in r.notes)

    def test_modo_normal_sigue_llamando(self, mocker) -> None:
        get = mocker.patch("response.enrichment.httpx.get", return_value=_resp(200, {"pulse_info": {"count": 0}}))
        _otx_lookup(IP, _settings(), TTLRedis())
        get.assert_called_once()
