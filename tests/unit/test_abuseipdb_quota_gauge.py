"""
H55: el token bucket de H52 solo cuenta lo que gastó este proceso. La cuota
real vive en AbuseIPDB, así que cada respuesta (200 o 429) actualiza un gauge
con X-RateLimit-Limit/-Remaining/-Reset y el ritmo de las consultas se ajusta a
lo que de verdad queda hasta el reset de las 00:00 UTC.

Casos que el bucket solo no cubre: arranque a media jornada (el deploy de H52
cayó 56 min después del reset, con cientos de consultas ya gastadas), desalojo o
FLUSHDB de `ti:*` (H54), otro consumidor de la misma cuenta, y un plan real
distinto del configurado.

Redis y las APIs siempre falsos; nunca se llama a AbuseIPDB ni OTX reales.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import response.enrichment as enr
from constants import ABUSEIPDB_QUOTA_GAUGE_KEY
from response.config import ResponseSettings
from response.enrichment import ABUSEIPDB_URL, abuseipdb_window_budget, enrich

T0 = 1_791_417_600.0  # 2026-10-08 00:00:00Z: reset de la cuota y borde de ventana
DAY_END = T0 + 86400


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


class FakeAbuseAPI:
    """httpx.get falso con cuota real: cada llamada a AbuseIPDB la descuenta y
    devuelve los headers X-RateLimit-* (o un 429 con remaining 0). OTX siempre
    corrobora, así que todas las consultas son decisivas."""

    def __init__(self, remaining: int, limit: int = 1000, send_headers: bool = True):
        self.remaining, self.limit, self.send_headers = remaining, limit, send_headers
        self.calls = 0
        self.rejected = 0

    def _headers(self) -> dict[str, str]:
        if not self.send_headers:
            return {}
        return {"X-RateLimit-Limit": str(self.limit), "X-RateLimit-Remaining": str(self.remaining),
                "X-RateLimit-Reset": str(int(DAY_END))}

    def __call__(self, url, **kw):
        req = httpx.Request("GET", url)
        if url != ABUSEIPDB_URL:
            return httpx.Response(200, json={"pulse_info": {"count": 24}}, request=req)
        self.calls += 1
        if self.remaining <= 0:
            self.rejected += 1
            return httpx.Response(429, headers=self._headers(), request=req)
        self.remaining -= 1
        return httpx.Response(
            200, headers=self._headers(), request=req,
            json={"data": {"abuseConfidenceScore": 90, "totalReports": 9, "countryCode": "NL"}},
        )


def _settings(**kw) -> ResponseSettings:
    base = {"abuseipdb_api_key": "k", "otx_api_key": "k", "crowdsec_lapi_url": ""}
    base.update(kw)
    return ResponseSettings(**base)


def _seed(rdb: FakeRedis, remaining: int, limit: int = 1000, reset: float = DAY_END) -> None:
    gauge = {"remaining": remaining, "limit": limit, "reset": reset}
    enr._quota_seen = dict(gauge)
    rdb.kv[ABUSEIPDB_QUOTA_GAUGE_KEY] = json.dumps(gauge)


@pytest.fixture(autouse=True)
def _estado_limpio():
    enr._quota_seen, enr._quota_limit_warned, enr._calls_since_seen = None, False, 0
    yield
    enr._quota_seen, enr._quota_limit_warned, enr._calls_since_seen = None, False, 0


@pytest.fixture
def clock(mocker):
    now = {"t": T0 + 1}
    mocker.patch("response.enrichment.time.time", side_effect=lambda: now["t"])
    mocker.patch("response.enrichment._reverse_dns", return_value=None)
    return now


def _run(mocker, ip, rdb, api, settings=None):
    mocker.patch("response.enrichment.httpx.get", side_effect=api)
    return enrich(ip, settings or _settings(), rdb)


class TestGauge:
    def test_cada_respuesta_actualiza_el_gauge(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=800)
        _run(mocker, "1.2.3.4", rdb, api)
        saved = json.loads(rdb.kv[ABUSEIPDB_QUOTA_GAUGE_KEY])
        assert saved == {"remaining": 799, "limit": 1000, "reset": DAY_END}
        assert enr._quota_seen == saved

    def test_un_429_deja_el_gauge_en_cero(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=0)
        _run(mocker, "1.2.3.4", rdb, api)
        assert enr._quota_seen is not None and enr._quota_seen["remaining"] == 0

    def test_caida_del_remaining_mayor_a_la_propia_avisa_consumo_externo(self, mocker, clock, caplog) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=700)
        _seed(rdb, remaining=900)  # el motor vio 900; otro cliente gastó ~200 sin pasar por el bucket
        with caplog.at_level("WARNING", logger="response.r1"):
            _run(mocker, "1.2.3.4", rdb, api)
        assert any("consumo externo" in rec.message for rec in caplog.records)

    def test_el_gasto_propio_normal_no_avisa(self, mocker, clock, caplog) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=900)
        _seed(rdb, remaining=900)
        with caplog.at_level("WARNING", logger="response.r1"):
            for i in range(3):
                _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert not any("consumo externo" in rec.message for rec in caplog.records)

    def test_timeouts_propios_no_se_leen_como_consumo_externo(self, mocker, clock, caplog) -> None:
        """Un timeout de lectura gasta cuota pero no trae headers (H55: el 8-oct
        hubo 20 seguidos tras el reset). La siguiente respuesta muestra una
        caída igual a las consultas propias emitidas: no es consumo externo."""
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=900)
        _seed(rdb, remaining=900)

        def flaky(url, **kw):
            if url == ABUSEIPDB_URL and api.calls < 8:
                api.calls += 1
                api.remaining -= 1  # AbuseIPDB lo procesó y lo cobró
                raise httpx.ReadTimeout("The read operation timed out")
            return api(url, **kw)

        mocker.patch("response.enrichment.httpx.get", side_effect=flaky)
        mocker.patch("response.enrichment._abuseipdb_rate_key", side_effect=lambda now: f"w:{api.calls}")
        with caplog.at_level("WARNING", logger="response.r1"):
            for i in range(9):
                enrich(f"1.2.3.{i + 1}", _settings(), rdb)
        assert enr._quota_seen["remaining"] == 891
        assert not any("consumo externo" in rec.message for rec in caplog.records)

    def test_sin_headers_no_hay_gauge_y_rige_el_bucket_local(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=1000, send_headers=False)
        for i in range(10):
            _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert enr._quota_seen is None and ABUSEIPDB_QUOTA_GAUGE_KEY not in rdb.kv
        assert api.calls == abuseipdb_window_budget(_settings())  # comportamiento de H52 intacto

    def test_gauge_vencido_se_ignora(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=1000)
        _seed(rdb, remaining=0, reset=T0 - 1)  # ya pasó su reset: la cuota se repuso
        for i in range(10):
            _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert api.calls == abuseipdb_window_budget(_settings())


class TestRitmoSegunCuotaReal:
    def test_remaining_cero_no_consulta_y_lo_dice(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=1000)
        _seed(rdb, remaining=0)
        r = _run(mocker, "1.2.3.4", rdb, api)
        assert api.calls == 0
        assert any("omitido por throttling" in n and "cuota real agotada" in n for n in r.notes)

    def test_poca_cuota_real_baja_el_ritmo_por_debajo_del_presupuesto(self, mocker, clock) -> None:
        clock["t"] = T0 + 43_201  # 72 ventanas hasta el reset
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=100)
        _seed(rdb, remaining=100)
        for i in range(6):
            r = _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert api.calls == 2  # ceil(100 / 72), no las 6 del presupuesto local
        assert any("ritmo según cuota real" in n for n in r.notes)

    def test_flush_de_redis_no_reabre_el_presupuesto_completo(self, mocker, clock) -> None:
        """El desalojo de ti:* borra el contador de la ventana y el gauge de
        Redis. La copia del proceso conserva la cuota real: tras el flush se
        puede gastar a lo sumo el ritmo (2), no un presupuesto entero (6)."""
        clock["t"] = T0 + 43_201
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=100)
        _seed(rdb, remaining=100)
        for i in range(6):
            _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert api.calls == 2
        rdb.kv.clear()  # FLUSHDB / desalojo
        for i in range(6):
            _run(mocker, f"5.6.7.{i + 1}", rdb, api)
        assert api.calls == 4  # sin el gauge del proceso habrían sido 2 + 6 = 8

    def test_plan_real_menor_al_configurado_reduce_el_presupuesto(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=500, limit=500)
        _seed(rdb, remaining=500, limit=500)
        for i in range(10):
            _run(mocker, f"1.2.3.{i + 1}", rdb, api)
        assert api.calls == abuseipdb_window_budget(_settings(), 500) == 3  # y no las 6 de la cuota configurada


class TestArranqueAMediaJornada:
    """Lo que pasó el 8-oct: el bucket se desplegó 56 min después del reset,
    con cientos de consultas ya gastadas sin control. El bucket reparte 864/día
    como si el día empezara de cero y la cuota real se agota a media jornada."""

    START = T0 + 3_601
    REMAINING_AT_START = 400
    PER_MINUTE = 2  # demanda > ritmo en todas las ventanas (6 y ~3 por 10 min)

    def _simulate(self, mocker, clock, api: FakeAbuseAPI, rdb: FakeRedis) -> None:
        mocker.patch("response.enrichment.httpx.get", side_effect=api)  # una sola vez: 2.700 iteraciones
        settings = _settings()
        minutes = int((DAY_END - self.START) // 60)
        for m in range(minutes):
            for i in range(self.PER_MINUTE):
                clock["t"] = self.START + m * 60 + i
                enrich(f"8.{(m // 250) % 250}.{m % 250}.{i + 1}", settings, rdb)

    def test_sin_gauge_el_bucket_solo_se_agota_antes_del_reset(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=self.REMAINING_AT_START, send_headers=False)
        self._simulate(mocker, clock, api, rdb)
        assert api.rejected >= 1  # 6 por ventana x ~138 ventanas > 400: llega el 429 y se corta la fuente

    def test_con_gauge_reparte_lo_que_queda_sin_llegar_al_429(self, mocker, clock) -> None:
        rdb, api = FakeRedis(), FakeAbuseAPI(remaining=self.REMAINING_AT_START)
        _seed(rdb, remaining=self.REMAINING_AT_START)
        self._simulate(mocker, clock, api, rdb)
        assert api.rejected == 0
        assert api.calls <= self.REMAINING_AT_START
        assert api.calls >= 0.9 * self.REMAINING_AT_START  # y no deja la cuota sin usar
