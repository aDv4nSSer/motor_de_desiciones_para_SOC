"""
H57: casos automáticos de T2 con dedup por IP pública, TTL y listado acotado.

Antes cada T2 de IP pública abría un caso nuevo, sin TTL (~550.000 casos, el
principal consumo de memoria de Redis), y dashboard.list_cases() hacía
SMEMBERS del índice completo más un GET por caso dentro del proceso del Fast
Path. Redis siempre falso.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import dashboard
from response.cases import (
    CASE_DEDUP_PREFIX,
    CASES_INDEX_KEY,
    CASES_KEY_PREFIX,
    CASES_RECENT_KEY,
    network_of,
    open_case,
)


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int | None] = {}
        self.sets: dict[str, set] = {}
        self.zsets: dict[str, dict[str, float]] = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        self.ttl[key] = ex
        return True

    def get(self, key):
        return self.kv.get(key)

    def mget(self, keys):
        return [self.kv.get(k) for k in keys]

    def sadd(self, key, member):
        self.sets.setdefault(key, set()).add(member)

    def smembers(self, key):
        raise AssertionError("SMEMBERS del índice completo: lectura masiva (H54)")

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        for m in [m for m, s in z.items() if s <= float(hi)]:
            del z[m]

    def zrevrange(self, key, start, end):
        ordered = sorted(self.zsets.get(key, {}).items(), key=lambda x: -x[1])
        return [m for m, _ in ordered[start:end + 1]]

    def zrevrangebyscore(self, key, hi, lo, start=0, num=None):
        lo = float(lo)
        ordered = [m for m, s in sorted(self.zsets.get(key, {}).items(), key=lambda x: -x[1]) if s >= lo]
        return ordered[start:start + num] if num is not None else ordered[start:]

    def zremrangebyrank(self, key, start, end):
        ordered = sorted(self.zsets.get(key, {}).items(), key=lambda x: x[1])
        n = len(ordered)
        end = n + end if end < 0 else end
        if end < start:
            return  # rango vacío, como Redis
        for m, _ in ordered[start:end + 1]:
            del self.zsets[key][m]

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def expire_now(self, key):
        self.kv.pop(key, None)


def _case(rdb, ip="45.9.20.7", trace="t-1"):
    return open_case("network_t2_unconfirmed", ip, {"trace_id": trace, "risk_score": 0.6}, rdb,
                     ttl=604800, dedup_window=86400)


class TestDedup:
    def test_la_misma_ip_publica_reutiliza_el_caso_abierto(self) -> None:
        rdb = FakeRedis()
        c1 = _case(rdb, trace="t-1")
        c2 = _case(rdb, trace="t-2")
        c3 = _case(rdb, trace="t-3")
        assert c1["case_id"] == c2["case_id"] == c3["case_id"]
        assert c3["deduplicated"] is True
        stored = json.loads(rdb.kv[f"{CASES_KEY_PREFIX}{c1['case_id']}"])
        assert stored["occurrences"] == 3 and stored["trace_ids"] == ["t-1", "t-2", "t-3"]
        assert len([k for k in rdb.kv if k.startswith(CASES_KEY_PREFIX) and k.count(":") == 2]) == 1

    def test_ips_distintas_abren_casos_distintos_con_su_net24(self) -> None:
        rdb = FakeRedis()
        a, b = _case(rdb, "91.92.42.10"), _case(rdb, "91.92.42.11")
        assert a["case_id"] != b["case_id"]
        assert a["net24"] == b["net24"] == "91.92.42.0/24"

    def test_un_caso_tocado_por_un_analista_no_se_reutiliza(self) -> None:
        rdb = FakeRedis()
        c1 = _case(rdb)
        key = f"{CASES_KEY_PREFIX}{c1['case_id']}"
        tocado = json.loads(rdb.kv[key]); tocado["state"] = "en_investigacion"
        rdb.kv[key] = json.dumps(tocado)
        c2 = _case(rdb, trace="t-2")
        assert c2["case_id"] != c1["case_id"]
        assert rdb.kv[f"{CASE_DEDUP_PREFIX}45.9.20.7"] == c2["case_id"]

    def test_si_el_caso_previo_expiro_se_abre_otro(self) -> None:
        rdb = FakeRedis()
        c1 = _case(rdb)
        rdb.expire_now(f"{CASES_KEY_PREFIX}{c1['case_id']}")
        c2 = _case(rdb, trace="t-2")
        assert c2["case_id"] != c1["case_id"]

    @pytest.mark.parametrize("ip", ["10.30.30.2", "desconocido"])
    def test_ips_no_publicas_no_se_deduplican(self, ip) -> None:
        rdb = FakeRedis()
        assert _case(rdb, ip)["case_id"] != _case(rdb, ip)["case_id"]
        assert not any(k.startswith(CASE_DEDUP_PREFIX) for k in rdb.kv)


class TestTTL:
    def test_caso_nuevo_y_ocurrencias_llevan_ttl(self) -> None:
        rdb = FakeRedis()
        c = _case(rdb)
        key = f"{CASES_KEY_PREFIX}{c['case_id']}"
        assert rdb.ttl[key] == 604800
        _case(rdb, trace="t-2")
        assert rdb.ttl[key] == 604800  # se extiende desde la última ocurrencia
        assert rdb.ttl[f"{CASE_DEDUP_PREFIX}45.9.20.7"] == 86400

    def test_compatibilidad_con_el_indice_historico(self) -> None:
        rdb = FakeRedis()
        c = _case(rdb)
        assert c["case_id"] in rdb.sets[CASES_INDEX_KEY]
        assert c["case_id"] in rdb.zsets[CASES_RECENT_KEY]


class TestListadoAcotado:
    def test_list_cases_no_hace_smembers_y_respeta_el_limite(self, mocker) -> None:
        rdb = FakeRedis()
        for i in range(30):
            _case(rdb, f"45.9.{i}.7", trace=f"t-{i}")
        mocker.patch.object(dashboard, "_get_redis", return_value=rdb)
        got = dashboard.list_cases(limit=10)
        assert len(got) == 10
        assert got[0]["host"] == "45.9.29.7"  # el más reciente primero

    def test_update_case_state_deja_el_caso_persistente(self, mocker) -> None:
        rdb = FakeRedis()
        c = _case(rdb)
        mocker.patch.object(dashboard, "_get_redis", return_value=rdb)
        dashboard.update_case_state(c["case_id"], "en_investigacion", "lo miro", "analista")
        assert rdb.ttl[f"{CASES_KEY_PREFIX}{c['case_id']}"] is None


def test_network_of() -> None:
    assert network_of("200.54.12.139") == "200.54.12.0/24"
    assert network_of("2001:db8::1") == "2001:db8::/64"
    assert network_of("desconocido") is None
