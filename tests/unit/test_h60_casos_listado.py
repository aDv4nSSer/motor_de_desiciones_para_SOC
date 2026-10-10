"""
H60: gestión interna de casos. Listado paginado con filtros sobre índices
acotados, transiciones de estado, ZSET de casos trabajados con tope duro y
filas de la exportación de cierres. Redis siempre falso.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dashboard
from response.cases import CASES_KEY_PREFIX, CASES_RECENT_KEY
from test_cases_dedup_ttl import FakeRedis, _case


@pytest.fixture
def rdb(mocker):
    store = FakeRedis()
    mocker.patch.object(dashboard, "_get_redis", return_value=store)
    return store


def _stored(rdb, case_id):
    return json.loads(rdb.kv[f"{CASES_KEY_PREFIX}{case_id}"])


class TestListado:
    def test_por_defecto_solo_ips_publicas(self, rdb) -> None:
        _case(rdb, "45.9.20.7"); _case(rdb, "10.10.10.3"); _case(rdb, "desconocido")
        page = dashboard.list_cases_page()
        assert [c["host"] for c in page["items"]] == ["45.9.20.7"]
        todas = dashboard.list_cases_page(public_only=False)
        assert len(todas["items"]) == 3

    def test_paginacion_por_cursor_sin_repetir(self, rdb) -> None:
        for i in range(7):
            _case(rdb, f"45.9.{i}.7", trace=f"t-{i}")
        p1 = dashboard.list_cases_page(limit=3)
        p2 = dashboard.list_cases_page(limit=3, cursor=p1["next_cursor"])
        p3 = dashboard.list_cases_page(limit=3, cursor=p2["next_cursor"])
        hosts = [c["host"] for p in (p1, p2, p3) for c in p["items"]]
        assert len(hosts) == 7 == len(set(hosts))
        assert p3["next_cursor"] is None

    def test_el_tope_de_lectura_se_informa(self, rdb, monkeypatch) -> None:
        monkeypatch.setattr(dashboard, "CASES_LIST_SCAN_MAX", 4)
        monkeypatch.setattr(dashboard, "CASES_LIST_BATCH", 2)
        for i in range(6):
            _case(rdb, f"10.0.0.{i}")  # privadas: el filtro las descarta todas
        page = dashboard.list_cases_page()
        assert page["items"] == [] and page["scanned"] == 4
        assert page["scan_cap_reached"] is True and page["next_cursor"] == 4

    def test_ventana_por_horas(self, rdb) -> None:
        a, b = _case(rdb, "45.9.1.7"), _case(rdb, "45.9.2.7")
        rdb.zsets[CASES_RECENT_KEY][a["case_id"]] = 1000.0
        rdb.zsets[CASES_RECENT_KEY][b["case_id"]] = 1000.0 + 5 * 3600
        page = dashboard.list_cases_page(since_hours=2, now=1000.0 + 6 * 3600)
        assert [c["case_id"] for c in page["items"]] == [b["case_id"]]

    def test_los_trabajados_se_leen_de_su_indice_aunque_se_hundan(self, rdb) -> None:
        viejo = _case(rdb, "45.9.1.7")
        dashboard.update_case_state(viejo["case_id"], "en_investigacion", "", "n1")
        rdb.zsets[CASES_RECENT_KEY][viejo["case_id"]] = 0.0  # hundido bajo miles de casos
        page = dashboard.list_cases_page(state="en_investigacion")
        assert page["source"] == "worked"
        assert [c["case_id"] for c in page["items"]] == [viejo["case_id"]]

    def test_redis_caido_no_rompe(self, mocker) -> None:
        mocker.patch.object(dashboard, "_get_redis", side_effect=ConnectionError("down"))
        assert dashboard.list_cases_page()["available"] is False


class TestTransiciones:
    def test_abierto_a_investigacion_y_cierre(self, rdb) -> None:
        c = _case(rdb)
        dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        dashboard.update_case_state(c["case_id"], "cerrado_confirmado", "AbuseIPDB 100", "n2")
        s = _stored(rdb, c["case_id"])
        assert s["state"] == "cerrado_confirmado"
        assert [h.get("actor") for h in s["history"]] == [None, "n1", "n2"]

    @pytest.mark.parametrize("final", ["cerrado_confirmado", "cerrado_falso_positivo"])
    def test_un_cerrado_es_final(self, rdb, final) -> None:
        c = _case(rdb)
        dashboard.update_case_state(c["case_id"], final, "nota", "n2")
        with pytest.raises(dashboard.CaseTransitionError):
            dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")

    def test_no_se_vuelve_a_abierto(self, rdb) -> None:
        c = _case(rdb)
        dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        with pytest.raises(dashboard.CaseTransitionError):
            dashboard.update_case_state(c["case_id"], "abierto", "", "n1")

    def test_el_ttl_no_cambia_respecto_de_h57(self, rdb) -> None:
        c = _case(rdb)
        dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        assert rdb.ttl[f"{CASES_KEY_PREFIX}{c['case_id']}"] is None  # igual que antes de H60
        assert dashboard.CASES_WORKED_KEY not in rdb.ttl  # el ZSET no es un SET con TTL


class TestTopeDuro:
    def test_el_zset_de_trabajados_no_pasa_del_tope(self, rdb, monkeypatch) -> None:
        monkeypatch.setattr(dashboard, "CASES_WORKED_MAX", 3)
        ids = []
        for i in range(5):
            c = _case(rdb, f"45.9.{i}.7")
            ids.append(c["case_id"])
            dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        worked = rdb.zsets[dashboard.CASES_WORKED_KEY]
        assert len(worked) == 3
        assert set(worked) == set(ids[-3:])  # se recortan los más antiguos


class TestCierresParaCsv:
    def test_solo_cierres_con_hora_y_actor_del_cierre(self, rdb) -> None:
        a, b, c = _case(rdb, "45.9.1.7", "ta"), _case(rdb, "45.9.2.7", "tb"), _case(rdb, "45.9.3.7", "tc")
        dashboard.update_case_state(a["case_id"], "en_investigacion", "", "n1")
        dashboard.update_case_state(a["case_id"], "cerrado_falso_positivo", "Bingbot", "n2")
        dashboard.update_case_state(b["case_id"], "cerrado_confirmado", "escaneo", "ciso")
        dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        rows = {r["ip"]: r for r in dashboard.closed_cases_rows()}
        assert set(rows) == {"45.9.1.7", "45.9.2.7"}
        assert rows["45.9.1.7"]["actor"] == "n2" and rows["45.9.1.7"]["estado"] == "cerrado_falso_positivo"
        assert rows["45.9.2.7"]["trace_id"] == "tb" and rows["45.9.2.7"]["net24"] == "45.9.2.0/24"
        assert rows["45.9.1.7"]["hora"] == _stored(rdb, a["case_id"])["history"][-1]["at"]


class TestConcurrencia:
    """WATCH/MULTI: lectura, validación y escritura contra el estado real (revisión de 55f4b7b, punto 1)."""

    def test_un_cierre_concurrente_no_se_pisa_con_investigacion(self, rdb) -> None:
        c = _case(rdb)
        key = f"{CASES_KEY_PREFIX}{c['case_id']}"

        def cierre_de_otro_analista() -> None:
            dashboard_case = json.loads(rdb.kv[key])
            dashboard_case["state"] = "cerrado_confirmado"
            dashboard_case["history"].append({"state": "cerrado_confirmado", "at": "x", "note": "ya", "actor": "n2"})
            rdb.set(key, json.dumps(dashboard_case))

        rdb.before_exec = cierre_de_otro_analista
        with pytest.raises(dashboard.CaseTransitionError):   # se revalida contra lo que hay al escribir
            dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        assert _stored(rdb, c["case_id"])["state"] == "cerrado_confirmado"
        assert [h["state"] for h in _stored(rdb, c["case_id"])["history"]][-1] == "cerrado_confirmado"

    def test_una_ocurrencia_del_worker_entre_lectura_y_escritura_no_se_pierde(self, rdb) -> None:
        c = _case(rdb)
        key = f"{CASES_KEY_PREFIX}{c['case_id']}"

        def worker_suma_ocurrencia() -> None:
            d = json.loads(rdb.kv[key]); d["occurrences"] = 99
            rdb.set(key, json.dumps(d), ex=604800)

        rdb.before_exec = worker_suma_ocurrencia
        got = dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        assert got["occurrences"] == 99 and got["state"] == "en_investigacion"   # releyó y reaplicó
        assert _stored(rdb, c["case_id"])["occurrences"] == 99
        assert rdb.ttl[key] is None                                              # sigue sin TTL

    def test_agotados_los_reintentos_es_conflicto(self, rdb, monkeypatch) -> None:
        c = _case(rdb)
        key = f"{CASES_KEY_PREFIX}{c['case_id']}"
        real_set = rdb.set
        pipe_cls = type(rdb.pipeline())
        original = pipe_cls.execute

        def siempre_conflicto(self):
            real_set(key, rdb.kv[key])   # alguien escribe antes de cada EXEC
            return original(self)

        monkeypatch.setattr(pipe_cls, "execute", siempre_conflicto)
        with pytest.raises(dashboard.CaseConflictError):
            dashboard.update_case_state(c["case_id"], "en_investigacion", "", "n1")
        assert _stored(rdb, c["case_id"])["state"] == "abierto"
        assert dashboard.CASES_WORKED_KEY not in rdb.zsets

    def test_set_zadd_y_recorte_van_juntos(self, rdb) -> None:
        c = _case(rdb)
        dashboard.update_case_state(c["case_id"], "cerrado_confirmado", "nota", "n2")
        assert _stored(rdb, c["case_id"])["state"] == "cerrado_confirmado"
        assert c["case_id"] in rdb.zsets[dashboard.CASES_WORKED_KEY]


class TestCsvSafe:
    @pytest.mark.parametrize("raw,esperado", [
        ("=1+1", "'=1+1"), ("+cmd", "'+cmd"), ("-2", "'-2"), ("@SUM(A1)", "'@SUM(A1)"),
        ("\t=1", "'\t=1"), ("\r=1", "'\r=1"), ("\n=1", "'\n=1"), ("＝1+1", "'＝1+1"),
        (' =1+1', "' =1+1"), ('"=1+1', "'\"=1+1"), ("'=1+1", "''=1+1"),
    ])
    def test_prefijos_de_formula(self, raw, esperado) -> None:
        assert dashboard.csv_safe(raw) == esperado

    @pytest.mark.parametrize("raw", [
        "", "2001:db8::1", "::ffff:10.0.0.1", "45.9.20.7", "2026-10-10T15:00:00+00:00",
        "13dd7cd0-2c35-4e59-a717-450729535a48", "analista.n2", "45.9.20.0/24", "   ",
    ])
    def test_valores_legitimos_no_cambian(self, raw) -> None:
        assert dashboard.csv_safe(raw) == raw

    def test_none_y_no_str(self) -> None:
        assert dashboard.csv_safe(None) == "" and dashboard.csv_safe(42) == "42"
