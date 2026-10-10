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
