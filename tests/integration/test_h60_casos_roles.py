"""
H60: permisos reales de la gestión interna de casos. El backend rechaza a N1
cuando intenta cerrar (403), exige nota al cerrar (422), rechaza transiciones
inválidas (409) y restringe la exportación de cierres a N2 y CISO. Tokens y
sesiones reales sobre una tabla de usuarios en memoria; Redis falso.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "unit"))
from test_cases_dedup_ttl import FakeRedis as CasesRedis
from test_cases_dedup_ttl import _case
from test_users_roles import FakeRedis

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")
PASSWORD = "una-passphrase-larga-123"  # pragma: allowlist secret (credencial ficticia de test)


@pytest.fixture
def env(monkeypatch, mocker):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")
    monkeypatch.setenv("FASTAPI_SECRET_KEY", "clave-de-test-no-usar-en-produccion")
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)

    import auth
    import dashboard
    import users
    from fastapi.testclient import TestClient

    import main

    auth.get_auth_settings.cache_clear()
    monkeypatch.setattr(users, "_client", FakeRedis())
    access_log = mocker.MagicMock()
    for mod in (auth, main):
        monkeypatch.setattr(mod, "log_access_event", access_log)
    cases = CasesRedis()
    monkeypatch.setattr(dashboard, "_get_redis", lambda: cases)
    tokens = {role: auth.create_access_token(users.create_user(f"u{role.lower()}", PASSWORD, role))
              for role in ("N1", "N2", "CISO")}
    yield {"client": TestClient(main.app), "tokens": tokens, "cases": cases, "log": access_log}
    auth.get_auth_settings.cache_clear()


def _call(env, role, method, path, body=None):
    return env["client"].request(method, path, json=body,
                                 headers={"Authorization": f"Bearer {env['tokens'][role]}"})


def _state(env, role, case_id, state, note=""):
    return _call(env, role, "POST", f"/api/v1/dashboard/cases/{case_id}/state", {"state": state, "note": note})


@pytest.mark.parametrize("final", ["cerrado_confirmado", "cerrado_falso_positivo"])
def test_n1_no_puede_cerrar_403_y_queda_registrado(env, final) -> None:
    c = _case(env["cases"])
    r = _state(env, "N1", c["case_id"], final, "intento de cierre")
    assert r.status_code == 403
    assert "N2" in r.json()["detail"]
    env["log"].assert_called_with("un1", "action_denied_role",
                                  {"required": "N2", "actual": "N1", "action": f"case_{final}"})
    assert '"state": "abierto"' in env["cases"].kv[f"soc:cases:{c['case_id']}"]


def test_n1_pasa_a_investigacion(env) -> None:
    c = _case(env["cases"])
    r = _state(env, "N1", c["case_id"], "en_investigacion")
    assert r.status_code == 200 and r.json()["state"] == "en_investigacion"
    assert r.json()["history"][-1]["actor"] == "un1"


@pytest.mark.parametrize("role", ["N2", "CISO"])
def test_n2_y_ciso_cierran_con_nota(env, role) -> None:
    c = _case(env["cases"])
    r = _state(env, role, c["case_id"], "cerrado_confirmado", "  AbuseIPDB 100 y OTX 26  ")
    assert r.status_code == 200
    assert r.json()["history"][-1]["note"] == "AbuseIPDB 100 y OTX 26"


@pytest.mark.parametrize("note", ["", "  ", "ok"])
def test_cerrar_sin_nota_es_422(env, note) -> None:
    c = _case(env["cases"])
    assert _state(env, "N2", c["case_id"], "cerrado_falso_positivo", note).status_code == 422


def test_transicion_invalida_es_409(env) -> None:
    c = _case(env["cases"])
    assert _state(env, "N2", c["case_id"], "cerrado_confirmado", "confirmado").status_code == 200
    assert _state(env, "N2", c["case_id"], "en_investigacion").status_code == 409


def test_volver_a_abierto_no_es_un_destino_valido(env) -> None:
    c = _case(env["cases"])
    assert _state(env, "CISO", c["case_id"], "abierto").status_code == 422


def test_caso_inexistente_404_y_id_invalido_422(env) -> None:
    assert _state(env, "N1", "00000000-0000-0000-0000-000000000000", "en_investigacion").status_code == 404
    assert _state(env, "N1", "no-es-un-uuid", "en_investigacion").status_code == 422


def test_detalle_y_pagina_para_cualquier_rol(env) -> None:
    c = _case(env["cases"])
    r = _call(env, "N1", "GET", f"/api/v1/dashboard/cases/{c['case_id']}")
    assert r.status_code == 200 and r.json()["host"] == "45.9.20.7"
    page = _call(env, "N1", "GET", "/api/v1/dashboard/cases/page?limit=10").json()
    assert [x["case_id"] for x in page["items"]] == [c["case_id"]]
    assert _call(env, "N1", "GET", "/api/v1/dashboard/cases/page?limit=500").status_code == 422


def test_exportacion_csv_solo_n2_y_ciso(env) -> None:
    c = _case(env["cases"], "45.9.1.7", "t-1")
    _state(env, "N2", c["case_id"], "cerrado_confirmado", "escaneo masivo")
    assert _call(env, "N1", "GET", "/api/v1/dashboard/cases/closures.csv").status_code == 403
    r = _call(env, "CISO", "GET", "/api/v1/dashboard/cases/closures.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0] == "case_id,ip,net24,estado,hora,actor,trace_id"
    assert ",45.9.1.7,45.9.1.0/24,cerrado_confirmado," in lines[1] and lines[1].endswith(",un2,t-1")
    env["log"].assert_called_with("uciso", "cases_closures_exported", {"rows": 1})


def test_csv_neutraliza_formulas(env, monkeypatch) -> None:
    import main
    monkeypatch.setattr(main, "closed_cases_rows", lambda: [
        {"case_id": "x", "ip": "=HYPERLINK(1)", "net24": "", "estado": "cerrado_confirmado",
         "hora": "h", "actor": "@a", "trace_id": "t"}])
    body = _call(env, "N2", "GET", "/api/v1/dashboard/cases/closures.csv").text
    assert "'=HYPERLINK(1)" in body and "'@a" in body
