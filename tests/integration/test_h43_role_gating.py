"""
H43 — Rol-gating real de los endpoints nuevos del dashboard: el backend
rechaza al rol insuficiente (no basta con que el frontend oculte el link).
Usa la dependencia real get_current_user/get_current_session con tokens y
sesiones reales sobre una tabla de usuarios en memoria (sin Redis real).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "unit"))
from test_users_roles import FakeRedis

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")
PASSWORD = "una-passphrase-larga-123"  # pragma: allowlist secret (credencial ficticia de test)
TRACE = "9291e87d-a84d-4e61-b429-8f9207fd401b"

# (método, path, cuerpo, rol mínimo). "CISO!" = exclusivo de CISO.
ENDPOINTS = [
    ("GET", "/api/v1/dashboard/nodes", None, "N1"),
    ("GET", f"/api/v1/dashboard/audit/trace/{TRACE}", None, "N2"),
    ("GET", "/api/v1/dashboard/audit/chain", None, "N2"),
    ("GET", "/api/v1/dashboard/audit/access", None, "CISO!"),
    ("GET", "/api/v1/dashboard/users", None, "N2"),
    ("POST", "/api/v1/dashboard/users", {"username": "nuevo.op", "password": PASSWORD, "role": "N1"}, "N2"),
    ("GET", "/api/v1/dashboard/sessions", None, "N2"),
    ("GET", "/api/v1/dashboard/compliance", None, "CISO!"),
    ("GET", "/api/v1/dashboard/trends?days=7", None, "CISO!"),
]
LEVEL = {"N1": 1, "N2": 2, "CISO": 3}


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

    import audit_view
    import auth
    import compliance
    import user_admin
    import users
    from fastapi.testclient import TestClient

    import main

    auth.get_auth_settings.cache_clear()
    store = FakeRedis()
    monkeypatch.setattr(users, "_client", store)
    for mod in (auth, main, user_admin):
        monkeypatch.setattr(mod, "log_access_event", mocker.MagicMock())
    monkeypatch.setattr(main, "get_node_status", lambda: {"overall": "ok", "components": []})
    monkeypatch.setattr(audit_view, "search_trace",
                        lambda trace_id, include_access: {"trace_id": trace_id, "include_access": include_access})
    monkeypatch.setattr(audit_view, "chain_status", lambda: {"chains": {}})
    monkeypatch.setattr(audit_view, "access_events", lambda limit, username: {"available": True, "items": []})
    monkeypatch.setattr(compliance, "compliance_report", lambda w, n: {"checklist": []})
    monkeypatch.setattr(compliance, "get_trends", lambda days: {"days": days})

    tokens = {}
    for role in ("N1", "N2", "CISO"):
        tokens[role] = auth.create_access_token(users.create_user(f"u{role.lower()}", PASSWORD, role))
    yield {"client": TestClient(main.app), "tokens": tokens, "store": store}
    auth.get_auth_settings.cache_clear()


def _call(env, role, method, path, body=None):
    return env["client"].request(method, path, json=body,
                                 headers={"Authorization": f"Bearer {env['tokens'][role]}"})


@pytest.mark.parametrize("method,path,body,minimum", ENDPOINTS)
@pytest.mark.parametrize("role", ["N1", "N2", "CISO"])
def test_matriz_de_roles(env, role, method, path, body, minimum) -> None:
    exact = minimum.endswith("!")
    need = minimum.rstrip("!")
    allowed = role == need if exact else LEVEL[role] >= LEVEL[need]
    status = _call(env, role, method, path, body).status_code
    if allowed:
        assert status in (200, 201), f"{role} debería acceder a {path} (status {status})"
    else:
        assert status == 403, f"{role} NO debería acceder a {path} (status {status})"


def test_sin_token_401_en_todos(env) -> None:
    for method, path, body, _ in ENDPOINTS:
        assert env["client"].request(method, path, json=body).status_code == 401, path


def test_n2_ve_historial_parcial_y_ciso_completo(env) -> None:
    n2 = _call(env, "N2", "GET", f"/api/v1/dashboard/audit/trace/{TRACE}").json()
    ciso = _call(env, "CISO", "GET", f"/api/v1/dashboard/audit/trace/{TRACE}").json()
    assert (n2["scope"], n2["include_access"]) == ("partial", False)
    assert (ciso["scope"], ciso["include_access"]) == ("full", True)


def test_trace_id_invalido_422(env) -> None:
    assert _call(env, "CISO", "GET", "/api/v1/dashboard/audit/trace/no_valido!!").status_code in (404, 422)
    assert _call(env, "CISO", "GET", "/api/v1/dashboard/audit/trace/x'OR1=1-").status_code == 422


def test_logout_revoca_el_token_en_el_servidor(env) -> None:
    assert _call(env, "N1", "POST", "/api/v1/auth/logout").status_code == 200
    assert _call(env, "N1", "GET", "/api/v1/auth/me").status_code == 401


def test_revocar_sesion_propia_desde_el_panel(env) -> None:
    items = _call(env, "N2", "GET", "/api/v1/dashboard/sessions").json()["items"]
    mine = next(i for i in items if i["is_current"])
    resp = _call(env, "N2", "DELETE", f"/api/v1/dashboard/sessions/un2/{mine['jti']}")
    assert resp.json()["own_session_revoked"] is True
    assert _call(env, "N2", "GET", "/api/v1/auth/me").status_code == 401


def test_n2_no_puede_revocar_sesiones_de_ciso(env) -> None:
    assert _call(env, "N2", "DELETE", "/api/v1/dashboard/users/uciso/sessions").status_code == 403
    assert _call(env, "CISO", "GET", "/api/v1/auth/me").status_code == 200


def test_trends_days_invalido_422(env, monkeypatch) -> None:
    import compliance
    monkeypatch.setattr(compliance, "get_trends", lambda days: (_ for _ in ()).throw(ValueError("days")))
    assert _call(env, "CISO", "GET", "/api/v1/dashboard/trends?days=3").status_code == 422
