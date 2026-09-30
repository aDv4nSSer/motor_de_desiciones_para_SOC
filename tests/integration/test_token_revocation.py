"""
Revocación de sesión a nivel HTTP: un JWT válido en firma y vigencia deja de
servir en TODOS los endpoints protegidos apenas el usuario se deshabilita o
se borra. Usa la dependencia real get_current_user (sin overrides) contra
una tabla de usuarios en memoria — sin Redis real.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "unit"))
from test_users_roles import FakeRedis  # noqa: E402

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")

PROTECTED = [
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/dashboard/approvals"),
    ("GET", "/api/v1/dashboard/compliance"),
    ("GET", "/api/v1/dashboard/decisions"),
    ("POST", "/api/v1/dashboard/approvals/t-x/resolve"),
    ("GET", "/dashboard"),
]


@pytest.fixture
def env(monkeypatch, mocker):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # puerto inválido a propósito: sin Redis real
    monkeypatch.setenv("FASTAPI_SECRET_KEY", "clave-de-test-no-usar-en-produccion")
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)

    from fastapi.testclient import TestClient
    import auth
    import main
    import users

    auth.get_auth_settings.cache_clear()
    store = FakeRedis()
    monkeypatch.setattr(users, "_client", store)
    monkeypatch.setattr(auth, "log_access_event", mocker.MagicMock())
    monkeypatch.setattr(main, "log_access_event", mocker.MagicMock())
    monkeypatch.setattr(main, "get_dashboard_redis", lambda: FakeRedis())

    user = users.create_user("ana", "una-passphrase-larga-123", "CISO")
    token = auth.create_access_token(user)
    yield {"client": TestClient(main.app), "store": store, "users": users,
           "headers": {"Authorization": f"Bearer {token}"}}
    auth.get_auth_settings.cache_clear()


def _call(env, method: str, path: str):
    kwargs = {"headers": env["headers"]}
    if method == "POST":
        kwargs["json"] = {"decision": "rejected"}
    return env["client"].request(method, path, **kwargs)


class TestTokenRevocadoEnEndpoints:
    def test_usuario_activo_no_regresion(self, env) -> None:
        assert _call(env, "GET", "/api/v1/auth/me").json() == {"username": "ana", "role": "CISO"}
        assert _call(env, "GET", "/api/v1/dashboard/approvals").status_code == 200

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_usuario_deshabilitado_401_en_todo_endpoint(self, env, method, path) -> None:
        record = env["users"].get_user_record("ana")
        record.disabled = True
        env["store"].set("soc:users:ana", record.model_dump_json())
        assert _call(env, method, path).status_code == 401

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_usuario_borrado_401_en_todo_endpoint(self, env, method, path) -> None:
        del env["store"]._kv["soc:users:ana"]
        assert _call(env, method, path).status_code == 401

    def test_redis_caido_503_nunca_200(self, env, monkeypatch) -> None:
        def _boom(key):
            raise redis.ConnectionError("redis caído")
        monkeypatch.setattr(env["store"], "get", _boom)
        assert _call(env, "GET", "/api/v1/auth/me").status_code == 503
