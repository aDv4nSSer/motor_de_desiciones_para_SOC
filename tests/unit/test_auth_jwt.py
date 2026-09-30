"""
Verifica emisión/validación de JWT y el gating por rol (require_role /
require_ciso) de motor/auth.py — sección 5 de la especificación.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import redis
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import auth
import users
from auth import (
    create_access_token,
    get_auth_settings,
    get_current_user,
    require_ciso,
    require_role,
)
from test_users_roles import FakeRedis
from users import User, create_user, get_user_record


@pytest.fixture(autouse=True)
def _jwt_secret(monkeypatch):
    """Fuerza un FASTAPI_SECRET_KEY determinístico para los tests, sin
    depender de que exista un .env real en este entorno."""
    get_auth_settings.cache_clear()
    monkeypatch.setenv("FASTAPI_SECRET_KEY", "clave-de-test-no-usar-en-produccion")
    yield
    get_auth_settings.cache_clear()


@pytest.fixture(autouse=True)
def user_store(monkeypatch):
    """Tabla de usuarios en memoria: get_current_user relee el usuario en
    cada request (revocación), así que ningún test toca un Redis real."""
    rdb = FakeRedis()
    monkeypatch.setattr(users, "_client", rdb)
    access_events: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(auth, "log_access_event",
                        lambda username, event, detail=None: access_events.append((username, event, detail)))
    rdb.access_events = access_events
    return rdb


def _fake_credentials(token: str):
    class _Creds:
        credentials = token
    return _Creds()


class TestTokenRoundTrip:
    def test_token_decodes_back_to_same_user(self) -> None:
        user = create_user("ana", "una-passphrase-larga-123", "N2")
        token = create_access_token(user)
        decoded = get_current_user(_fake_credentials(token))
        assert decoded.username == "ana"
        assert decoded.role == "N2"

    def test_missing_credentials_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(None)
        assert exc_info.value.status_code == 401

    def test_tampered_token_raises_401(self) -> None:
        user = User(username="ana", role="N1", created_at="", disabled=False)
        token = create_access_token(user)
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token + "x"))
        assert exc_info.value.status_code == 401


class TestRequireRoleGate:
    def test_n2_user_passes_n1_gate(self) -> None:
        user = User(username="ana", role="N2", created_at="", disabled=False)
        gate = require_role("N1")
        assert gate(user).username == "ana"

    def test_n1_user_fails_n2_gate(self) -> None:
        user = User(username="ana", role="N1", created_at="", disabled=False)
        gate = require_role("N2")
        with pytest.raises(HTTPException) as exc_info:
            gate(user)
        assert exc_info.value.status_code == 403

    def test_ciso_gate_rejects_n2_exactly(self) -> None:
        """require_ciso es exacto, NO acumulativo — N2 no hereda reportes
        de cumplimiento (sección 5: excepción explícita a la jerarquía)."""
        user = User(username="ana", role="N2", created_at="", disabled=False)
        with pytest.raises(HTTPException) as exc_info:
            require_ciso(user)
        assert exc_info.value.status_code == 403

    def test_ciso_gate_accepts_ciso(self) -> None:
        user = User(username="ana", role="CISO", created_at="", disabled=False)
        assert require_ciso(user).role == "CISO"


class TestRevocacion:
    """Un JWT válido en firma y vigencia no alcanza: el usuario tiene que
    seguir existiendo, activo y con el mismo rol del token."""

    def _token_de(self, username: str, role: str = "N2") -> str:
        return create_access_token(create_user(username, "una-passphrase-larga-123", role))

    def test_usuario_activo_sigue_pasando(self, user_store) -> None:
        token = self._token_de("ana")
        assert get_current_user(_fake_credentials(token)).username == "ana"
        assert user_store.access_events == []

    def test_usuario_deshabilitado_despues_del_token_401(self, user_store) -> None:
        token = self._token_de("ana")
        record = get_user_record("ana")
        record.disabled = True
        user_store.set("soc:users:ana", record.model_dump_json())

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token))
        assert exc_info.value.status_code == 401
        assert user_store.access_events[-1][1] == "token_rejected_user_state"
        assert user_store.access_events[-1][2]["reason"] == "deshabilitado"

    def test_usuario_borrado_despues_del_token_401(self, user_store) -> None:
        token = self._token_de("ana")
        del user_store._kv["soc:users:ana"]

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token))
        assert exc_info.value.status_code == 401
        assert user_store.access_events[-1][2]["reason"] == "inexistente"

    def test_rol_cambiado_despues_del_token_401(self, user_store) -> None:
        """Un CISO degradado a N1 no conserva privilegios CISO con su token viejo."""
        token = self._token_de("ana", role="CISO")
        create_user("ana", "una-passphrase-larga-123", "N1")

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token))
        assert exc_info.value.status_code == 401
        assert user_store.access_events[-1][2]["reason"] == "rol_cambiado"

    def test_registro_corrupto_401(self, user_store) -> None:
        token = self._token_de("ana")
        user_store.set("soc:users:ana", "{no es json")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token))
        assert exc_info.value.status_code == 401

    def test_redis_caido_falla_cerrado_503(self, user_store, monkeypatch) -> None:
        token = self._token_de("ana")

        def _boom(key):
            raise redis.ConnectionError("redis caído")
        monkeypatch.setattr(user_store, "get", _boom)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(_fake_credentials(token))
        assert exc_info.value.status_code == 503
