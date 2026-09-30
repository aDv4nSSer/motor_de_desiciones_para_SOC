"""
Verifica emisión/validación de JWT y el gating por rol (require_role /
require_ciso) de motor/auth.py — sección 5 de la especificación.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from auth import (
    create_access_token,
    get_auth_settings,
    get_current_user,
    require_ciso,
    require_role,
)
from users import User


@pytest.fixture(autouse=True)
def _jwt_secret(monkeypatch):
    """Fuerza un FASTAPI_SECRET_KEY determinístico para los tests, sin
    depender de que exista un .env real en este entorno."""
    get_auth_settings.cache_clear()
    monkeypatch.setenv("FASTAPI_SECRET_KEY", "clave-de-test-no-usar-en-produccion")
    yield
    get_auth_settings.cache_clear()


def _fake_credentials(token: str):
    class _Creds:
        credentials = token
    return _Creds()


class TestTokenRoundTrip:
    def test_token_decodes_back_to_same_user(self) -> None:
        user = User(username="ana", role="N2", created_at="", disabled=False)
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
