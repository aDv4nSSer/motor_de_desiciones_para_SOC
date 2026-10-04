"""
H43 — Sesiones revocables por token (jti) y gestión de usuarios desde el
dashboard con mínimo privilegio (user_admin.py). Redis en memoria, sin red.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import jwt
import pytest
import redis
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import auth
import sessions
import user_admin
import users
from test_users_roles import FakeRedis

PASSWORD = "una-passphrase-larga-123"  # pragma: allowlist secret (credencial ficticia de test)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    auth.get_auth_settings.cache_clear()
    monkeypatch.setenv("FASTAPI_SECRET_KEY", "clave-de-test-no-usar-en-produccion")
    rdb = FakeRedis()
    monkeypatch.setattr(users, "_client", rdb)
    events: list[tuple[str, str, dict]] = []
    record = lambda username, event, detail=None: events.append((username, event, detail or {}))
    monkeypatch.setattr(auth, "log_access_event", record)
    monkeypatch.setattr(user_admin, "log_access_event", record)
    rdb.events = events
    yield rdb
    auth.get_auth_settings.cache_clear()


def _creds(token: str):
    class _C:
        credentials = token
    return _C()


def _user(name: str, role: str) -> users.User:
    return users.create_user(name, PASSWORD, role)


class TestSesionesPorToken:
    def test_token_lleva_jti_y_queda_registrado(self, env) -> None:
        token = auth.create_access_token(_user("ana", "N1"), user_agent="Firefox", client_ip="10.0.0.9")
        claims = jwt.decode(token, options={"verify_signature": False})
        listed = sessions.list_sessions("ana")
        assert [s.jti for s in listed] == [claims["jti"]]
        assert listed[0].user_agent == "Firefox" and listed[0].client_ip == "10.0.0.9"

    def test_revocar_un_token_no_afecta_a_otro_del_mismo_usuario(self, env) -> None:
        u = _user("ana", "N2")
        t1, t2 = auth.create_access_token(u), auth.create_access_token(u)
        jti1 = jwt.decode(t1, options={"verify_signature": False})["jti"]
        assert sessions.revoke_session("ana", jti1) is True
        with pytest.raises(HTTPException) as e:
            auth.get_current_user(_creds(t1))
        assert e.value.status_code == 401
        assert env.events[-1][1] == "token_rejected_session_revoked"
        assert auth.get_current_user(_creds(t2)).username == "ana"

    def test_token_sin_jti_previo_a_h43_rechazado(self, env) -> None:
        _user("ana", "N1")
        now = int(time.time())
        legacy = jwt.encode({"sub": "ana", "role": "N1", "iat": now, "exp": now + 60},
                            "clave-de-test-no-usar-en-produccion", algorithm="HS256")
        with pytest.raises(HTTPException) as e:
            auth.get_current_user(_creds(legacy))
        assert e.value.status_code == 401

    def test_sesiones_vencidas_se_limpian_al_listar(self, env) -> None:
        sessions.register_session(sessions.Session(jti="a1", username="ana", role="N1", issued_at=1, expires_at=2))
        assert sessions.list_sessions("ana") == []
        assert env.hgetall("soc:sessions:ana") == {}

    def test_redis_caido_al_registrar_login_da_503(self, env, monkeypatch) -> None:
        _user("ana", "N1")

        def boom(*a, **k):
            raise redis.ConnectionError("caído")
        monkeypatch.setattr(env, "hset", boom)
        with pytest.raises(HTTPException) as e:
            auth.login("ana", PASSWORD)
        assert e.value.status_code == 503


class TestPoliticaDeGestion:
    @pytest.mark.parametrize("actor,target,ok", [
        ("CISO", "N1", True), ("CISO", "N2", True), ("CISO", "CISO", True),
        ("N2", "N1", True), ("N2", "N2", False), ("N2", "CISO", False),
        ("N1", "N1", False),
    ])
    def test_matriz_can_manage(self, actor, target, ok) -> None:
        a = users.User(username="x", role=actor, created_at="")
        assert user_admin.can_manage(a, target) is ok

    def test_n2_crea_n1_y_queda_auditado(self, env) -> None:
        actor = _user("jefe", "N2")
        user_admin.create_account(actor, "nuevo.op", PASSWORD, "N1")
        assert users.get_user_record("nuevo.op").role == "N1"
        assert ("jefe", "user_created", {"target": "nuevo.op", "role": "N1"}) in env.events

    @pytest.mark.parametrize("role", ["N2", "CISO"])
    def test_n2_no_crea_su_nivel_ni_superior(self, env, role) -> None:
        actor = _user("jefe", "N2")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.create_account(actor, "otro", PASSWORD, role)
        assert e.value.status == 403
        assert users.get_user_record("otro") is None
        assert env.events[-1][1] == "user_admin_denied"

    def test_alta_no_reemplaza_usuario_existente(self, env) -> None:
        actor = _user("ciso", "CISO")
        _user("ana", "N1")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.create_account(actor, "ana", PASSWORD, "CISO")
        assert e.value.status == 409
        assert users.get_user_record("ana").role == "N1"

    @pytest.mark.parametrize("username,password", [
        ("AB", PASSWORD), ("con espacio", PASSWORD), ("ok.user", "corta"), ("ok.user", "ñ" * 40),
    ])
    def test_validaciones_de_alta(self, env, username, password) -> None:
        actor = _user("ciso", "CISO")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.create_account(actor, username, password, "N1")
        assert e.value.status == 422

    def test_n2_no_da_de_baja_a_otro_n2(self, env) -> None:
        actor = _user("jefe", "N2")
        _user("par", "N2")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.update_account(actor, "par", None, True)
        assert e.value.status == 403
        assert users.get_user_record("par").disabled is False

    def test_n2_no_promueve_n1_a_n2(self, env) -> None:
        actor = _user("jefe", "N2")
        _user("op", "N1")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.update_account(actor, "op", "N2", None)
        assert e.value.status == 403
        assert users.get_user_record("op").role == "N1"

    def test_nadie_se_cambia_a_si_mismo(self, env) -> None:
        actor = _user("ciso", "CISO")
        _user("ciso2", "CISO")
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.update_account(actor, "ciso", "N1", None)
        assert e.value.status == 403

    def test_ultimo_ciso_no_se_puede_degradar(self, env) -> None:
        actor = _user("ciso", "CISO")
        _user("ciso2", "CISO")
        users.update_user("ciso", disabled=True)  # queda un solo CISO habilitado: ciso2
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.update_account(users.User(username="ciso", role="CISO", created_at=""), "ciso2", "N2", None)
        assert e.value.status == 409
        assert actor.role == "CISO"

    def test_baja_revoca_sesiones_y_token_deja_de_servir(self, env) -> None:
        actor = _user("ciso", "CISO")
        token = auth.create_access_token(_user("op", "N1"))
        result = user_admin.update_account(actor, "op", None, True)
        assert result["revoked_sessions"] == 1
        assert sessions.list_sessions("op") == []
        with pytest.raises(HTTPException):
            auth.get_current_user(_creds(token))
        assert ("ciso", "user_disabled", {"target": "op"}) in env.events

    def test_reset_password_revoca_sesiones_y_cambia_hash(self, env) -> None:
        actor = _user("jefe", "N2")
        auth.create_access_token(_user("op", "N1"))
        old_hash = users.get_user_record("op").password_hash
        assert user_admin.reset_password(actor, "op", "otra-clave-bien-larga")["revoked_sessions"] == 1
        assert users.get_user_record("op").password_hash != old_hash
        assert users.authenticate("op", "otra-clave-bien-larga") is not None

    def test_n2_ve_sesiones_de_n1_y_propias_no_de_ciso(self, env) -> None:
        jefe = _user("jefe", "N2")
        auth.create_access_token(jefe)
        auth.create_access_token(_user("op", "N1"))
        auth.create_access_token(_user("ciso", "CISO"))
        assert {s["username"] for s in user_admin.visible_sessions(jefe)} == {"jefe", "op"}

    def test_n2_no_revoca_sesion_de_ciso(self, env) -> None:
        jefe = _user("jefe", "N2")
        token = auth.create_access_token(_user("ciso", "CISO"))
        jti = jwt.decode(token, options={"verify_signature": False})["jti"]
        with pytest.raises(user_admin.AdminError) as e:
            user_admin.revoke(jefe, "ciso", jti, "otra")
        assert e.value.status == 403
        assert sessions.session_exists("ciso", jti)

    def test_revocar_la_propia_sesion_se_informa(self, env) -> None:
        jefe = _user("jefe", "N2")
        token = auth.create_access_token(jefe)
        jti = jwt.decode(token, options={"verify_signature": False})["jti"]
        assert user_admin.revoke(jefe, "jefe", jti, jti)["own_session_revoked"] is True
