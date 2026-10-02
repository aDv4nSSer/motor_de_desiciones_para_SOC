"""
Gate de rol de POST /api/v1/dashboard/approvals/{trace_id}/resolve.

El nivel mínimo lo trae cada registro (approval_level), según la tabla de la
sección 4 de docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md: bloqueo de red con
corroboración insuficiente -> N1 o superior; cuarentena de host -> N2 o CISO.
Verifica la jerarquía N1<N2<CISO y que un nivel vacío/desconocido falle
cerrado (exige CISO) en vez de degradarse a N1.

Sin Redis ni enforcer reales: FakeRedis en memoria y enforcer mockeado.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "unit"))
from test_approvals import FakeRedis, _record  # noqa: E402

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")


@pytest.fixture
def app_env(monkeypatch, mocker):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # puerto inválido a propósito: sin Redis real
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)

    from fastapi.testclient import TestClient
    import main
    from response.approvals import create_pending_approval, get_approval
    from users import User

    rdb = FakeRedis()
    rdb.xadd = mocker.MagicMock()  # auditoría de la aprobación manual
    monkeypatch.setattr(main, "get_dashboard_redis", lambda: rdb)
    monkeypatch.setattr(main, "log_access_event", mocker.MagicMock())
    enforcer = mocker.MagicMock()
    enforcer.block.return_value = (True, None)
    monkeypatch.setattr(main, "build_enforcer", lambda settings: enforcer)
    monkeypatch.setattr(main, "get_response_settings", lambda: mocker.MagicMock(
        block_ttl_seconds=3600, approval_ttl_seconds=14400, safelist=set()))

    def as_role(role: str) -> None:
        main.app.dependency_overrides[main.get_current_user] = (
            lambda: User(username=f"user-{role.lower()}", role=role, created_at="", disabled=False)
        )

    def pending(trace_id: str, level: str | None, src_ip: str = "1.2.3.4") -> None:
        create_pending_approval(_record(trace_id, approval_level=level or "", src_ip=src_ip), rdb)
        if level is None:  # registro sin la clave approval_level
            import json
            stored = get_approval(trace_id, rdb)
            stored.pop("approval_level")
            rdb._kv[f"soc:approvals:{trace_id}"] = json.dumps(stored)

    yield {"client": TestClient(main.app), "main": main, "rdb": rdb, "enforcer": enforcer,
           "as_role": as_role, "pending": pending, "get": lambda t: get_approval(t, rdb)}
    main.app.dependency_overrides.clear()


def _resolve(env, trace_id: str, decision: str = "approved"):
    return env["client"].post(f"/api/v1/dashboard/approvals/{trace_id}/resolve",
                              json={"decision": decision})


class TestCuarentenaExigeN2:
    def test_n1_no_puede_aprobar_accion_nivel_n2(self, app_env) -> None:
        app_env["pending"]("t-cuarentena", "N2")
        app_env["as_role"]("N1")
        resp = _resolve(app_env, "t-cuarentena")
        assert resp.status_code == 403
        assert app_env["get"]("t-cuarentena")["status"] == "pending"
        app_env["enforcer"].block.assert_not_called()

    def test_n1_tampoco_puede_rechazarla(self, app_env) -> None:
        app_env["pending"]("t-cuarentena", "N2")
        app_env["as_role"]("N1")
        assert _resolve(app_env, "t-cuarentena", "rejected").status_code == 403
        assert app_env["get"]("t-cuarentena")["status"] == "pending"

    @pytest.mark.parametrize("role", ["N2", "CISO"])
    def test_n2_y_ciso_aprueban_y_se_ejecuta_el_enforcer(self, app_env, role) -> None:
        app_env["pending"]("t-cuarentena", "N2")
        app_env["as_role"](role)
        resp = _resolve(app_env, "t-cuarentena")
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"
        assert resp.json()["resolved_by"] == f"user-{role.lower()}"
        app_env["enforcer"].block.assert_called_once()


class TestJerarquia:
    def test_n1_confirma_bloqueo_de_red_nivel_n1(self, app_env) -> None:
        """Tabla sección 4: T3 red con 1 sola fuente -> confirmación N1 o superior."""
        app_env["pending"]("t-red", "N1")
        app_env["as_role"]("N1")
        assert _resolve(app_env, "t-red").status_code == 200

    def test_n2_no_alcanza_para_nivel_ciso(self, app_env) -> None:
        app_env["pending"]("t-ciso", "CISO")
        app_env["as_role"]("N2")
        assert _resolve(app_env, "t-ciso").status_code == 403
        app_env["enforcer"].block.assert_not_called()


class TestFailClosed:
    @pytest.mark.parametrize("level", [None, "", "n2", "ADMIN"])
    def test_nivel_ausente_o_desconocido_exige_ciso(self, app_env, level) -> None:
        app_env["pending"]("t-raro", level)
        for role in ("N1", "N2"):
            app_env["as_role"](role)
            assert _resolve(app_env, "t-raro").status_code == 403, role
        app_env["enforcer"].block.assert_not_called()
        app_env["as_role"]("CISO")
        assert _resolve(app_env, "t-raro").status_code == 200


class TestOtrosCaminos:
    def test_sin_token_401(self, app_env) -> None:
        app_env["main"].app.dependency_overrides.clear()
        app_env["pending"]("t-cuarentena", "N2")
        assert _resolve(app_env, "t-cuarentena").status_code == 401

    def test_ya_resuelta_409_y_no_se_pisa(self, app_env) -> None:
        app_env["pending"]("t-cuarentena", "N2")
        app_env["as_role"]("N2")
        assert _resolve(app_env, "t-cuarentena", "rejected").status_code == 200
        app_env["as_role"]("CISO")
        assert _resolve(app_env, "t-cuarentena", "approved").status_code == 409
        assert app_env["get"]("t-cuarentena")["status"] == "rejected"
        app_env["enforcer"].block.assert_not_called()

    def test_inexistente_404(self, app_env) -> None:
        app_env["as_role"]("CISO")
        assert _resolve(app_env, "no-existe").status_code == 404


class TestListadoConTotal:
    def test_endpoint_devuelve_total_y_respeta_limit(self, app_env) -> None:
        for i in range(7):
            app_env["pending"](f"t-{i}", "N1", src_ip=f"1.2.3.{10 + i}")
        app_env["as_role"]("N1")
        body = app_env["client"].get("/api/v1/dashboard/approvals", params={"limit": 3}).json()
        assert body["total"] == 7
        assert len(body["items"]) == 3
        assert body["available"] is True

    @pytest.mark.parametrize("limit", [0, 1001])
    def test_limit_fuera_de_rango_422(self, app_env, limit) -> None:
        app_env["as_role"]("N1")
        resp = app_env["client"].get("/api/v1/dashboard/approvals", params={"limit": limit})
        assert resp.status_code == 422


class TestSafelist:
    """La aprobación manual llama al enforcer directo: sin este gate, aprobar
    la IP del bastion o de un gateway bloquearía la propia infraestructura."""

    @pytest.mark.parametrize("ip", ["200.54.12.139", "10.30.30.1", "10.10.10.3"])
    def test_aprobar_ip_de_infra_422_sin_bloquear(self, app_env, monkeypatch, ip) -> None:
        from response.config import ResponseSettings
        monkeypatch.setattr(app_env["main"], "get_response_settings",
                            lambda: ResponseSettings(response_safelist_extra="200.54.12.139"))
        app_env["pending"]("t-infra", "N1", src_ip=ip)
        app_env["as_role"]("CISO")
        resp = _resolve(app_env, "t-infra", "approved")
        assert resp.status_code == 422
        assert "safelist" in resp.json()["detail"]
        app_env["enforcer"].block.assert_not_called()
        assert app_env["get"]("t-infra")["status"] == "pending"

    def test_rechazar_ip_de_infra_si_se_permite(self, app_env) -> None:
        app_env["pending"]("t-infra", "N1", src_ip="10.30.30.1")
        app_env["as_role"]("N1")
        assert _resolve(app_env, "t-infra", "rejected").status_code == 200
        app_env["enforcer"].block.assert_not_called()

    def test_listado_marca_safelisted(self, app_env) -> None:
        app_env["pending"]("t-infra", "N1", src_ip="10.30.30.1")
        app_env["pending"]("t-ext", "N1", src_ip="1.2.3.4")
        app_env["as_role"]("N1")
        items = {i["trace_id"]: i for i in app_env["client"].get("/api/v1/dashboard/approvals").json()["items"]}
        assert items["t-infra"]["safelisted"] is True
        assert items["t-ext"]["safelisted"] is False


class TestExpiradas:
    def _envejecer(self, app_env, trace_id: str, hours: float) -> None:
        import json as _json
        from datetime import datetime, timedelta, timezone
        a = app_env["get"](trace_id)
        a["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        app_env["rdb"]._kv[f"soc:approvals:{trace_id}"] = _json.dumps(a)

    def test_pendiente_vencida_por_edad_409_sin_ejecutar(self, app_env) -> None:
        """Aunque el barrido del worker no haya corrido, motor-soc no actúa
        sobre una aprobación de más de 4 h."""
        app_env["pending"]("t-vieja", "N1")
        self._envejecer(app_env, "t-vieja", 5)
        app_env["as_role"]("CISO")
        resp = _resolve(app_env, "t-vieja")
        assert resp.status_code == 409
        assert "expiró" in resp.json()["detail"]
        app_env["enforcer"].block.assert_not_called()

    def test_ya_expirada_409_con_mensaje_de_expiracion(self, app_env) -> None:
        from response.approvals import expire_stale_approvals
        app_env["pending"]("t-vieja", "N1")
        self._envejecer(app_env, "t-vieja", 5)
        expire_stale_approvals(app_env["rdb"], 4 * 3600)
        app_env["as_role"]("N1")
        resp = _resolve(app_env, "t-vieja", "rejected")
        assert resp.status_code == 409
        assert "expiró" in resp.json()["detail"]

    def test_listado_no_muestra_vencidas_y_trae_ocurrencias(self, app_env) -> None:
        app_env["pending"]("t-vieja", "N1", src_ip="1.1.1.1")
        self._envejecer(app_env, "t-vieja", 5)
        app_env["pending"]("t-a", "N1", src_ip="2.2.2.2")
        app_env["pending"]("t-b", "N1", src_ip="2.2.2.2")
        app_env["as_role"]("N1")
        body = app_env["client"].get("/api/v1/dashboard/approvals").json()
        assert body["total"] == 1
        assert body["items"][0]["src_ip"] == "2.2.2.2"
        assert body["items"][0]["occurrences"] == 2
