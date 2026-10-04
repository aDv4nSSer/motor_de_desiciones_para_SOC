"""
H45 — X-Trace-Id en TODA respuesta (CLAUDE.md, observability.md), en los dos
servicios FastAPI del repo: el motor (motor/main.py, producción) y la API de
inferencia de la raíz (main.py). Incluye respuestas de error: 401, 404, 422 y
500 no controlado.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
MOTOR_PATH = str(ROOT / "motor")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TRACE = "test-trace-abc-123"


@pytest.fixture
def motor_client(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # sin Redis real
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)
    import main
    yield TestClient(main.app)
    sys.modules.pop("main", None)


@pytest.fixture
def api_client():
    spec = importlib.util.spec_from_file_location("root_api_main", ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return TestClient(module.app)


@pytest.fixture
def trace_module():
    sys.path.insert(0, MOTOR_PATH)
    import trace_middleware
    return trace_middleware


class TestResolveTraceId:
    def test_valido_se_respeta(self, trace_module) -> None:
        assert trace_module.resolve_trace_id(TRACE) == TRACE

    @pytest.mark.parametrize("bad", [None, "", "corto", "a" * 65, "x'OR1=1-abcdef",
                                     "abc\r\nSet-Cookie: x=1", "trace id con espacios"])
    def test_ausente_o_invalido_genera_uuid(self, trace_module, bad) -> None:
        assert UUID_RE.match(trace_module.resolve_trace_id(bad))


class TestMotor:
    def test_genera_trace_id_si_no_viene(self, motor_client) -> None:
        resp = motor_client.get("/api/v1/auth/me")  # 401 sin token
        assert resp.status_code == 401
        assert UUID_RE.match(resp.headers["X-Trace-Id"])
        assert float(resp.headers["X-Duration-Ms"]) >= 0

    def test_propaga_el_trace_id_del_request(self, motor_client) -> None:
        resp = motor_client.get("/api/v1/auth/me", headers={"X-Trace-Id": TRACE})
        assert resp.headers["X-Trace-Id"] == TRACE

    def test_trace_id_invalido_no_se_refleja(self, motor_client) -> None:
        resp = motor_client.get("/api/v1/auth/me", headers={"X-Trace-Id": "x'OR1=1-abcdef"})
        assert UUID_RE.match(resp.headers["X-Trace-Id"])

    @pytest.mark.parametrize("method,path,body,status", [
        ("GET", "/ruta/que/no/existe", None, 404),
        ("POST", "/api/v1/auth/login", {"username": "x"}, 422),
        ("GET", "/api/v1/dashboard/nodes", None, 401),
    ])
    def test_header_en_respuestas_de_error(self, motor_client, method, path, body, status) -> None:
        resp = motor_client.request(method, path, json=body)
        assert resp.status_code == status
        assert UUID_RE.match(resp.headers["X-Trace-Id"])

    def test_un_solo_header_por_respuesta(self, motor_client) -> None:
        resp = motor_client.get("/api/v1/auth/me", headers={"X-Trace-Id": TRACE})
        assert resp.headers.get_list("X-Trace-Id") == [TRACE]


class TestErrorNoControlado:
    def _app(self, trace_module) -> FastAPI:
        app = FastAPI()
        app.add_middleware(trace_module.TraceIdMiddleware)

        @app.get("/boom")
        def boom():
            raise RuntimeError("falla de prueba")

        return app

    def test_500_lleva_header_y_error_uniforme(self, trace_module) -> None:
        client = TestClient(self._app(trace_module), raise_server_exceptions=False)
        resp = client.get("/boom", headers={"X-Trace-Id": TRACE})
        assert resp.status_code == 500
        assert resp.headers["X-Trace-Id"] == TRACE
        err = resp.json()["error"]
        assert err["code"] == "INTERNAL_ERROR"
        assert err["trace_id"] == TRACE
        assert err["timestamp"]
        assert "falla de prueba" not in resp.text  # no filtra el detalle interno

    def test_la_excepcion_se_relanza(self, trace_module) -> None:
        # uvicorn debe seguir viendo (y logueando) la excepción original.
        with pytest.raises(RuntimeError, match="falla de prueba"):
            TestClient(self._app(trace_module)).get("/boom")


class TestApiInferencia:
    def test_health_con_header(self, api_client) -> None:
        resp = api_client.get("/health", headers={"X-Trace-Id": TRACE})
        assert resp.status_code == 200
        assert resp.headers["X-Trace-Id"] == TRACE

    def test_404_genera_uuid(self, api_client) -> None:
        resp = api_client.get("/no-existe")
        assert resp.status_code == 404
        assert UUID_RE.match(resp.headers["X-Trace-Id"])
