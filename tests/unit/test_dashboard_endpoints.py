"""
Endpoints de dashboard/auth vs. Fast Path (CLAUDE.md: "Fast Path nunca
bloquea por IO").

Los endpoints de dashboard hacen IO síncrono (OpenSearch vía urllib, Redis
síncrono, bcrypt). Si fueran `async def`, ese IO correría en el event loop de
uvicorn y frenaría /decide. Deben ser `def` (threadpool de FastAPI). Además:
filtro por tier + paginación por cursor de GET /api/v1/dashboard/decisions.
"""
from __future__ import annotations

import inspect
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")

PAYLOAD = {
    "SERVER_TCP_FLAGS": 2, "OUT_PKTS": 1,
    "FLOW_DURATION_MILLISECONDS": 10, "L4_DST_PORT": 443,
}


@pytest.fixture
def app_env(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # puerto inválido a propósito: sin Redis real
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)

    from fastapi.testclient import TestClient
    import main
    from users import User

    main.app.dependency_overrides[main.get_current_user] = (
        lambda: User(username="op", role="N1", created_at="", disabled=False)
    )
    yield TestClient(main.app), main
    main.app.dependency_overrides.clear()


class TestNingunEndpointDeDashboardBloqueaElLoop:
    def test_endpoints_de_dashboard_y_auth_son_sync(self, app_env) -> None:
        _, main = app_env
        guarded = [r for r in main.app.routes
                   if hasattr(r, "endpoint") and (
                       r.path.startswith(("/api/v1/dashboard/", "/api/v1/auth/"))
                       or r.path == "/dashboard")]
        assert len(guarded) >= 16
        offenders = [r.path for r in guarded if inspect.iscoroutinefunction(r.endpoint)]
        assert offenders == [], (
            "estos endpoints hacen IO síncrono y deben ser `def`, no `async def`: "
            f"{offenders}")

    def test_consulta_lenta_del_dashboard_no_frena_decide(self, app_env, monkeypatch) -> None:
        """Una consulta de dashboard de 2s (ej. OpenSearch lento) en curso no
        debe retrasar un /decide concurrente."""
        _, main = app_env
        from fastapi.testclient import TestClient

        def slow_stats(window_minutes):
            time.sleep(2.0)
            return {"available": True}
        monkeypatch.setattr(main, "get_stats", slow_stats)

        # `with`: un único event loop compartido por todas las requests, como
        # en uvicorn. Sin él, TestClient abre un loop por request y el
        # bloqueo nunca se observa.
        with TestClient(main.app) as client:
            assert client.post("/api/v1/decide", json=PAYLOAD).status_code == 200  # warm-up
            slow = threading.Thread(target=lambda: client.get("/api/v1/dashboard/stats"))
            slow.start()
            time.sleep(0.2)  # la consulta lenta ya está en curso
            t0 = time.monotonic()
            resp = client.post("/api/v1/decide", json=PAYLOAD)
            elapsed = time.monotonic() - t0
            slow.join()

        assert resp.status_code == 200
        assert elapsed < 1.0, f"/decide tardó {elapsed:.2f}s detrás de una consulta de dashboard"


class TestDecisionsQuery:
    def _captura(self, monkeypatch):
        import dashboard
        calls: list[dict] = []

        def fake_os_request(method, path, body=None):
            calls.append(body)
            return {"hits": {"hits": [{"_source": {"trace_id": "t1", "tier": 3}}]}}
        monkeypatch.setattr(dashboard, "_os_request", fake_os_request)
        return dashboard, calls

    def test_sin_filtros_match_all(self, app_env, monkeypatch) -> None:
        dashboard, calls = self._captura(monkeypatch)
        # with_regime agrega regime_id (None sin timestamp) y la marca de derivado
        assert dashboard.get_recent_decisions(10) == [
            {"trace_id": "t1", "tier": 3, "regime_id": None, "regime_derivado": True}]
        assert calls[0]["query"] == {"match_all": {}}
        assert calls[0]["size"] == 10
        assert calls[0]["sort"] == [{"timestamp": {"order": "desc"}}]

    def test_tier_min_y_cursor(self, app_env, monkeypatch) -> None:
        dashboard, calls = self._captura(monkeypatch)
        before = datetime(2026, 9, 30, 18, 0, tzinfo=timezone.utc)
        dashboard.get_recent_decisions(50, tier_min=2, before=before)
        assert calls[0]["query"] == {"bool": {"filter": [
            {"range": {"tier": {"gte": 2}}},
            {"range": {"timestamp": {"lt": "2026-09-30T18:00:00+00:00"}}},
        ]}}

    def test_limite_acotado(self, app_env, monkeypatch) -> None:
        dashboard, calls = self._captura(monkeypatch)
        dashboard.get_recent_decisions(10_000)
        assert calls[0]["size"] == dashboard.DECISIONS_MAX_LIMIT

    def test_opensearch_caido_lista_vacia(self, app_env, monkeypatch) -> None:
        import dashboard
        monkeypatch.setattr(dashboard, "_os_request", lambda *a, **k: None)
        assert dashboard.get_recent_decisions(10, tier_min=2) == []


class TestDecisionsEndpoint:
    def test_parametros_llegan_validados(self, app_env, monkeypatch, mocker) -> None:
        client, main = app_env
        spy = mocker.MagicMock(return_value=[])
        monkeypatch.setattr(main, "get_recent_decisions", spy)
        resp = client.get("/api/v1/dashboard/decisions",
                          params={"tier_min": 2, "limit": 100, "before": "2026-09-30T18:00:00Z"})
        assert resp.status_code == 200
        args, kwargs = spy.call_args
        assert args == (100,)
        assert kwargs["tier_min"] == 2
        assert kwargs["before"] == datetime(2026, 9, 30, 18, 0, tzinfo=timezone.utc)

    def test_defaults_compatibles(self, app_env, monkeypatch, mocker) -> None:
        client, main = app_env
        spy = mocker.MagicMock(return_value=[])
        monkeypatch.setattr(main, "get_recent_decisions", spy)
        assert client.get("/api/v1/dashboard/decisions").status_code == 200
        assert spy.call_args.args == (50,)
        assert spy.call_args.kwargs == {"tier_min": 0, "before": None}

    @pytest.mark.parametrize("params", [
        {"tier_min": 4}, {"tier_min": -1}, {"limit": 0}, {"limit": 201},
        {"before": "no-es-fecha"},
    ])
    def test_parametros_invalidos_422(self, app_env, monkeypatch, mocker, params) -> None:
        client, main = app_env
        spy = mocker.MagicMock(return_value=[])
        monkeypatch.setattr(main, "get_recent_decisions", spy)
        assert client.get("/api/v1/dashboard/decisions", params=params).status_code == 422
        spy.assert_not_called()
