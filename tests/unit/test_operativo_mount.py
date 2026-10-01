"""
Montaje del Dashboard Operativo (bundle React/Vite) en /operativo.

Se prueba sobre una app FastAPI nueva con un bundle de mentira en tmp_path:
no depende de que exista un build real en motor/static/operativo.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")


@pytest.fixture
def mount_operativo(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)
    import main
    return main.mount_operativo


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>R-SOAR</title><div id=root></div>")
    (tmp_path / "assets" / "index-abc.js").write_text("console.log('ok')")
    return tmp_path


class TestMountOperativo:
    def test_sirve_index_y_assets(self, mount_operativo, bundle) -> None:
        app = FastAPI()
        assert mount_operativo(app, bundle) is True
        client = TestClient(app)
        resp = client.get("/operativo/")
        assert resp.status_code == 200
        assert "R-SOAR" in resp.text
        assert client.get("/operativo/assets/index-abc.js").status_code == 200

    def test_redirect_sin_barra_es_relativo(self, mount_operativo, bundle) -> None:
        """Detrás del proxy https de .139 un Location absoluto http:// sacaría
        al navegador de https: el redirect debe ser relativo."""
        app = FastAPI()
        mount_operativo(app, bundle)
        resp = TestClient(app).get("/operativo", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["location"] == "/operativo/"

    def test_estaticos_no_exigen_token(self, mount_operativo, bundle) -> None:
        app = FastAPI()
        mount_operativo(app, bundle)
        assert TestClient(app).get("/operativo/").status_code == 200

    def test_sin_bundle_no_monta_y_no_rompe_el_arranque(self, mount_operativo, tmp_path) -> None:
        app = FastAPI()
        assert mount_operativo(app, tmp_path / "no-existe") is False
        assert TestClient(app).get("/operativo/").status_code == 404

    def test_path_traversal_no_sale_del_bundle(self, mount_operativo, bundle) -> None:
        (bundle.parent / "secreto.env").write_text("REDIS_PASSWORD=x")
        app = FastAPI()
        mount_operativo(app, bundle)
        resp = TestClient(app).get("/operativo/..%2Fsecreto.env")
        assert "REDIS_PASSWORD" not in resp.text
