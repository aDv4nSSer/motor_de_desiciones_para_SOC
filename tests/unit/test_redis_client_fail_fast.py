"""
Continuación de H26/H32: redis_client.py no debe arrancar con una password
adivinable por default — si REDIS_PASSWORD no está en el entorno, debe
fallar fuerte al importar, no arrancar silenciosamente con un fallback.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")


def _reload_redis_client(monkeypatch, redis_password: str | None):
    if redis_password is None:
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("REDIS_PASSWORD", redis_password)

    monkeypatch.syspath_prepend(MOTOR_PATH)
    sys.modules.pop("redis_client", None)
    return importlib.import_module("redis_client")


class TestRedisPasswordFailsFast:
    def test_missing_redis_password_raises_on_import(self, monkeypatch) -> None:
        with pytest.raises(RuntimeError, match="REDIS_PASSWORD"):
            _reload_redis_client(monkeypatch, redis_password=None)

    def test_empty_redis_password_also_raises(self, monkeypatch) -> None:
        with pytest.raises(RuntimeError, match="REDIS_PASSWORD"):
            _reload_redis_client(monkeypatch, redis_password="")

    def test_valid_redis_password_imports_cleanly(self, monkeypatch) -> None:
        mod = _reload_redis_client(monkeypatch, redis_password="test-pass")
        assert mod.REDIS_PASS == "test-pass"

    def test_no_hardcoded_password_fallback_in_source(self) -> None:
        """No debe reaparecer un default adivinable tipo os.environ.get('REDIS_PASSWORD', '<algo>')."""
        source = (Path(MOTOR_PATH) / "redis_client.py").read_text()
        assert 'os.environ.get("REDIS_PASSWORD")' in source
        assert 'os.environ.get("REDIS_PASSWORD", "' not in source
