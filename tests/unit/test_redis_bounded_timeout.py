"""
Continuación de H30: confirma que los clientes Redis del Fast Path
(redis_client.py y response/queue.py) están configurados para fallar en
un único intento acotado, no para reintentar silenciosamente.

Hallazgo validado con evidencia real (CLIENT PAUSE contra un Redis de
prueba local, ver docs/BITACORA_TECNICA.md): redis-py 8.x reintenta hasta
10 veces sobre TimeoutError por defecto, incluso con retry_on_timeout=False
(deprecado en 8.x — TimeoutError ya se incluye por defecto en el Retry)
— sin retry=Retry(NoBackoff(), 0) explícito, socket_timeout=1.0 no acota
el peor caso real (~5s medidos en vez de ~1s en la prueba).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from redis.backoff import NoBackoff
from redis.retry import Retry

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")
sys.path.insert(0, MOTOR_PATH)


class TestRedisClientHasBoundedRetry:
    def test_redis_client_uses_zero_retry(self, monkeypatch) -> None:
        monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
        import importlib
        sys.modules.pop("redis_client", None)
        mod = importlib.import_module("redis_client")

        client = mod.redis.Redis(
            host="localhost", port=6379, password="x", decode_responses=True,
            socket_timeout=1.0, socket_connect_timeout=1.0,
            retry=Retry(NoBackoff(), 0),
        )
        retry = client.connection_pool.connection_kwargs.get("retry")
        assert retry is not None and retry._retries == 0, (
            "el cliente debe tener 0 reintentos configurados explícitamente — "
            "el default de redis-py 8.x reintenta hasta 10 veces sobre "
            "timeout pese a retry_on_timeout=False"
        )

    def test_source_declares_explicit_zero_retry(self) -> None:
        source = (Path(MOTOR_PATH) / "redis_client.py").read_text()
        assert "Retry(NoBackoff(), 0)" in source


class TestResponseQueueHasBoundedRetry:
    def test_source_declares_explicit_zero_retry(self) -> None:
        source = (Path(MOTOR_PATH) / "response" / "queue.py").read_text()
        assert "Retry(NoBackoff(), 0)" in source

    def test_settings_declare_short_timeouts(self) -> None:
        from response.config import ResponseSettings

        s = ResponseSettings()
        assert s.redis_socket_timeout <= 2.0
        assert s.redis_socket_connect_timeout <= 2.0


@pytest.mark.parametrize("module_name", ["redis_client", "response.queue"])
def test_no_naked_redis_client_without_retry_override(module_name: str) -> None:
    """
    Guardrail: cualquier redis.Redis(...) nuevo en el Fast Path debe declarar
    retry= explícito. No previene todos los casos futuros, pero al menos
    obliga a que estos dos puntos de entrada conocidos no regresen.
    """
    rel_path = module_name.replace(".", "/") + ".py"
    source = (Path(MOTOR_PATH) / rel_path).read_text()
    assert "retry=Retry(NoBackoff(), 0)" in source, (
        f"{rel_path}: falta retry=Retry(NoBackoff(), 0) explícito en el "
        "cliente Redis del Fast Path (ver H30 en BITACORA_TECNICA.md)"
    )
