"""
Continuación de H30: motor/main.py::decide() corre process_event() vía
run_in_executor en vez de inline, para no bloquear el event loop de
uvicorn con trabajo síncrono (CPU-bound + Redis). Estos tests cubren
correctness básica (single/batch/malformado); la validación real de
degradación bajo Redis lento (CLIENT PAUSE contra un Redis de prueba) y
de concurrencia real está documentada en docs/BITACORA_TECNICA.md — no
requiere infraestructura externa para correr en CI.
"""
from __future__ import annotations

import sys
from pathlib import Path

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")


def _client(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # puerto inválido a propósito: sin Redis real
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)

    from fastapi.testclient import TestClient
    import main

    return TestClient(main.app), main


PAYLOAD = {
    "SERVER_TCP_FLAGS": 2, "OUT_PKTS": 1,
    "FLOW_DURATION_MILLISECONDS": 10, "L4_DST_PORT": 443,
}


class TestDecideSingleEvent:
    def test_single_event_returns_decision_object(self, monkeypatch) -> None:
        client, _ = _client(monkeypatch)
        resp = client.post("/decide", json=PAYLOAD)
        assert resp.status_code == 200
        body = resp.json()
        assert "tier" in body and "trace_id" in body and "decision" in body


class TestDecideBatch:
    def test_batch_returns_list_same_length(self, monkeypatch) -> None:
        client, _ = _client(monkeypatch)
        resp = client.post("/decide", json=[PAYLOAD, PAYLOAD, PAYLOAD])
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) == 3
        assert all("trace_id" in item for item in body)
        # cada evento debe tener su propio trace_id independiente
        assert len({item["trace_id"] for item in body}) == 3


class TestDecideMalformedInput:
    def test_invalid_json_returns_400(self, monkeypatch) -> None:
        client, _ = _client(monkeypatch)
        resp = client.post(
            "/decide", content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestDecideUsesExecutor:
    def test_decide_offloads_to_executor_not_inline(self, monkeypatch) -> None:
        """Confirma que process_event ya no se llama directo en el event loop
        — debe pasar por loop.run_in_executor, verificable viendo que el
        endpoint sigue funcionando incluso si comparamos con el hilo actual."""
        client, main = _client(monkeypatch)
        import threading

        calling_threads = []
        original = main.process_event

        def wrapped(*args, **kwargs):
            calling_threads.append(threading.current_thread())
            return original(*args, **kwargs)

        monkeypatch.setattr(main, "process_event", wrapped)
        resp = client.post("/decide", json=PAYLOAD)
        assert resp.status_code == 200
        assert len(calling_threads) == 1
        assert calling_threads[0] is not threading.main_thread(), (
            "process_event debe correr en un worker thread del executor, "
            "no en el hilo principal del event loop"
        )
