"""H57: función guarda de SCAN (COUNT <= 100, pausa, tope de iteraciones)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import redis_guard

# ── Guarda de SCAN ───────────────────────────────────────────────────────────

class FakeScan:
    def __init__(self, n_iterations):
        self.n, self.calls = n_iterations, 0

    def scan(self, cursor=0, match=None, count=10):
        self.calls += 1
        return (0 if self.calls >= self.n else self.calls), [f"k{self.calls}"]


class TestGuardaScan:
    def test_count_mayor_a_100_se_rechaza(self) -> None:
        with pytest.raises(ValueError):
            list(redis_guard.guarded_scan(FakeScan(1), count=500))

    def test_tope_de_iteraciones(self) -> None:
        with pytest.raises(redis_guard.ScanLimitError):
            list(redis_guard.guarded_scan(FakeScan(10_000), count=100, pause=0, max_iterations=5))

    def test_recorrido_normal(self) -> None:
        assert len(list(redis_guard.guarded_scan(FakeScan(3), pause=0))) == 3
