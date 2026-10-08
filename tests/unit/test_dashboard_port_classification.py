"""
H56: el tráfico contra Cowrie llega al motor por el puerto 2223 (REDIRECT
22 -> 2223 en .139, antes de NFQUEUE). El dashboard lo clasificaba como
"external" porque HONEYPOT_PORTS solo tenía el 22.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from dashboard import classify_port


@pytest.mark.parametrize("port,expected", [
    (2223, "honeypot"),   # Cowrie tras el redirect: lo que de verdad ve Suricata
    (22, "honeypot"),     # los pocos flows sin redirigir
    (2222, "infra"),      # SSH de administración real
    (80, "external"),
])
def test_classify_port(port, expected) -> None:
    assert classify_port(port) == expected
