"""
H57: los cambios de la vista Cumplimiento (y de casos, auditoría y regímenes)
no alteran ninguna decisión de R2.

Foto fija de las decisiones de process_task sobre los 180 docs reales del
8-oct (tests/fixtures/h56_replay_docs.json), con las APIs y Redis falsos del
test de invariancia de H56. Si un cambio altera una sola decisión
(accion_recomendada, acción de bloqueo, llamadas a respond_block, aprobación
o caso), este test falla. Regenerar la foto es una decisión explícita:
    REGENERAR_FOTO_R2=1 pytest tests/unit/test_h57_no_regresion_r2.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from tests.unit.test_abuseipdb_tier_policy import DOCS, _replay

SNAPSHOT = Path(__file__).resolve().parents[1] / "fixtures" / "h57_r2_decisiones.json"


def _decisions(mocker) -> list[list]:
    out = []
    for doc in DOCS:
        decision, _, _ = _replay(mocker, doc, new_policy=True)
        accion, block, n_block, n_pending, n_case = decision
        out.append([doc["src_ip"], doc["tier"], accion, getattr(block, "value", block), n_block, n_pending, n_case])
    return out


def test_las_decisiones_de_r2_no_cambian(mocker) -> None:
    got = _decisions(mocker)
    if os.environ.get("REGENERAR_FOTO_R2") == "1":
        SNAPSHOT.write_text(json.dumps(got, indent=0))
    expected = json.loads(SNAPSHOT.read_text())
    assert got == expected
    assert any(row[3] == "block" for row in expected)  # la foto ejercita la rama de bloqueo
