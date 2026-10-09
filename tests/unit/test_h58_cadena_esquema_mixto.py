"""
H58: el único campo nuevo que esta rama agrega a registros encadenados es
`approval_created_at`, dentro del payload de `manual_approval` y del `detail`
de los eventos de acceso `approval_rejected` (motor/main.py, H57 d).

El hash de cada eslabón es sha256(json canónico del contenido completo con
chain_seq + prev_hash): no depende del esquema. Por eso:
1. una cadena con eventos viejos (sin el campo) y nuevos (con el campo)
   intercalados verifica íntegra;
2. alterar un documento, viejo o nuevo, se sigue detectando;
3. el eslabón de un evento viejo da exactamente el mismo hash que con el
   indexador desplegado hoy en .140 (origin/develop, d0c8f93): no se
   recalcula nada histórico ni cambia la forma del cálculo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response_audit_indexer import STREAM, build_content, chain_document, verify_chain

from tests.unit.test_response_audit_indexer import (
    FakeOpenSearch,
    FakeStreamRedis,
    _drain,
    _indexer,
)

# Calculado con motor/response_audit_indexer.py de origin/develop (d0c8f93),
# el indexador que corre en .140, para el evento OLD_APPROVAL con chain_seq 7.
DEPLOYED_HASH = "61aa26e0ba0510f40c9230625ad0dbf741f962e39f39be312105bc5bfbeb09cc"  # pragma: allowlist secret (sha256 de prueba)
OLD_APPROVAL = {"trace_id": "t-viejo", "manual_approval": True, "approved_by": "aiayala", "approver_role": "CISO",
                "src_ip": "45.9.20.7", "enforced": True, "error": None, "at": "2026-10-05T12:00:00+00:00"}


def _events() -> list[dict]:
    response = {"trace_id": "t-r", "tier": 3, "risk_score": 0.9, "src_ip": "45.9.20.7",
                "accion_recomendada": "alertar_pendiente_aprobacion",
                "block": {"action": "block_pending_approval", "reason": "x", "enforced": False}}
    new_approval = {**OLD_APPROVAL, "trace_id": "t-nuevo", "approval_created_at": "2026-10-11T12:00:00+00:00"}
    old_reject = {"access_event": "approval_rejected", "username": "n1", "detail": {"trace_id": "t-rv"}}
    new_reject = {"access_event": "approval_rejected", "username": "n1",
                  "detail": {"trace_id": "t-rn", "approval_created_at": "2026-10-11T12:05:00+00:00"}}
    return [response, OLD_APPROVAL, old_reject, response, new_approval, new_reject, OLD_APPROVAL, new_approval]


def _chain() -> list[dict]:
    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    for e in _events():
        rdb.xadd(STREAM, {"data": json.dumps(e)})
    _drain(_indexer(rdb, osc))
    return osc.all_docs()


def test_cadena_mixta_vieja_y_nueva_verifica_integra() -> None:
    docs = _chain()
    assert len(docs) == 8 and verify_chain(docs) == []
    with_field = [d for d in docs if "approval_created_at" in json.dumps(d.get("payload", {}))]
    assert len(with_field) == 3  # dos aprobaciones nuevas y un rechazo nuevo


def test_alterar_un_documento_nuevo_se_detecta() -> None:
    docs = _chain()
    target = next(d for d in docs if d["payload"].get("approval_created_at"))
    target["payload"]["approval_created_at"] = "2026-10-11T00:00:00+00:00"  # adelantar la apertura
    problems = verify_chain(docs)
    assert any(f"chain_seq {target['chain_seq']}: el hash no corresponde" in p for p in problems)


def test_alterar_un_documento_viejo_se_detecta() -> None:
    docs = _chain()
    target = next(d for d in docs if d.get("event_type") == "manual_approval"
                  and "approval_created_at" not in d["payload"])
    target["payload"]["approved_by"] = "otro"
    assert any(f"chain_seq {target['chain_seq']}" in p for p in verify_chain(docs))


def test_el_eslabon_de_un_evento_viejo_no_cambia_respecto_del_desplegado() -> None:
    doc = chain_document(build_content("1791000000000-0", {"data": json.dumps(OLD_APPROVAL)}), 7, "prev-ejemplo")
    assert doc["hash"] == DEPLOYED_HASH
