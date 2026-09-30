"""
response/approvals.py — Aprobaciones humanas pendientes (accion_recomendada
con requires_approval=True, ver schemas.BlockResult).

Persiste en Redis (estado operable, lo que consulta/resuelve el dashboard).
NO toca soc-decisions ni soc:response:audit directamente -- esos siguen
siendo append-only (CLAUDE.md prohibición #6). Cuando un operador aprueba,
se ejecuta el enforcer y se emite un NUEVO registro de auditoría (ver
main.py:resolve_approval_endpoint) -- nunca se edita el registro original.

Mismo patrón que vigilante/cases.py (Redis: hash JSON + set de índice),
pero como servicio separado: vigilante corre en `.139`, response-worker en
`.140`, y no se acoplan por import directo entre paquetes de servicios
distintos.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Literal

import redis
from response.schemas import ResponseRecord

log = logging.getLogger("response.approvals")

APPROVALS_KEY_PREFIX = "soc:approvals:"
APPROVALS_INDEX_KEY = "soc:approvals:pending"  # set — solo trace_id con status="pending"

ApprovalStatus = Literal["pending", "approved", "rejected"]


def create_pending_approval(record: ResponseRecord, rdb: redis.Redis) -> dict:
    """Registra una aprobación pendiente a partir de un ResponseRecord con
    block.requires_approval=True. Idempotente por trace_id."""
    block = record.block
    approval = {
        "trace_id": record.trace_id,
        "src_ip": record.src_ip,
        "tier": record.tier,
        "risk_score": record.risk_score,
        "reason": block.reason if block else "",
        "approval_level": block.approval_level if block else "N1",
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resolved_by": None,
        "resolved_at": None,
    }
    try:
        rdb.set(f"{APPROVALS_KEY_PREFIX}{record.trace_id}", json.dumps(approval))
        rdb.sadd(APPROVALS_INDEX_KEY, record.trace_id)
    except redis.RedisError as e:
        log.error(f"no se pudo registrar aprobacion pendiente {record.trace_id}: {e}")
    return approval


def get_approval(trace_id: str, rdb: redis.Redis) -> dict | None:
    raw = rdb.get(f"{APPROVALS_KEY_PREFIX}{trace_id}")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.error(f"registro de aprobacion corrupto: {trace_id}")
        return None


def list_pending_approvals(rdb: redis.Redis, limit: int = 100) -> list[dict]:
    try:
        trace_ids = rdb.smembers(APPROVALS_INDEX_KEY)
    except redis.RedisError as e:
        log.error(f"error leyendo indice de aprobaciones pendientes: {e}")
        return []
    approvals = []
    for tid in trace_ids:
        approval = get_approval(tid, rdb)
        if approval is not None and approval.get("status") == "pending":
            approvals.append(approval)
    approvals.sort(key=lambda a: a.get("created_at", ""), reverse=True)
    return approvals[:limit]


def resolve_approval(
    trace_id: str, resolved_by: str, decision: ApprovalStatus, rdb: redis.Redis,
) -> dict | None:
    """Marca una aprobación como approved/rejected. No ejecuta el enforcer —
    eso lo hace el llamador (main.py) DESPUÉS de esta función, solo si
    decision == "approved", para mantener esta función libre de side effects
    de red (fácil de testear, y consistente con el resto del código de R2)."""
    approval = get_approval(trace_id, rdb)
    if approval is None:
        return None
    if approval["status"] != "pending":
        return approval  # ya resuelta — idempotente, no se pisa la resolución anterior

    approval["status"] = decision
    approval["resolved_by"] = resolved_by
    approval["resolved_at"] = datetime.now(timezone.utc).isoformat()

    try:
        rdb.set(f"{APPROVALS_KEY_PREFIX}{trace_id}", json.dumps(approval))
        rdb.srem(APPROVALS_INDEX_KEY, trace_id)
    except redis.RedisError as e:
        log.error(f"no se pudo resolver aprobacion {trace_id}: {e}")
        return None

    log.info(f"aprobacion {trace_id} -> {decision} por {resolved_by}")
    return approval
