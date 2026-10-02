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
# H38 — dedup por IP: una sola aprobación pendiente por src_ip.
APPROVALS_BY_IP_PREFIX = "soc:approvals:by_ip:"  # ip -> trace_id de la pendiente abierta
# Contadores en un hash aparte (HINCRBY): el worker nunca reescribe el JSON
# de la aprobación al sumar ocurrencias, así no puede pisar una resolución
# hecha en paralelo desde el panel.
APPROVALS_META_PREFIX = "soc:approvals:meta:"    # hash: occurrences, last_seen_at, last_trace_id

APPROVALS_MAX_LIMIT = 1000  # tope por request del panel
EXPIRY_ACTOR = "system:expiry"
CAS_RETRIES = 3

ApprovalStatus = Literal["pending", "approved", "rejected", "expired"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_approval(trace_id: str, rdb: redis.Redis) -> dict | None:
    raw = rdb.get(f"{APPROVALS_KEY_PREFIX}{trace_id}")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.error(f"registro de aprobacion corrupto: {trace_id}")
        return None


def _with_meta(approval: dict, meta: dict | None) -> dict:
    """Agrega ocurrencias/última vez vista. Registros previos al dedup (sin
    hash de meta) cuentan como 1 ocurrencia vista al crearse."""
    meta = meta or {}
    view = dict(approval)
    view["occurrences"] = int(meta.get("occurrences", 1))
    view["last_seen_at"] = meta.get("last_seen_at") or approval.get("created_at")
    view["last_trace_id"] = meta.get("last_trace_id") or approval.get("trace_id")
    return view


def _open_for_ip(ip: str, rdb: redis.Redis) -> str | None:
    """trace_id de la aprobación pendiente abierta para `ip`, o None. Limpia
    un puntero que apunte a una aprobación ya resuelta/expirada."""
    tid = rdb.get(f"{APPROVALS_BY_IP_PREFIX}{ip}")
    if not tid:
        return None
    current = get_approval(tid, rdb)
    if current is not None and current.get("status") == "pending":
        return tid
    rdb.delete(f"{APPROVALS_BY_IP_PREFIX}{ip}")
    return None


def create_pending_approval(record: ResponseRecord, rdb: redis.Redis) -> dict:
    """Registra una aprobación pendiente para record.src_ip, o suma una
    ocurrencia a la que ya está abierta para esa IP (dedup, H38).

    Idempotente por trace_id: reprocesar la misma tarea (redelivery del
    stream) no duplica ni suma, y nunca reabre una aprobación resuelta.

    Returns:
        La aprobación (nueva o existente) con occurrences/last_seen_at.
    """
    block = record.block
    now = _now().isoformat()
    approval = {
        "trace_id": record.trace_id,
        "src_ip": record.src_ip,
        "tier": record.tier,
        "risk_score": record.risk_score,
        "reason": block.reason if block else "",
        "approval_level": block.approval_level if block else "N1",
        "status": "pending",
        "created_at": now,
        "resolved_by": None,
        "resolved_at": None,
    }
    ip = record.src_ip
    try:
        open_tid = _open_for_ip(ip, rdb) if ip else None
        if open_tid is not None and open_tid != record.trace_id:
            meta_key = f"{APPROVALS_META_PREFIX}{open_tid}"
            rdb.hincrby(meta_key, "occurrences", 1)
            rdb.hset(meta_key, mapping={"last_seen_at": now, "last_trace_id": record.trace_id})
            existing = get_approval(open_tid, rdb) or approval
            return _with_meta(existing, rdb.hgetall(meta_key))

        # NX: si el worker reprocesa el mismo trace_id no se pisa el registro
        # existente, en particular uno ya aprobado/rechazado/expirado.
        if not rdb.set(f"{APPROVALS_KEY_PREFIX}{record.trace_id}", json.dumps(approval), nx=True):
            existing = get_approval(record.trace_id, rdb)
            if existing is None:
                return approval
            if existing.get("status") == "pending":
                # Repara índice/puntero si un intento previo cayó a mitad de camino.
                rdb.sadd(APPROVALS_INDEX_KEY, record.trace_id)
                if ip:
                    rdb.set(f"{APPROVALS_BY_IP_PREFIX}{ip}", record.trace_id, nx=True)
            return _with_meta(existing, rdb.hgetall(f"{APPROVALS_META_PREFIX}{record.trace_id}"))
        rdb.sadd(APPROVALS_INDEX_KEY, record.trace_id)
        meta = {"occurrences": 1, "last_seen_at": now, "last_trace_id": record.trace_id}
        rdb.hset(f"{APPROVALS_META_PREFIX}{record.trace_id}", mapping=meta)
        if ip:
            rdb.set(f"{APPROVALS_BY_IP_PREFIX}{ip}", record.trace_id)
        return _with_meta(approval, meta)
    except redis.RedisError as e:
        log.error(f"no se pudo registrar aprobacion pendiente {record.trace_id}: {e}")
    return _with_meta(approval, None)


def is_expired(approval: dict, ttl_seconds: int, now: datetime | None = None) -> bool:
    """True si la aprobación pendiente superó el TTL desde su creación. Una
    fecha ilegible cuenta como vencida: expirar nunca ejecuta nada."""
    try:
        created = datetime.fromisoformat(approval["created_at"])
    except (KeyError, TypeError, ValueError):
        return True
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return ((now or _now()) - created).total_seconds() > ttl_seconds


def _transition(
    trace_id: str, new_status: ApprovalStatus, actor: str, rdb: redis.Redis, now: datetime,
) -> tuple[str, dict | None]:
    """pending -> new_status con compare-and-set (WATCH/MULTI): si otro
    proceso resolvió/expiró la aprobación entre la lectura y la escritura,
    no se pisa. Devuelve ("done"|"not_pending"|"missing"|"conflict", registro)."""
    key = f"{APPROVALS_KEY_PREFIX}{trace_id}"
    for _ in range(CAS_RETRIES):
        with rdb.pipeline() as pipe:
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                if raw is None:
                    pipe.unwatch()
                    return "missing", None
                try:
                    approval = json.loads(raw)
                except json.JSONDecodeError:
                    pipe.unwatch()
                    log.error(f"registro de aprobacion corrupto: {trace_id}")
                    return "missing", None
                if approval.get("status") != "pending":
                    pipe.unwatch()
                    return "not_pending", approval
                approval.update(status=new_status, resolved_by=actor, resolved_at=now.isoformat())
                ip = approval.get("src_ip")
                pointer = pipe.get(f"{APPROVALS_BY_IP_PREFIX}{ip}") if ip else None
                pipe.multi()
                pipe.set(key, json.dumps(approval))
                pipe.srem(APPROVALS_INDEX_KEY, trace_id)
                if ip and pointer == trace_id:
                    pipe.delete(f"{APPROVALS_BY_IP_PREFIX}{ip}")
                pipe.execute()
                return "done", approval
            except redis.WatchError:
                continue
    log.warning(f"aprobacion {trace_id}: {CAS_RETRIES} conflictos de escritura seguidos, no se resolvió")
    return "conflict", None


def _load_pending(rdb: redis.Redis) -> list[dict] | None:
    """Todas las aprobaciones pendientes, más recientes primero. None si
    Redis no responde (distinto de "no hay pendientes")."""
    try:
        trace_ids = rdb.smembers(APPROVALS_INDEX_KEY)
    except redis.RedisError as e:
        log.error(f"error leyendo indice de aprobaciones pendientes: {e}")
        return None
    approvals = []
    try:
        for tid in trace_ids:
            approval = get_approval(tid, rdb)
            if approval is not None and approval.get("status") == "pending":
                approvals.append(approval)
    except redis.RedisError as e:
        log.error(f"error leyendo aprobaciones pendientes: {e}")
        return None
    approvals.sort(key=lambda a: a.get("created_at", ""), reverse=True)
    return approvals


def list_pending_approvals(rdb: redis.Redis, limit: int = 100) -> list[dict]:
    return (_load_pending(rdb) or [])[:limit]


def pending_approvals_page(
    rdb: redis.Redis, limit: int = 100, ttl_seconds: int | None = None, now: datetime | None = None,
) -> dict:
    """Página de pendientes con el total real y las ocurrencias por IP.

    Args:
        rdb: cliente Redis.
        limit: máximo de ítems (los con actividad más reciente primero).
        ttl_seconds: si se pasa, oculta las vencidas aunque el barrido del
            worker todavía no las haya expirado (solo lectura, no escribe).
        now: reloj inyectable para tests.

    Returns:
        {"items": [...], "total": int, "limit": int, "available": bool};
        available=False si Redis no respondió (total 0 no significa cola vacía).
    """
    pending = _load_pending(rdb)
    if pending is None:
        return {"items": [], "total": 0, "limit": limit, "available": False}
    if ttl_seconds is not None:
        pending = [a for a in pending if not is_expired(a, ttl_seconds, now)]
    try:
        metas: list = []
        if pending:
            pipe = rdb.pipeline(transaction=False)
            for a in pending:
                pipe.hgetall(f"{APPROVALS_META_PREFIX}{a['trace_id']}")
            metas = pipe.execute()
    except redis.RedisError as e:
        log.error(f"error leyendo ocurrencias de aprobaciones: {e}")
        metas = [None] * len(pending)
    items = [_with_meta(a, m) for a, m in zip(pending, metas)]
    items.sort(key=lambda a: a.get("last_seen_at") or "", reverse=True)
    return {"items": items[:limit], "total": len(items), "limit": limit, "available": True}


def resolve_approval(
    trace_id: str, resolved_by: str, decision: ApprovalStatus, rdb: redis.Redis,
) -> dict | None:
    """Marca una aprobación como approved/rejected. No ejecuta el enforcer —
    eso lo hace el llamador (main.py) DESPUÉS de esta función, solo si
    decision == "approved", para mantener esta función libre de side effects
    de red (fácil de testear, y consistente con el resto del código de R2).

    Returns:
        La aprobación resuelta; la existente sin cambios si ya no estaba
        pendiente (idempotente, no se pisa la resolución anterior); None si
        no existe o si Redis falló (se loguea).
    """
    try:
        kind, approval = _transition(trace_id, decision, resolved_by, rdb, _now())
    except redis.RedisError as e:
        log.error(f"no se pudo resolver aprobacion {trace_id}: {e}")
        return None
    if kind == "done":
        log.info(f"aprobacion {trace_id} -> {decision} por {resolved_by}")
        return approval
    if kind == "not_pending":
        return approval
    return None


def expire_stale_approvals(
    rdb: redis.Redis, ttl_seconds: int, now: datetime | None = None,
) -> list[dict]:
    """Auto-rechaza como "expired" (no "rejected": nadie lo decidió) las
    pendientes con más de ttl_seconds. No audita: devuelve las expiradas
    para que el llamador (worker) las publique en soc:response:audit.

    Returns:
        Las aprobaciones expiradas en esta pasada, con sus ocurrencias.
    """
    now = now or _now()
    expired: list[dict] = []
    pending = _load_pending(rdb) or []
    for a in pending:
        if not is_expired(a, ttl_seconds, now):
            continue
        try:
            kind, rec = _transition(a["trace_id"], "expired", EXPIRY_ACTOR, rdb, now)
            if kind == "done" and rec is not None:
                expired.append(_with_meta(rec, rdb.hgetall(f"{APPROVALS_META_PREFIX}{a['trace_id']}")))
        except redis.RedisError as e:
            log.error(f"barrido de expiración interrumpido en {a.get('trace_id')}: {e}")
            break
    if expired:
        log.info(f"{len(expired)} aprobaciones expiradas (> {ttl_seconds}s sin resolver)")
    return expired
