"""
response/worker.py — Orquestador asíncrono de la capa de respuesta.

Proceso SEPARADO del Fast Path. Consume la stream Redis `soc:response:tasks`
(consumer group, at-least-once) y ejecuta:

    tier >= r1_min_tier  ->  R1 enrich  (pasivo)
    tier >= r2_min_tier  ->  R2 block   (activo, con salvaguardas)

Cada respuesta se audita como ResponseRecord hacia OpenSearch (mismo índice de
auditoría con hash-chain) y se loguea de forma estructurada.

Ejecutar como servicio systemd independiente del FastAPI:
    python -m response.worker
"""
from __future__ import annotations

import json
import logging
import time

import redis
from response.approvals import create_pending_approval, expire_stale_approvals
from response.cases import open_case
from response.config import get_settings
from response.enforcer import build_enforcer, is_safelisted, respond_block
from response.enrichment import enrich
from response.schemas import (
    ACCION_ALERTAR_CREAR_CASO,
    ACCION_ALERTAR_PENDIENTE_APROBACION,
    ACCION_BLOQUEO_IP,
    ACCION_NINGUNA,
    ActionType,
    BlockResult,
    ResponseRecord,
    ResponseTask,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("response.worker")


def _audit(record: ResponseRecord, rdb: redis.Redis):
    """Publica el registro de respuesta para indexado/auditoría."""
    try:
        rdb.xadd("soc:response:audit", {"data": json.dumps(record.to_audit_dict())},
                 maxlen=100_000, approximate=True)
    except redis.RedisError as e:
        log.warning(f"no se pudo auditar {record.trace_id}: {e}")


def stale_reason(max_age_seconds: int) -> str:
    """Motivo auditado de una acción omitida por antigüedad, ej.
    "stale_backlog_event_age>1h" (distinto de un skip por safelist)."""
    span = f"{max_age_seconds // 3600}h" if max_age_seconds % 3600 == 0 else f"{max_age_seconds}s"
    return f"stale_backlog_event_age>{span}"


def event_age_seconds(task: ResponseTask, enqueued_at: float | None, now: float) -> float | None:
    """Antigüedad de la detección: task.ts (lo fija el Fast Path al encolar)
    o, si falta, la marca de tiempo del ID del mensaje en el stream. None si
    no hay ninguna (la tarea se trata como fresca, igual que antes de H38)."""
    origin = task.ts or enqueued_at
    return max(0.0, now - origin) if origin else None


def process_task(
    task: ResponseTask, settings, rdb, enforcer, enqueued_at: float | None = None,
) -> ResponseRecord:
    """Procesa una tarea de respuesta (R1 + T2 + R2) y la audita.

    Args:
        task: tarea encolada por el Fast Path.
        settings: ResponseSettings.
        rdb: cliente Redis.
        enforcer: backend de bloqueo (dry_run / wazuh_api).
        enqueued_at: epoch del ID del mensaje en el stream, respaldo si
            task.ts no viene.

    Returns:
        El ResponseRecord auditado.
    """
    now = time.time()
    age = event_age_seconds(task, enqueued_at, now)
    # H38: una tarea del backlog con la detección más vieja que el umbral
    # completa R1 y se audita con su accion_recomendada, pero no ejecuta
    # nada (ni bloqueo, ni aprobación, ni caso): actuar horas después no es
    # respuesta, y en enforce bloquearía IPs vistas hace un día.
    stale = age is not None and age > settings.stale_event_max_age_seconds
    record = ResponseRecord(
        trace_id=task.trace_id,
        tier=task.tier,
        risk_score=task.risk_score,
        src_ip=task.src_ip,
        dst_ip=task.dst_ip,
        dst_port=task.dst_port,
        processed_at=now,
        event_age_seconds=round(age, 1) if age is not None else None,
    )

    # ── R1: enriquecimiento pasivo ──────────────────────────────────────
    if task.tier >= settings.r1_min_tier:
        # Stale: R1 solo con caché, sin APIs externas (H38).
        record.enrichment = enrich(task.src_ip, settings, rdb, cache_only=stale)
        e = record.enrichment
        log.info(
            f"[{task.trace_id[:8]}] R1 ip={task.src_ip} "
            f"abuse={e.abuseipdb_score} rdns={e.reverse_dns} "
            f"cached={e.cached} avail={e.abuseipdb_available}"
        )

    # ── T2: alertar + crear caso automático (tabla sección 4, origen Red) ──
    # Solo T2 exacto -- T3 tiene su propia rama abajo, T0/T1 no generan
    # ningún caso (accion_recomendada queda en su default "" -> ACCION_NINGUNA
    # se asigna explícitamente para que el dashboard no tenga que inferirlo).
    if task.tier == 2 and stale:
        record.accion_recomendada = ACCION_ALERTAR_CREAR_CASO
        log.info(f"[{task.trace_id[:8]}] T2 sin caso: {stale_reason(settings.stale_event_max_age_seconds)} (age={age:.0f}s)")
    elif task.tier == 2:
        record.accion_recomendada = ACCION_ALERTAR_CREAR_CASO
        case = open_case(
            kind="network_t2_unconfirmed",
            host=task.src_ip or "desconocido",
            detail={
                "trace_id": task.trace_id,
                "risk_score": task.risk_score,
                "dst_port": task.dst_port,
                "classtype": task.classtype,
                "corroboration_count": (
                    record.enrichment.corroboration_count if record.enrichment else 0
                ),
            },
            rdb=rdb,
        )
        record.case_id = case["case_id"]
        log.info(f"[{task.trace_id[:8]}] T2 caso automático abierto: {case['case_id']}")
    else:
        # Default para T0/T1 (y para cualquier tier fuera de 2 que no vaya a
        # pasar por la rama T3 de abajo) — la rama R2 lo sobreescribe si
        # corresponde.
        record.accion_recomendada = ACCION_NINGUNA

    # ── R2: acción activa (bloqueo) ─────────────────────────────────────
    if task.tier >= settings.r2_min_tier:
        corroboration_count = record.enrichment.corroboration_count if record.enrichment else 0
        corroborated = corroboration_count >= settings.min_corroborating_sources_for_autoblock

        if stale:
            # accion_recomendada = lo que se habría recomendado, para
            # trazabilidad; la acción en sí se omite y queda explícito por qué.
            reason = stale_reason(settings.stale_event_max_age_seconds)
            record.block = BlockResult(
                src_ip=task.src_ip, action=ActionType.BLOCK_SKIPPED, enforced=False,
                enforcer="none", reason=reason,
            )
            if task.src_ip and is_safelisted(task.src_ip, settings):
                record.accion_recomendada = ACCION_NINGUNA
            elif corroborated:
                record.accion_recomendada = ACCION_BLOQUEO_IP
            else:
                record.accion_recomendada = ACCION_ALERTAR_PENDIENTE_APROBACION
        elif corroborated:
            record.block = respond_block(task.src_ip, settings, rdb, enforcer, task.trace_id)
            record.accion_recomendada = (
                ACCION_BLOQUEO_IP if record.block.action == ActionType.BLOCK
                else ACCION_NINGUNA  # ya bloqueada / safelisted / dry_run sin ejecutar
            )
        elif task.src_ip and is_safelisted(task.src_ip, settings):
            # Infra propia: nunca se ofrece aprobar un bloqueo sobre ella (la
            # aprobación manual iba directo al enforcer, ver H38). Mismo
            # motivo que usa respond_block para el skip por safelist.
            record.block = BlockResult(
                src_ip=task.src_ip, action=ActionType.BLOCK_SKIPPED, enforced=False,
                enforcer="none", reason="safelisted (infra del lab)",
            )
            record.accion_recomendada = ACCION_NINGUNA
        else:
            # Score/tier alto pero sin corroboración multi-fuente suficiente:
            # no se ejecuta bloqueo automático (evita el falso positivo tipo
            # Bing/msnbot). Queda pendiente de aprobación humana en vez de
            # llegar al enforcer — R2 (enforcer.py) no se toca ni se invoca.
            record.block = BlockResult(
                src_ip=task.src_ip,
                action=ActionType.BLOCK_PENDING_APPROVAL,
                enforced=False,
                enforcer="none",
                reason=(
                    f"corroboración insuficiente ({corroboration_count}/"
                    f"{settings.min_corroborating_sources_for_autoblock} fuentes) "
                    "— requiere aprobación humana antes de bloquear"
                ),
                requires_approval=True,
                approval_level="N1",
            )
            record.accion_recomendada = ACCION_ALERTAR_PENDIENTE_APROBACION
            create_pending_approval(record, rdb)

        b = record.block
        log.info(
            f"[{task.trace_id[:8]}] R2 ip={task.src_ip} action={b.action.value} "
            f"enforced={b.enforced} reason='{b.reason}' via={b.enforcer} "
            f"corroboration={corroboration_count}"
        )

    _audit(record, rdb)
    return record


def sweep_expired_approvals(settings, rdb) -> int:
    """Expira las aprobaciones pendientes con más de approval_ttl_seconds y
    publica cada una en soc:response:audit como "expired" (distinto de un
    rejected: nadie la decidió). Devuelve cuántas expiró."""
    expired = expire_stale_approvals(rdb, settings.approval_ttl_seconds)
    for a in expired:
        payload = {
            "approval_expired": True,
            "trace_id": a["trace_id"],
            "src_ip": a.get("src_ip"),
            "status": "expired",
            "resolved_by": a.get("resolved_by"),
            "created_at": a.get("created_at"),
            "expired_at": a.get("resolved_at"),
            "occurrences": a.get("occurrences", 1),
            "ttl_seconds": settings.approval_ttl_seconds,
        }
        try:
            rdb.xadd("soc:response:audit", {"data": json.dumps(payload)},
                     maxlen=100_000, approximate=True)
        except redis.RedisError as e:
            log.warning(f"no se pudo auditar expiración de {a['trace_id']}: {e}")
    return len(expired)


def run():
    settings = get_settings()
    rdb = redis.Redis(
        host=settings.redis_host, port=settings.redis_port,
        password=settings.redis_password, decode_responses=True
    )
    enforcer = build_enforcer(settings)

    log.info(
        f"Response worker iniciando | mode={settings.response_mode.value} "
        f"enforcer={enforcer.name} r1_tier>={settings.r1_min_tier} "
        f"r2_tier>={settings.r2_min_tier} safelist={len(settings.safelist)} IPs"
    )

    # Crear consumer group (idempotente)
    try:
        rdb.xgroup_create(settings.response_stream, settings.response_group,
                          id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise

    last_sweep = 0.0
    while True:
        if time.time() - last_sweep >= settings.approval_sweep_interval_seconds:
            last_sweep = time.time()
            try:
                n = sweep_expired_approvals(settings, rdb)
                if n:
                    log.info(f"barrido de aprobaciones: {n} expiradas")
            except Exception as e:  # noqa: BLE001 — el barrido nunca debe tumbar el worker
                log.error(f"barrido de aprobaciones falló: {e}")

        try:
            msgs = rdb.xreadgroup(
                settings.response_group, settings.response_consumer,
                {settings.response_stream: ">"}, count=16, block=5000,
            )
        except redis.RedisError as e:
            log.error(f"error leyendo cola: {e}; reintentando en 2s")
            time.sleep(2)
            continue

        if not msgs:
            continue

        for _stream, entries in msgs:
            for msg_id, fields in entries:
                try:
                    raw = fields.get("data", "{}")
                    task = ResponseTask(**json.loads(raw))
                    process_task(task, settings, rdb, enforcer,
                                 enqueued_at=int(msg_id.split("-")[0]) / 1000)
                except Exception as e:  # noqa: BLE001 — el worker nunca debe morir
                    log.error(f"tarea {msg_id} falló: {e}")
                finally:
                    # ACK siempre: una tarea envenenada no debe bloquear la cola.
                    try:
                        rdb.xack(settings.response_stream, settings.response_group, msg_id)
                    except redis.RedisError:
                        pass


if __name__ == "__main__":
    run()
