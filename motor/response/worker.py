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

from response.config import get_settings
from response.enforcer import build_enforcer, respond_block
from response.enrichment import enrich
from response.schemas import ResponseRecord, ResponseTask

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


def process_task(task: ResponseTask, settings, rdb, enforcer) -> ResponseRecord:
    record = ResponseRecord(
        trace_id=task.trace_id,
        tier=task.tier,
        risk_score=task.risk_score,
        src_ip=task.src_ip,
        dst_ip=task.dst_ip,
        dst_port=task.dst_port,
        processed_at=time.time(),
    )

    # ── R1: enriquecimiento pasivo ──────────────────────────────────────
    if task.tier >= settings.r1_min_tier:
        record.enrichment = enrich(task.src_ip, settings, rdb)
        e = record.enrichment
        log.info(
            f"[{task.trace_id[:8]}] R1 ip={task.src_ip} "
            f"abuse={e.abuseipdb_score} rdns={e.reverse_dns} "
            f"cached={e.cached} avail={e.abuseipdb_available}"
        )

    # ── R2: acción activa (bloqueo) ─────────────────────────────────────
    if task.tier >= settings.r2_min_tier:
        record.block = respond_block(task.src_ip, settings, rdb, enforcer, task.trace_id)
        b = record.block
        log.info(
            f"[{task.trace_id[:8]}] R2 ip={task.src_ip} action={b.action.value} "
            f"enforced={b.enforced} reason='{b.reason}' via={b.enforcer}"
        )

    _audit(record, rdb)
    return record


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

    while True:
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
                    process_task(task, settings, rdb, enforcer)
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
