"""
response/queue.py — Puente entre el Fast Path (main.py) y la cola de respuesta.

`enqueue_response_task()` es lo único que el Fast Path llama. Es deliberadamente
trivial y no-bloqueante: serializa y hace XADD. Si Redis falla, NO rompe el
Fast Path — registra y sigue (la decisión ya se tomó y se publicó).
"""
from __future__ import annotations

import json
import logging
import time

import redis

from response.config import get_settings
from response.schemas import ResponseTask

log = logging.getLogger("response.queue")

# Conexión dedicada y reutilizable para encolar desde el Fast Path.
_settings = get_settings()
_rdb = redis.Redis(
    host=_settings.redis_host, port=_settings.redis_port,
    password=_settings.redis_password, decode_responses=True
)


def enqueue_response_task(
    trace_id: str,
    tier: int,
    risk_score: float,
    src_ip: str | None,
    dst_ip: str | None,
    dst_port: int,
    classtype: str = "",
    classtype_override: bool = False,
) -> None:
    """Encola una tarea de respuesta. Silencioso ante fallos de Redis."""
    # Solo encolar lo que va a producir alguna acción (tier >= r1_min_tier).
    if tier < _settings.r1_min_tier:
        return

    task = ResponseTask(
        trace_id=trace_id,
        tier=tier,
        risk_score=risk_score,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        classtype=classtype,
        classtype_override=classtype_override,
        ts=time.time(),
    )
    try:
        _rdb.xadd(
            _settings.response_stream,
            {"data": task.model_dump_json()},
            maxlen=200_000,
            approximate=True,
        )
    except redis.RedisError as e:
        # Nunca propagar al Fast Path.
        log.warning(f"no se pudo encolar respuesta [{trace_id[:8]}]: {e}")
