"""
response/recidivism.py — Acumulador de recidivismo por IP para el grupo
`context` del score de corroboración (H53, modo sombra).

Sorted set `risk:ip:{ip}` (nombre de CLAUDE.md, `risk:{entity_type}:{entity_id}`):
miembro y score = inicio del bucket horario (epoch) en que la IP tuvo un
incidente T2+. Cuenta HORAS distintas, no eventos: un scanner manda cientos de
flows por hora y contar eventos saturaría el grupo con una sola ráfaga. Con el
score = epoch, la ventana de 30 días es un ZCOUNT por rango, sin sweep aparte.

Fuera de alcance a propósito: IPs propias/privadas/safelist (no tiene sentido
"recidivismo" del gateway, y eran el top-5 de eventos T2+ en .140) y
kill-chain progression (extensión futura del mismo acumulador).

Nunca lanza: si Redis falla, devuelve None y el grupo queda no disponible.
"""
from __future__ import annotations

import logging

import redis
from constants import (
    RECIDIVISM_BUCKET_SECONDS,
    RECIDIVISM_MAX_MEMBERS,
    RECIDIVISM_WINDOW_SECONDS,
    RISK_KEY_PREFIX,
)

log = logging.getLogger("response.recidivism")


def risk_key(ip: str) -> str:
    """Clave del acumulador de una IP."""
    return f"{RISK_KEY_PREFIX}ip:{ip}"


def bucket_start(ts: float) -> int:
    """Inicio (epoch) del bucket horario que contiene `ts`."""
    return int(ts // RECIDIVISM_BUCKET_SECONDS) * RECIDIVISM_BUCKET_SECONDS


def count_and_record(rdb: redis.Redis, ip: str, event_ts: float, now: float) -> int | None:
    """Cuenta las horas PREVIAS con incidentes T2+ de `ip` en los 30 días
    anteriores a `event_ts` y registra el bucket de este evento.

    El conteo excluye el bucket del propio evento, así que varios flows de la
    misma ráfaga no se cuentan entre sí: dos decisiones en la misma hora dan
    0 las dos; una en otra hora, más tarde, da 1. Usa la hora del EVENTO (no
    la de procesamiento) para que el backlog del worker (H38) no distorsione
    el conteo.

    Una sola ida y vuelta a Redis (pipeline sin transacción): ZCOUNT, ZADD,
    limpieza por ventana y por tope de miembros, EXPIRE.

    Args:
        rdb: cliente Redis del worker.
        ip: IP pública ya validada por el llamador (no safelist).
        event_ts: epoch de la detección (task.ts o equivalente).
        now: epoch actual, para la limpieza de miembros vencidos.

    Returns:
        Horas previas distintas con incidente T2+ en la ventana, o None si
        Redis falló (degradación con gracia: el grupo queda no disponible).
    """
    key = risk_key(ip)
    current = bucket_start(event_ts)
    try:
        pipe = rdb.pipeline(transaction=False)
        pipe.zcount(key, event_ts - RECIDIVISM_WINDOW_SECONDS, current - 1)
        pipe.zadd(key, {str(current): current})
        pipe.zremrangebyscore(key, "-inf", f"({now - RECIDIVISM_WINDOW_SECONDS}")
        pipe.zremrangebyrank(key, 0, -(RECIDIVISM_MAX_MEMBERS + 1))
        pipe.expire(key, RECIDIVISM_WINDOW_SECONDS)
        count = pipe.execute()[0]
        return int(count)
    except (redis.RedisError, TypeError, ValueError, IndexError) as e:
        log.warning(f"acumulador de recidivismo no disponible para {key}: {type(e).__name__}: {e}")
        return None
