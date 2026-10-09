"""
redis_guard.py — Recorridos de Redis acotados (H57).

El incidente de H54 (una lectura masiva llevó used_memory a 1,35 GB y
allkeys-lru desalojó 72.205 claves) dejó una regla: en el Redis de .140 todo
recorrido pasa por esta función guarda. COUNT chico, pausa entre iteraciones
y tope de iteraciones; nunca KEYS, SMEMBERS de colecciones grandes ni lecturas
masivas.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import time
from collections.abc import Iterator

import redis

MAX_COUNT = 100
DEFAULT_PAUSE_SECONDS = 0.05
DEFAULT_MAX_ITERATIONS = 10_000


class ScanLimitError(RuntimeError):
    """El recorrido llegó al tope de iteraciones sin terminar."""


def guarded_scan(
    rdb: redis.Redis, *, match: str | None = None, set_key: str | None = None,
    count: int = MAX_COUNT, pause: float = DEFAULT_PAUSE_SECONDS,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
) -> Iterator[list[str]]:
    """Recorre el keyspace (SCAN) o un set (SSCAN) en lotes acotados.

    Args:
        rdb: cliente Redis.
        match: patrón MATCH (solo SCAN del keyspace).
        set_key: si viene, SSCAN sobre ese set en vez de SCAN.
        count: COUNT por iteración; nunca más de MAX_COUNT.
        pause: segundos de pausa entre iteraciones.
        max_iterations: tope; al alcanzarlo se lanza ScanLimitError.

    Yields:
        Cada lote no vacío de claves (o miembros).

    Raises:
        ValueError: si count > MAX_COUNT o pause < 0.
        ScanLimitError: si se alcanza max_iterations sin terminar.
    """
    if count > MAX_COUNT or count < 1:
        raise ValueError(f"COUNT {count} fuera de rango (1 a {MAX_COUNT})")
    if pause < 0:
        raise ValueError("pause no puede ser negativa")
    cursor, iterations = 0, 0
    while True:
        if set_key is not None:
            cursor, batch = rdb.sscan(set_key, cursor=cursor, count=count)
        else:
            cursor, batch = rdb.scan(cursor=cursor, match=match, count=count)
        iterations += 1
        if batch:
            yield list(batch)
        if int(cursor) == 0:
            return
        if iterations >= max_iterations:
            raise ScanLimitError(f"tope de {max_iterations} iteraciones alcanzado")
        time.sleep(pause)
