"""
response/cases.py — Apertura de casos desde el worker de respuesta (`.140`).

Mismo esquema y mismas keys de Redis que vigilante/cases.py (que corre en
`.139` para hallazgos de host/FIM) — así dashboard.list_cases() y
update_case_state(), que ya leen soc:cases:*, ven ambos orígenes (red y
host) sin ningún cambio ni duplicación de índice. Se duplica el código (en
vez de importar vigilante.cases desde acá) porque son paquetes de servicios
distintos que corren en hosts distintos — no se acoplan por import directo.

H57: cada T2 de IP pública abría un caso nuevo, sin TTL ni dedup (~550.000
casos y el principal consumo de memoria de Redis, cerca de su límite de 1 GB).
Ahora:
- Dedup por IP pública: mientras exista `soc:cases:open:ip:{ip}` (ventana
  de dedup), los T2 nuevos de esa IP se suman al caso abierto (ocurrencias,
  último trace_id) en vez de abrir otro. Un caso que un analista ya movió de
  "abierto" no se reutiliza: la recurrencia abre uno nuevo.
- TTL: los casos automáticos expiran `ttl` segundos después de la última
  ocurrencia. update_case_state() del dashboard reescribe el caso sin TTL, así
  que todo caso que un analista tocó queda persistente (es evidencia).
- `net24` (/24 en IPv4, /64 en IPv6) para agrupar campañas en el dashboard.
- Índice acotado `soc:cases:recent` (ZSET por última actividad, recortado a la
  ventana de TTL) para listar sin leer el índice completo. El SET histórico
  `soc:cases:index` se sigue alimentando por compatibilidad con vigilante.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import time
import uuid
from datetime import datetime, timezone

import redis

log = logging.getLogger("response.cases")

CASES_KEY_PREFIX = "soc:cases:"
CASES_INDEX_KEY = "soc:cases:index"
CASES_RECENT_KEY = "soc:cases:recent"
CASE_DEDUP_PREFIX = "soc:cases:open:ip:"
CASE_TTL_SECONDS = 7 * 86400
CASE_DEDUP_WINDOW_SECONDS = 86400
CASE_TRACE_IDS_KEPT = 20


def network_of(host: str) -> str | None:
    """/24 (IPv4) o /64 (IPv6) de una IP; None si no es una IP."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def _is_public(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def open_case(
    kind: str, host: str, detail: dict, rdb: redis.Redis,
    ttl: int = CASE_TTL_SECONDS, dedup_window: int = CASE_DEDUP_WINDOW_SECONDS,
) -> dict:
    """Abre un caso automático, o suma la ocurrencia al caso abierto de la
    misma IP pública dentro de la ventana de dedup.

    Args:
        kind: tipo de hallazgo, ej. "network_t2_unconfirmed".
        host: origen del hallazgo (acá, típicamente la IP de origen del flujo).
        detail: contexto libre (score, fuentes de corroboración, etc.)
        rdb: cliente Redis ya conectado (worker.py ya mantiene uno).
        ttl: segundos de vida del caso automático desde su última ocurrencia.
        dedup_window: segundos durante los que una IP pública reutiliza su caso.

    Returns:
        El caso (nuevo o el existente actualizado), con su case_id y
        `deduplicated` en True si se reutilizó.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    now = time.time()
    trace_id = detail.get("trace_id")
    dedup_key = f"{CASE_DEDUP_PREFIX}{host}" if _is_public(host) else None
    case_id = str(uuid.uuid4())
    try:
        if dedup_key is not None and not rdb.set(dedup_key, case_id, nx=True, ex=dedup_window):
            existing = _add_occurrence(rdb, rdb.get(dedup_key), trace_id, now_iso, now, ttl)
            if existing is not None:
                return existing
            rdb.set(dedup_key, case_id, ex=dedup_window)  # el caso previo expiró o lo tomó un analista
        case = {
            "case_id": case_id,
            "kind": kind,
            "host": host,
            "net24": network_of(host),
            "detail": detail,
            "state": "abierto",
            "opened_at": now_iso,
            "updated_at": now_iso,
            "last_seen": now_iso,
            "occurrences": 1,
            "trace_ids": [trace_id] if trace_id else [],
            "history": [{"state": "abierto", "at": now_iso, "note": "Caso creado automáticamente (R1, tier T2)"}],
        }
        rdb.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case), ex=ttl)
        rdb.sadd(CASES_INDEX_KEY, case_id)
        _touch_recent(rdb, case_id, now, ttl)
        return case
    except redis.RedisError as e:
        log.error(f"no se pudo abrir caso automatico para {host}: {e}")
        return {"case_id": case_id, "kind": kind, "host": host, "detail": detail, "state": "abierto"}


def _add_occurrence(
    rdb: redis.Redis, case_id: str | None, trace_id: str | None, now_iso: str, now: float, ttl: int,
) -> dict | None:
    """Suma una ocurrencia al caso abierto y extiende su TTL. None si el caso
    ya no existe o un analista lo movió de "abierto" (se abre uno nuevo)."""
    if not case_id:
        return None
    raw = rdb.get(f"{CASES_KEY_PREFIX}{case_id}")
    if not raw:
        return None
    case = json.loads(raw)
    if case.get("state") != "abierto":
        return None
    case["occurrences"] = int(case.get("occurrences", 1)) + 1
    case["last_seen"] = now_iso
    if trace_id:
        case["trace_ids"] = (case.get("trace_ids", []) + [trace_id])[-CASE_TRACE_IDS_KEPT:]
    rdb.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case), ex=ttl)
    _touch_recent(rdb, case_id, now, ttl)
    case["deduplicated"] = True
    return case


def _touch_recent(rdb: redis.Redis, case_id: str, now: float, ttl: int) -> None:
    """Índice acotado por última actividad: lo que expiró sale del ZSET."""
    rdb.zadd(CASES_RECENT_KEY, {case_id: now})
    rdb.zremrangebyscore(CASES_RECENT_KEY, "-inf", now - ttl)
