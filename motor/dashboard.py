"""
dashboard.py — Endpoints de solo lectura para el dashboard de monitoreo del motor.

Lee datos ya existentes en OpenSearch (decisiones, tiers, latencia) y Redis
(bloqueos activos de R2, auditoría R1/R2). No escribe ni modifica nada — es
una capa de lectura pura sobre el estado real del sistema. Tesis UBO.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import redis

from response.config import get_settings

log = logging.getLogger("motor.dashboard")

# ── OpenSearch (mismo patrón que opensearch_indexer.py) ─────────────────────
OS_HOST  = os.environ.get("OS_HOST", "https://localhost:9201")
OS_USER  = os.environ.get("OS_USER", "admin")
OS_PASS  = os.environ.get("OS_PASS", "")
OS_INDEX = "soc-decisions"

RESPONSE_AUDIT_STREAM = "soc:response:audit"

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _os_request(method: str, path: str, body: dict | None = None) -> dict | None:
    url = f"{OS_HOST}{path}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode(),
    }
    data = json.dumps(body).encode() if body is not None else None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Esquema de URL no permitido: {parsed.scheme!r}")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=5) as r:  # nosec B310 - esquema validado arriba (solo http/https)
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        log.error(f"OpenSearch HTTP error en {path}: {e.read()}")
        return None
    except Exception as e:
        log.error(f"OpenSearch error en {path}: {e}")
        return None


_redis_client: "redis.Redis | None" = None


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        s = get_settings()
        _redis_client = redis.Redis(
            host=s.redis_host, port=s.redis_port, password=s.redis_password,
            decode_responses=True, socket_timeout=3, socket_connect_timeout=3,
        )
    return _redis_client


# ── Estadísticas agregadas ────────────────────────────────────────────────
def get_stats(window_minutes: int = 60) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    query = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {
            "por_tier":     {"terms": {"field": "tier_name", "size": 10}},
            "por_decision": {"terms": {"field": "decision", "size": 10}},
            "latencia_avg": {"avg": {"field": "latency_ms"}},
            "latencia_p95": {"percentiles": {"field": "latency_ms", "percents": [95]}},
        },
    }
    result = _os_request("POST", f"/{OS_INDEX}/_search", query)
    if result is None:
        return {"available": False, "window_minutes": window_minutes}

    total = result["hits"]["total"]["value"]
    aggs = result.get("aggregations", {})
    por_tier     = {b["key"]: b["doc_count"] for b in aggs.get("por_tier", {}).get("buckets", [])}
    por_decision = {b["key"]: b["doc_count"] for b in aggs.get("por_decision", {}).get("buckets", [])}
    avg_lat = aggs.get("latencia_avg", {}).get("value")
    p95_lat = aggs.get("latencia_p95", {}).get("values", {}).get("95.0")

    return {
        "available": True,
        "window_minutes": window_minutes,
        "total_decisiones": total,
        "por_tier": por_tier,
        "por_decision": por_decision,
        "latencia_avg_ms": round(avg_lat, 2) if avg_lat is not None else None,
        "latencia_p95_ms": round(p95_lat, 2) if p95_lat is not None else None,
    }


# ── Últimas decisiones ──────────────────────────────────────────────────────
def get_recent_decisions(limit: int = 50) -> list[dict]:
    query = {"size": limit, "sort": [{"timestamp": {"order": "desc"}}]}
    result = _os_request("POST", f"/{OS_INDEX}/_search", query)
    if result is None:
        return []
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


# ── Bloqueos activos (R2, con TTL restante) ──────────────────────────────────
def get_active_blocks() -> list[dict]:
    s = get_settings()
    r = _get_redis()
    prefix = s.blocks_key_prefix
    blocks = []
    try:
        for key in r.scan_iter(match=f"{prefix}*", count=100):
            ip = key[len(prefix):]
            ttl = r.ttl(key)
            trace_id = r.get(key)
            if ttl is not None and ttl >= 0:
                blocks.append({"ip": ip, "ttl_seconds": ttl, "trace_id": trace_id})
    except redis.RedisError as e:
        log.error(f"error escaneando bloqueos activos: {e}")
    blocks.sort(key=lambda b: b["ttl_seconds"])
    return blocks


# ── Últimas respuestas R1/R2 (auditoría) ─────────────────────────────────────
def get_recent_responses(limit: int = 50) -> list[dict]:
    r = _get_redis()
    records = []
    try:
        for _msg_id, fields in r.xrevrange(RESPONSE_AUDIT_STREAM, count=limit):
            try:
                records.append(json.loads(fields.get("data", "{}")))
            except json.JSONDecodeError:
                continue
    except redis.RedisError as e:
        log.error(f"error leyendo auditoría de respuestas: {e}")
    return records
