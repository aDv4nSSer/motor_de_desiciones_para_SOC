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
import urllib.request
from datetime import datetime, timedelta, timezone

import redis
from dotenv import load_dotenv

from response.config import get_settings

load_dotenv()

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


# ── Categorización de puertos (verificado 2026-07-07, ver bitácora) ────────
INFRA_PORTS = {2222, 8000, 55000, 443}
HONEYPOT_PORTS = {22}

PORT_NAMES = {
    0: "ICMP (ping/traceroute)",
    2222: "SSH admin", 8000: "Motor FastAPI", 55000: "Wazuh API", 443: "Wazuh Dashboard",
    22: "SSH (honeypot)", 23: "Telnet", 3389: "RDP", 1433: "SQL Server", 5060: "SIP",
    8728: "MikroTik API", 88: "Kerberos", 53: "DNS", 67: "DHCP", 123: "NTP",
    80: "HTTP", 8080: "HTTP-alt", 8081: "HTTP-alt", 8443: "HTTPS-alt", 81: "HTTP-alt",
}


def classify_port(port: int) -> str:
    """infra (propio) | honeypot (Cowrie) | external (ataque real probable)."""
    if port in INFRA_PORTS:
        return "infra"
    if port in HONEYPOT_PORTS:
        return "honeypot"
    return "external"


def get_port_stats(window_minutes: int = 60, top_n: int = 15) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    query = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {
            "puertos": {
                "terms": {"field": "L4_DST_PORT", "size": top_n},
                "aggs": {"por_tier": {"terms": {"field": "tier_name", "size": 10}}},
            }
        },
    }
    result = _os_request("POST", f"/{OS_INDEX}/_search", query)
    if result is None:
        return []
    buckets = result.get("aggregations", {}).get("puertos", {}).get("buckets", [])
    out = []
    for b in buckets:
        port = b["key"]
        por_tier = {tb["key"]: tb["doc_count"] for tb in b.get("por_tier", {}).get("buckets", [])}
        out.append({
            "port": port,
            "name": PORT_NAMES.get(port, "Desconocido"),
            "category": classify_port(port),
            "count": b["doc_count"],
            "por_tier": por_tier,
        })
    return out


# ── Precisión corroborada (metodología: .claude/skills/soc-audit/SKILL.md) ──
ABUSEIPDB_HIGH_SCORE_THRESHOLD = 40  # score >= 40 AbuseIPDB = corroboración real (ver H3, BITACORA_TECNICA.md)
PRECISION_SCAN_LIMIT = 60_000        # tope de entradas de soc:response:audit a inspeccionar por consulta
                                      # (margen ~1.6x sobre 24h de tráfico real medido el 2026-08-12, ~1559/h)


def get_precision_stats(window_minutes: int = 60) -> dict:
    """Precisión de bloqueos R2 corroborada externamente por AbuseIPDB.

    Separa siempre decisiones con corroboración disponible de las que no la
    tienen (cuota de API u otro fallo) — nunca se mezclan en una sola cifra
    de precisión, siguiendo la metodología de auditoría del proyecto.

    Args:
        window_minutes: ventana de tiempo hacia atrás desde ahora.

    Returns:
        dict con total de bloqueos, desglose corroborado/sin-corroborar y
        el % de corroborados con score alto. `available=False` si Redis falla.
    """
    since_ts = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).timestamp()

    r = _get_redis()
    try:
        entries = r.xrevrange(RESPONSE_AUDIT_STREAM, count=PRECISION_SCAN_LIMIT)
    except redis.RedisError as e:
        log.error(f"error leyendo auditoría de respuestas para precisión: {e}")
        return {"available": False, "window_minutes": window_minutes}

    corroborated_total = 0
    corroborated_high = 0
    uncorroborated_total = 0

    for _msg_id, fields in entries:
        try:
            record = json.loads(fields.get("data", "{}"))
        except json.JSONDecodeError:
            continue

        if record.get("processed_at", 0.0) < since_ts:
            break  # xrevrange es descendente en el tiempo — el resto es aún más viejo

        block = record.get("block") or {}
        if block.get("action") != "block":
            continue

        enrichment = record.get("enrichment") or {}
        if enrichment.get("abuseipdb_available"):
            corroborated_total += 1
            score = enrichment.get("abuseipdb_score")
            if score is not None and score >= ABUSEIPDB_HIGH_SCORE_THRESHOLD:
                corroborated_high += 1
        else:
            uncorroborated_total += 1

    precision_pct = (
        round(100 * corroborated_high / corroborated_total, 1)
        if corroborated_total > 0 else None
    )

    return {
        "available": True,
        "window_minutes": window_minutes,
        "total_blocks": corroborated_total + uncorroborated_total,
        "corroborated": {
            "count": corroborated_total,
            "high_score_count": corroborated_high,
            "precision_pct": precision_pct,
            "threshold": ABUSEIPDB_HIGH_SCORE_THRESHOLD,
        },
        "uncorroborated": {
            "count": uncorroborated_total,
        },
    }


# ── Salud del vigilante FIM (heartbeat, ver vigilante/cases.py:write_heartbeat) ─
WATCHER_HEARTBEAT_KEY = "soc:watcher:heartbeat"
HEARTBEAT_GREEN_MAX_MINUTES = 15
HEARTBEAT_YELLOW_MAX_MINUTES = 60


def get_watcher_heartbeat() -> dict:
    """Estado del último heartbeat del vigilante FIM (motor-watcher.service en .139).

    Returns:
        dict con `status` (green/yellow/red), `age_minutes` y `last_seen` ISO.
        `status="red"` si la key no existe, el formato es inválido, o Redis falla.
    """
    r = _get_redis()
    try:
        raw = r.get(WATCHER_HEARTBEAT_KEY)
    except redis.RedisError as e:
        log.error(f"error leyendo heartbeat del vigilante: {e}")
        return {"available": False, "status": "red", "age_minutes": None, "last_seen": None}

    if raw is None:
        return {"available": True, "status": "red", "age_minutes": None, "last_seen": None}

    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        log.error(f"heartbeat con formato inválido en redis: {raw!r}")
        return {"available": True, "status": "red", "age_minutes": None, "last_seen": None}

    age_minutes = (datetime.now(timezone.utc) - last).total_seconds() / 60
    if age_minutes < HEARTBEAT_GREEN_MAX_MINUTES:
        status = "green"
    elif age_minutes < HEARTBEAT_YELLOW_MAX_MINUTES:
        status = "yellow"
    else:
        status = "red"

    return {
        "available": True,
        "status": status,
        "age_minutes": round(age_minutes, 1),
        "last_seen": raw,
    }


# ── Detección experimental L7 + DNS/DGA (modo observación pura) ────────────
# Ver vigilante/shadow_detect.py -- nunca conectado a R1/R2 ni a soc-decisions.
EXPERIMENTAL_INDEX = "soc-experimental-detections"


def get_experimental_detections(limit: int = 20) -> dict:
    """Hallazgos experimentales en modo observación pura (L7 + DNS/DGA).

    Lee soc-experimental-detections -- índice separado, sin relación con
    R1/R2 ni con el pipeline de decisión real. Las dos fuentes (l7_shadow,
    dga_shadow) se devuelven en listas separadas, nunca mezcladas.

    Args:
        limit: máximo de hallazgos a devolver por fuente.

    Returns:
        dict con `available`, `l7` (lista) y `dns_dga` (lista).
        `available=False` si OpenSearch no responde para alguna de las dos.
    """
    def _search(source: str) -> list[dict] | None:
        query = {
            "size": limit,
            "sort": [{"detected_at": {"order": "desc"}}],
            "query": {"term": {"source.keyword": source}},
        }
        result = _os_request("POST", f"/{EXPERIMENTAL_INDEX}/_search", query)
        if result is None:
            return None
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]

    l7 = _search("l7_shadow")
    dns_dga = _search("dga_shadow")

    if l7 is None or dns_dga is None:
        return {"available": False}

    return {"available": True, "l7": l7, "dns_dga": dns_dga}


# ── Gestion de casos (escritos por el vigilante en .139) ──────────────────
CASES_KEY_PREFIX = "soc:cases:"
CASES_INDEX_KEY = "soc:cases:index"
VALID_CASE_STATES = {"abierto", "en_investigacion", "cerrado_confirmado", "cerrado_falso_positivo"}


def list_cases(only_open: bool = False, limit: int = 50) -> list[dict]:
    try:
        r = _get_redis()
        ids = r.smembers(CASES_INDEX_KEY)
    except Exception as e:
        logging.error(f"no se pudo leer casos de Redis: {e}")
        return []

    cases = []
    for cid in ids:
        try:
            raw = r.get(f"{CASES_KEY_PREFIX}{cid}")
            if not raw:
                continue
            case = json.loads(raw)
            if only_open and case.get("state") not in ("abierto", "en_investigacion"):
                continue
            cases.append(case)
        except Exception:
            continue

    cases.sort(key=lambda c: c.get("opened_at", ""), reverse=True)
    return cases[:limit]


def update_case_state(case_id: str, new_state: str, note: str, actor: str) -> dict | None:
    if new_state not in VALID_CASE_STATES:
        raise ValueError(f"Estado invalido: {new_state}")

    r = _get_redis()
    raw = r.get(f"{CASES_KEY_PREFIX}{case_id}")
    if raw is None:
        return None

    case = json.loads(raw)
    now = datetime.now(timezone.utc).isoformat()
    case["state"] = new_state
    case["updated_at"] = now
    case.setdefault("history", []).append({
        "state": new_state,
        "at": now,
        "note": note,
        "actor": actor,
    })
    r.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case))
    logging.info(f"caso {case_id} -> {new_state} por {actor}")
    return case
