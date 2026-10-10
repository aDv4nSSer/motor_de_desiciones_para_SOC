"""
dashboard.py — Endpoints de solo lectura para el dashboard de monitoreo del motor.

Lee datos ya existentes en OpenSearch (decisiones, tiers, latencia) y Redis
(bloqueos activos de R2, auditoría R1/R2). No escribe ni modifica nada — es
una capa de lectura pura sobre el estado real del sistema. Tesis UBO.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import ssl
import time
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
# Índice legado (cadena vieja, hasta el corte de H42) + índices diarios de la
# cadena nueva. Mismo mapping de campos: búsquedas y agregaciones abarcan ambos.
OS_INDEX = "soc-decisions,soc-decisions-*"

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
        # Sin esto OpenSearch topea hits.total en 10.000 y total_decisiones
        # (denominador de fatiga_alertas_pct) queda falso: 4277,6% en 24 h (H46).
        "track_total_hits": True,
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
DECISIONS_MAX_LIMIT = 200  # tope por página: ~150k T2+/día hacen inmanejable un listado sin límite


def get_recent_decisions(
    limit: int = 50, tier_min: int = 0, before: datetime | None = None,
) -> list[dict]:
    """Últimas decisiones de soc-decisions, más recientes primero.

    Args:
        limit: tamaño de página (se acota a DECISIONS_MAX_LIMIT).
        tier_min: solo decisiones con tier >= tier_min (2 = vista de alertas T2+).
        before: cursor de paginación — solo decisiones con timestamp
            estrictamente anterior (se pasa el timestamp del último ítem de la
            página previa). Sin cursor, la página más reciente.

    Returns:
        Lista de documentos (_source); [] si OpenSearch no responde.
    """
    filters: list[dict] = []
    if tier_min > 0:
        filters.append({"range": {"tier": {"gte": tier_min}}})
    if before is not None:
        filters.append({"range": {"timestamp": {"lt": before.isoformat()}}})
    query = {
        "size": min(limit, DECISIONS_MAX_LIMIT),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
    }
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


# ── Respuestas R1/R2 por trace_id (vista de alertas, H49) ───────────────────
# La vista cruzaba sus 50 decisiones con las últimas 200 entradas del stream
# (~25 s de tráfico): fuera de esa ventana no encontraba nada aunque el registro
# existiera. Ahora se busca exactamente por los trace_id de la página.
RESPONSES_INDEX = "soc-responses-*"
RESPONSE_AUDIT_INDEXER_GROUP = "response-audit-indexer"
RESPONSE_LOOKUP_MAX_IDS = 100
# Cola del stream que se revisa siempre, además de lo que el indexador aún no
# persistió: cubre el refresh de OpenSearch (~1 s) después del XACK.
RESPONSE_TAIL_MARGIN = 500
# Tope de la cola: si el atraso del indexador lo supera, un trace_id ausente
# ya no prueba que no haya registro (complete=False).
RESPONSE_TAIL_MAX = 20_000


def _is_response_record(rec: dict) -> bool:
    """Entrada R1/R2 del worker (mismo criterio que el indexador): descarta
    accesos, aprobaciones manuales y expiraciones."""
    return (bool(rec.get("trace_id")) and not rec.get("access_event")
            and not rec.get("manual_approval") and not rec.get("approval_expired")
            and ("accion_recomendada" in rec or "enrichment" in rec))


def _group_info(r: redis.Redis, stream: str, group: str) -> dict | None:
    for g in r.xinfo_groups(stream):
        if g.get("name") == group:
            return g
    return None


def _stream_id_iso(msg_id: str | None) -> str | None:
    if not msg_id or msg_id == "0-0":
        return None
    ms = int(msg_id.split("-")[0])
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def lookup_responses(trace_ids: list[str]) -> dict:
    """Registros R1/R2 de trace_id concretos.

    Busca en soc-responses-* (consulta `terms`, el historial persistido) y,
    para lo que no esté, en la cola de soc:response:audit que el indexador aún
    no persistió. Además informa hasta dónde llegó el response-worker, para que
    la vista distinga "en proceso" de "sin registro".

    Args:
        trace_ids: ids a resolver (se acota a RESPONSE_LOOKUP_MAX_IDS).

    Returns:
        {"responses": {trace_id: registro}, "complete": bool,
         "sources": {"opensearch": bool, "redis": bool},
         "worker_frontier": ISO de la última tarea entregada al worker | None}.
        complete=True garantiza que un trace_id ausente no tiene registro;
        False si alguna fuente falló o el atraso del indexador excede la cola
        revisada (entonces la vista no debe afirmar que falta).
    """
    wanted = list(dict.fromkeys(trace_ids))[:RESPONSE_LOOKUP_MAX_IDS]
    found: dict[str, dict] = {}
    sources = {"opensearch": True, "redis": True}
    complete = True

    result = _os_request("POST", f"/{RESPONSES_INDEX}/_search", {
        "size": len(wanted) * 2,
        "_source": ["payload"],
        "query": {"bool": {"filter": [
            {"terms": {"trace_id": wanted}},
            {"term": {"event_type": "response"}},
        ]}},
    })
    if result is None:
        sources["opensearch"] = False
        complete = False
    else:
        for h in result.get("hits", {}).get("hits", []):
            rec = h.get("_source", {}).get("payload") or {}
            if _is_response_record(rec) and rec["trace_id"] in wanted:
                found.setdefault(rec["trace_id"], rec)

    worker_frontier = None
    r = _get_redis()
    missing = {t for t in wanted if t not in found}
    try:
        if missing:
            indexer = _group_info(r, RESPONSE_AUDIT_STREAM, RESPONSE_AUDIT_INDEXER_GROUP)
            lag = indexer.get("lag") if indexer else None
            if lag is None:  # sin grupo o lag desconocido: no se sabe qué falta persistir
                tail, covered = RESPONSE_TAIL_MAX, False
            else:
                backlog = lag + (indexer.get("pending") or 0)
                tail = min(backlog + RESPONSE_TAIL_MARGIN, RESPONSE_TAIL_MAX)
                covered = backlog + RESPONSE_TAIL_MARGIN <= RESPONSE_TAIL_MAX
            for _msg_id, fields in r.xrevrange(RESPONSE_AUDIT_STREAM, count=tail):
                try:
                    rec = json.loads(fields.get("data", "{}"))
                except json.JSONDecodeError:
                    continue
                if _is_response_record(rec) and rec["trace_id"] in missing:
                    found[rec["trace_id"]] = rec
                    missing.discard(rec["trace_id"])
                    if not missing:
                        break
            if missing and not covered:
                complete = False
        s = get_settings()
        worker = _group_info(r, s.response_stream, s.response_group)
        worker_frontier = _stream_id_iso(worker.get("last-delivered-id") if worker else None)
    except redis.RedisError as e:
        log.error(f"error resolviendo respuestas por trace_id: {e}")
        sources["redis"] = False
        if missing:
            complete = False

    return {"responses": found, "complete": complete, "sources": sources,
            "worker_frontier": worker_frontier}


# ── Categorización de puertos (verificado 2026-07-07, ver bitácora) ────────
INFRA_PORTS = {2222, 8000, 55000, 443}
# Cowrie escucha en 2223: el REDIRECT 22 -> 2223 de .139 (H34) ocurre antes de
# NFQUEUE, así que Suricata (y el motor) ven el puerto 2223. El 22 queda por
# los pocos flows que llegan sin redirigir (H56).
HONEYPOT_PORTS = {22, 2223}

PORT_NAMES = {
    0: "ICMP (ping/traceroute)",
    2222: "SSH admin", 8000: "Motor FastAPI", 55000: "Wazuh API", 443: "Wazuh Dashboard",
    22: "SSH (honeypot)", 2223: "SSH (honeypot Cowrie)", 23: "Telnet", 3389: "RDP", 1433: "SQL Server", 5060: "SIP",
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


CASES_RECENT_KEY = "soc:cases:recent"
CASES_LIST_SCAN_MAX = 2000   # tope de casos leídos por listado (lotes de MGET)
CASES_LIST_BATCH = 200


def list_cases(only_open: bool = False, limit: int = 50) -> list[dict]:
    """Casos más recientes por última actividad, desde el índice acotado
    `soc:cases:recent` (H57). Antes se hacía SMEMBERS de soc:cases:index
    (~550.000 ids) y un GET por caso dentro del proceso del Fast Path: el
    mismo patrón de lectura masiva que causó el incidente de H54. Ahora lee a
    lo sumo CASES_LIST_SCAN_MAX casos, en lotes de MGET. Los casos anteriores
    a H57 no están en el índice nuevo y expiran con la migración de H57."""
    try:
        r = _get_redis()
    except Exception as e:
        logging.error(f"no se pudo leer casos de Redis: {e}")
        return []

    cases: list[dict] = []
    for start in range(0, CASES_LIST_SCAN_MAX, CASES_LIST_BATCH):
        try:
            ids = r.zrevrange(CASES_RECENT_KEY, start, start + CASES_LIST_BATCH - 1)
            if not ids:
                break
            raws = r.mget([f"{CASES_KEY_PREFIX}{cid}" for cid in ids])
        except Exception as e:
            logging.error(f"no se pudo leer casos de Redis: {e}")
            break
        for raw in raws:
            if not raw:
                continue
            try:
                case = json.loads(raw)
            except ValueError:
                continue
            if only_open and case.get("state") not in ("abierto", "en_investigacion"):
                continue
            cases.append(case)
            if len(cases) >= limit:
                return cases
    return cases


# ── Casos trabajados por un analista (H60) ──────────────────────────────────
# soc:cases:recent ordena por última ocurrencia; un caso que un analista movió
# ya no suma ocurrencias (la recurrencia abre otro caso), así que se hunde y
# con ~500 casos/h sale de la ventana de CASES_LIST_SCAN_MAX en unas 4 h.
# Este ZSET guarda solo los casos tocados por un analista, por hora del último
# cambio, con tope duro: lo que pase de CASES_WORKED_MAX se recorta por rango
# (el caso en sí sigue en Redis sin TTL, como antes; solo sale del listado).
CASES_WORKED_KEY = "soc:cases:worked"
CASES_WORKED_MAX = 5000
CASES_PAGE_MAX_LIMIT = 200
CLOSED_CASE_STATES = frozenset({"cerrado_confirmado", "cerrado_falso_positivo"})
WORKED_CASE_STATES = CLOSED_CASE_STATES | {"en_investigacion"}

# Transiciones permitidas y rol mínimo por estado destino (sección 5 de la
# especificación: N1 investiga, N2 y CISO cierran). Los cerrados son finales.
CASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "abierto": frozenset({"en_investigacion", "cerrado_confirmado", "cerrado_falso_positivo"}),
    "en_investigacion": frozenset({"cerrado_confirmado", "cerrado_falso_positivo"}),
}
CASE_TARGET_MIN_ROLE: dict[str, str] = {
    "en_investigacion": "N1",
    "cerrado_confirmado": "N2",
    "cerrado_falso_positivo": "N2",
}


class CaseTransitionError(Exception):
    """Transición de estado no permitida desde el estado actual del caso."""


def _is_public_host(host: str | None) -> bool:
    try:
        return bool(host) and ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def list_cases_page(
    state: str | None = None, public_only: bool = True, since_hours: int | None = None,
    cursor: int = 0, limit: int = 50, now: float | None = None,
) -> dict:
    """Página de casos con filtros, leída de un índice acotado (H60).

    Los casos en investigación o cerrados se leen de soc:cases:worked; el resto
    de soc:cases:recent. Cada pedido lee a lo sumo CASES_LIST_SCAN_MAX ids, en
    lotes de MGET de CASES_LIST_BATCH: nunca el índice completo (H54).

    Args:
        state: filtra por estado; None = todos los del índice reciente.
        public_only: excluye IPs privadas, de infra propia y hosts no IP.
        since_hours: solo casos con actividad en las últimas N horas.
        cursor: posición en el índice desde donde seguir (next_cursor previo).
        limit: casos por página (1 a CASES_PAGE_MAX_LIMIT).
        now: epoch de referencia (tests).

    Returns:
        {"items", "next_cursor" (None si no hay más), "scanned", "source",
         "index_size", "scan_cap_reached", "available"}.
    """
    limit = max(1, min(limit, CASES_PAGE_MAX_LIMIT))
    worked = state in WORKED_CASE_STATES
    key = CASES_WORKED_KEY if worked else CASES_RECENT_KEY
    out: dict = {"items": [], "next_cursor": None, "scanned": 0, "source": "worked" if worked else "recent",
                 "index_size": None, "scan_cap_reached": False, "available": True}
    try:
        r = _get_redis()
        out["index_size"] = r.zcard(key)
    except Exception as e:
        logging.error(f"no se pudo leer casos de Redis: {e}")
        return {**out, "available": False}

    min_score: float | str = "-inf"
    if since_hours:
        min_score = (now if now is not None else time.time()) - since_hours * 3600
    pos = cursor
    while out["scanned"] < CASES_LIST_SCAN_MAX:
        batch = min(CASES_LIST_BATCH, CASES_LIST_SCAN_MAX - out["scanned"])
        try:
            ids = r.zrevrangebyscore(key, "+inf", min_score, start=pos, num=batch)
            if not ids:
                return out
            raws = r.mget([f"{CASES_KEY_PREFIX}{cid}" for cid in ids])
        except Exception as e:
            logging.error(f"no se pudo leer casos de Redis: {e}")
            return {**out, "available": False}
        for raw in raws:
            pos += 1
            out["scanned"] += 1
            if not raw:
                continue
            try:
                case = json.loads(raw)
            except ValueError:
                continue
            if state and case.get("state") != state:
                continue
            if public_only and not _is_public_host(case.get("host")):
                continue
            out["items"].append(case)
            if len(out["items"]) >= limit:
                out["next_cursor"] = pos
                return out
        if len(ids) < batch:
            return out
    out["next_cursor"] = pos
    out["scan_cap_reached"] = True
    return out


def get_case(case_id: str) -> dict | None:
    """Un caso por id (GET O(1)); None si no existe o expiró."""
    raw = _get_redis().get(f"{CASES_KEY_PREFIX}{case_id}")
    return json.loads(raw) if raw else None


def closed_cases_rows() -> list[dict]:
    """Cierres registrados en soc:cases:worked (a lo sumo CASES_WORKED_MAX),
    para la exportación CSV de solo lectura. Hora y actor salen del último
    evento del historial con el estado de cierre."""
    r = _get_redis()
    rows: list[dict] = []
    for start in range(0, CASES_WORKED_MAX, CASES_LIST_BATCH):
        ids = r.zrevrange(CASES_WORKED_KEY, start, start + CASES_LIST_BATCH - 1)
        if not ids:
            break
        for raw in r.mget([f"{CASES_KEY_PREFIX}{cid}" for cid in ids]):
            if not raw:
                continue
            try:
                case = json.loads(raw)
            except ValueError:
                continue
            if case.get("state") not in CLOSED_CASE_STATES:
                continue
            closing = next((h for h in reversed(case.get("history") or [])
                            if h.get("state") == case["state"]), {})
            rows.append({
                "case_id": case.get("case_id", ""), "ip": case.get("host", ""),
                "net24": case.get("net24") or "", "estado": case["state"],
                "hora": closing.get("at", case.get("updated_at", "")), "actor": closing.get("actor", ""),
                "trace_id": (case.get("detail") or {}).get("trace_id", ""),
            })
    return rows


def update_case_state(case_id: str, new_state: str, note: str, actor: str) -> dict | None:
    """Cambia el estado de un caso y lo deja en soc:cases:worked.

    No valida rol: lo hace el endpoint (CASE_TARGET_MIN_ROLE) antes de leer.
    No entra a la cadena hash de auditoría (limitación declarada en H60).

    Args:
        case_id: id del caso.
        new_state: estado destino.
        note: nota del analista (el endpoint exige nota al cerrar).
        actor: usuario que hace el cambio.

    Returns:
        El caso actualizado, o None si no existe.

    Raises:
        ValueError: estado desconocido.
        CaseTransitionError: transición no permitida desde el estado actual.
    """
    if new_state not in VALID_CASE_STATES:
        raise ValueError(f"Estado invalido: {new_state}")

    r = _get_redis()
    raw = r.get(f"{CASES_KEY_PREFIX}{case_id}")
    if raw is None:
        return None

    case = json.loads(raw)
    current = case.get("state", "abierto")
    if new_state not in CASE_TRANSITIONS.get(current, frozenset()):
        raise CaseTransitionError(f"No se puede pasar de {current} a {new_state}")
    now_ts = time.time()
    now = datetime.fromtimestamp(now_ts, timezone.utc).isoformat()
    case["state"] = new_state
    case["updated_at"] = now
    case.setdefault("history", []).append({
        "state": new_state,
        "at": now,
        "note": note,
        "actor": actor,
    })
    # SET sin TTL a propósito (H57): un caso que un analista tocó es evidencia
    # y deja de expirar, aunque haya nacido como caso automático con TTL.
    r.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case))
    r.zadd(CASES_WORKED_KEY, {case_id: now_ts})
    r.zremrangebyrank(CASES_WORKED_KEY, 0, -(CASES_WORKED_MAX + 1))  # tope duro
    logging.info(f"caso {case_id} -> {new_state} por {actor}")
    return case
