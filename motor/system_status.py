"""
system_status.py — Estado de nodos y servicios para el dashboard (H43).

Reemplaza "mirar Grafana aparte" con señales reales que el motor ya puede
leer, sin agregar agentes ni exporters:

- motor-soc (este proceso): modelo cargado y versión (mismo dato que /health).
- Redis: PING con latencia + INFO (memoria, clientes).
- OpenSearch: _cluster/health con latencia (green/yellow/red, shards sin asignar).
- Pipelines: los procesos sin HTTP (opensearch-indexer, response-worker,
  response-audit-indexer) se ven por su consumer group en Redis: lag,
  pendientes y antigüedad del último evento del stream. Es la misma señal
  que habría delatado H25 (Fast Path sin tráfico) o H38 (worker atrasado).
- Vigilante FIM en .139: heartbeat existente (dashboard.get_watcher_heartbeat).
- Wazuh: agentes vía la API del manager con un usuario propio de SOLO
  LECTURA (WAZUH_NODES_USER, rol agents_readonly), nunca con la credencial
  del enforcer (WAZUH_API_USER, que puede disparar Active Response).

Ningún servicio del repo expone /metrics Prometheus todavía (pendiente de
.claude/rules/observability.md): esta vista no lo simula.

Degradación con gracia: cada chequeo es independiente; uno caído queda
"down"/"unknown" con su motivo y el resto se informa igual.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
import redis
from dashboard import _get_redis, _os_request, get_watcher_heartbeat
from response.config import get_settings

log = logging.getLogger("motor.system_status")

Status = Literal["ok", "degraded", "down", "unknown", "not_configured"]

#: (stream, consumer group, servicio, host, descripción)
PIPELINES: tuple[tuple[str, str, str, str, str], ...] = (
    ("soc:decisions", "opensearch-indexer", "opensearch-indexer", ".140",
     "Persiste decisiones del Fast Path en soc-decisions-* (hash-chain)"),
    ("soc:response:tasks", "response-workers", "response-worker", ".140",
     "R1/R2: enriquecimiento, acción recomendada, bloqueo"),
    ("soc:response:audit", "response-audit-indexer", "response-audit-indexer", ".140",
     "Persiste la auditoría R1/R2 y accesos en soc-responses-* (hash-chain)"),
)

PIPELINE_LAG_WARN = 1_000        # mensajes sin entregar al grupo
PIPELINE_LAG_DOWN = 50_000
INGEST_IDLE_WARN_SECONDS = 15 * 60   # sin decisiones nuevas en soc:decisions (H25)
REDIS_LATENCY_WARN_MS = 50.0
OPENSEARCH_LATENCY_WARN_MS = 1_000.0
STATUS_CACHE_SECONDS = 10.0      # varios paneles abiertos no multiplican los chequeos
WAZUH_CACHE_SECONDS = 60.0
WAZUH_AGENTS_LIMIT = 100
WAZUH_TIMEOUT = httpx.Timeout(5.0, connect=2.0)


def _component(cid: str, name: str, host: str, status: Status, detail: str,
               latency_ms: float | None = None, metrics: dict | None = None) -> dict[str, Any]:
    return {"id": cid, "name": name, "host": host, "status": status, "detail": detail,
            "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
            "metrics": metrics or {}}


def check_motor() -> dict[str, Any]:
    """Modelo cargado en el proceso del motor (mismo dato que GET /health)."""
    try:
        from model import get_model  # import local: ver main._init_score_worker
        model = get_model()
    except Exception as e:  # noqa: BLE001 — cualquier fallo de carga se informa como "down", no tumba la vista
        log.error(f"estado del modelo no disponible: {e}")
        return _component("motor-soc", "Motor de decisiones (Fast Path)", ".140", "down",
                          f"Modelo no disponible: {type(e).__name__}")
    real = model.lgbm is not None and model.iforest is not None
    return _component(
        "motor-soc", "Motor de decisiones (Fast Path)", ".140", "ok" if real else "degraded",
        f"Modelo {model.model_version}" + ("" if real else ": algún modelo no cargó (fallback)"),
        metrics={"model_version": model.model_version, "lgbm_loaded": model.lgbm is not None,
                 "iforest_loaded": model.iforest is not None},
    )


def check_redis(rdb: redis.Redis) -> dict[str, Any]:
    """PING con latencia e INFO de memoria/clientes."""
    try:
        t0 = time.perf_counter()
        rdb.ping()
        latency = (time.perf_counter() - t0) * 1000
        info = rdb.info()
    except redis.RedisError as e:
        log.error(f"redis no responde al chequeo de estado: {e}")
        return _component("redis", "Redis (colas, caché, sesiones)", ".140", "down",
                          f"Sin respuesta: {type(e).__name__}")
    status: Status = "ok" if latency < REDIS_LATENCY_WARN_MS else "degraded"
    return _component(
        "redis", "Redis (colas, caché, sesiones)", ".140", status,
        f"PING {latency:.1f} ms", latency,
        metrics={"used_memory_human": info.get("used_memory_human"),
                 "maxmemory_human": info.get("maxmemory_human"),
                 "connected_clients": info.get("connected_clients"),
                 "version": info.get("redis_version")},
    )


def check_opensearch(request: Callable[..., dict | None] = _os_request) -> dict[str, Any]:
    """_cluster/health con latencia. yellow = degradado (réplicas sin asignar)."""
    t0 = time.perf_counter()
    health = request("GET", "/_cluster/health")
    latency = (time.perf_counter() - t0) * 1000
    if health is None:
        return _component("opensearch", "OpenSearch (evidencia y auditoría)", ".140", "down",
                          "Sin respuesta de _cluster/health", latency)
    color = health.get("status", "unknown")
    status: Status = {"green": "ok", "yellow": "degraded", "red": "down"}.get(color, "unknown")
    if status == "ok" and latency > OPENSEARCH_LATENCY_WARN_MS:
        status = "degraded"
    detail = f"Clúster {color}"
    unassigned = health.get("unassigned_shards", 0)
    if unassigned:
        detail += f", {unassigned} shards sin asignar"
    return _component(
        "opensearch", "OpenSearch (evidencia y auditoría)", ".140", status, detail, latency,
        metrics={"cluster_status": color, "nodes": health.get("number_of_nodes"),
                 "active_shards": health.get("active_shards"), "unassigned_shards": unassigned},
    )


def _stream_age_seconds(last_id: str | None, now: float) -> float | None:
    try:
        return max(0.0, now - int(str(last_id).split("-")[0]) / 1000)
    except (TypeError, ValueError):
        return None


def check_pipeline(rdb: redis.Redis, stream: str, group: str, service: str, host: str,
                   description: str, now: float | None = None) -> dict[str, Any]:
    """Estado de un consumidor de stream por su consumer group.

    `lag` = entradas del stream aún no entregadas al grupo (Redis >= 7);
    `pending` = entregadas sin XACK. La antigüedad del último evento del
    stream dice si llega tráfico.
    """
    now = time.time() if now is None else now
    try:
        info = rdb.xinfo_stream(stream)
        groups = rdb.xinfo_groups(stream)
    except redis.ResponseError as e:
        return _component(service, service, host, "down", f"Stream {stream} no existe: {e}")
    except redis.RedisError as e:
        return _component(service, service, host, "unknown", f"Redis no respondió: {type(e).__name__}")
    g = next((x for x in groups if x.get("name") == group), None)
    age = _stream_age_seconds(info.get("last-generated-id"), now)
    metrics = {"stream": stream, "group": group, "length": info.get("length"),
               "last_event_age_s": round(age, 1) if age is not None else None, "description": description}
    if g is None:
        return _component(service, service, host, "down",
                          f"No hay consumer group {group}: nadie consume {stream}", metrics=metrics)
    lag = g.get("lag")
    pending = g.get("pending", 0)
    metrics.update(lag=lag, pending=pending, consumers=g.get("consumers"))
    status: Status = "ok"
    parts = []
    if lag is None:
        parts.append("lag no informado por Redis")
    elif lag >= PIPELINE_LAG_DOWN:
        status = "down"
        parts.append(f"atrasado: {lag:,} sin procesar".replace(",", "."))
    elif lag >= PIPELINE_LAG_WARN:
        status = "degraded"
        parts.append(f"atrasado: {lag:,} sin procesar".replace(",", "."))
    else:
        parts.append(f"al día (lag {lag})")
    if stream == "soc:decisions" and age is not None and age > INGEST_IDLE_WARN_SECONDS:
        status = "degraded" if status == "ok" else status
        parts.append(f"sin decisiones nuevas hace {int(age // 60)} min (¿llega tráfico al Fast Path?)")
    return _component(service, service, host, status, ", ".join(parts), metrics=metrics)


def check_watcher() -> dict[str, Any]:
    """Heartbeat del vigilante FIM (motor-watcher en .139)."""
    hb = get_watcher_heartbeat()
    status: Status = {"green": "ok", "yellow": "degraded", "red": "down"}.get(hb.get("status", ""), "unknown")
    if not hb.get("available", True):
        status = "unknown"
    age = hb.get("age_minutes")
    detail = f"Último heartbeat hace {age} min" if age is not None else "Sin heartbeat registrado"
    return _component("motor-watcher", "Vigilante FIM", ".139", status, detail,
                      metrics={"last_seen": hb.get("last_seen"), "age_minutes": age})


_wazuh_cache: dict[str, Any] = {"at": 0.0, "value": None}
_wazuh_lock = threading.Lock()


def _parse_wazuh_summary(data: dict) -> dict[str, int]:
    # 4.4+: {"connection": {...}, "configuration": {...}}; versiones previas: plano.
    conn = data.get("connection", data)
    return {k: int(conn.get(k, 0) or 0) for k in ("active", "disconnected", "never_connected", "pending", "total")}


def fetch_wazuh_agents(transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    """Agentes Wazuh vía API del manager (GET, solo lectura). Cacheado 60 s.

    Usa WAZUH_NODES_USER/WAZUH_NODES_PASSWORD (rol agents_readonly). Si no
    están, NO cae a la credencial del enforcer: queda "not_configured".

    Returns:
        Componente con resumen por estado y lista de agentes; "not_configured"
        si faltan credenciales, "down" si la API no responde.
    """
    with _wazuh_lock:
        if _wazuh_cache["value"] is not None and time.monotonic() - _wazuh_cache["at"] < WAZUH_CACHE_SECONDS:
            return _wazuh_cache["value"]
    s = get_settings()
    name = "Wazuh Manager (agentes)"
    if not s.wazuh_nodes_user or not s.wazuh_nodes_password:
        value = _component("wazuh", name, ".139", "not_configured",
                           "Sin usuario de solo lectura (WAZUH_NODES_USER) en el .env del motor",
                           metrics={"agents": []})
    else:
        try:
            t0 = time.perf_counter()
            with httpx.Client(base_url=s.wazuh_api_url, verify=s.wazuh_verify_tls,
                              timeout=WAZUH_TIMEOUT, transport=transport) as client:
                auth = client.post("/security/user/authenticate", auth=(s.wazuh_nodes_user, s.wazuh_nodes_password))
                auth.raise_for_status()
                headers = {"Authorization": f"Bearer {auth.json()['data']['token']}"}
                summary = client.get("/agents/summary/status", headers=headers)
                summary.raise_for_status()
                agents = client.get("/agents", headers=headers, params={
                    "select": "id,name,ip,status,version,lastKeepAlive", "limit": WAZUH_AGENTS_LIMIT})
                agents.raise_for_status()
            latency = (time.perf_counter() - t0) * 1000
            counts = _parse_wazuh_summary(summary.json().get("data", {}))
            items = [{
                "id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "status": a.get("status"),
                "version": a.get("version"), "last_keepalive": a.get("lastKeepAlive"),
            } for a in agents.json().get("data", {}).get("affected_items", [])]
            # El agente 000 es el propio manager: siempre "active", no cuenta como agente remoto.
            remote = [a for a in items if a["id"] != "000"]
            down = sum(1 for a in remote if a["status"] != "active")
            status: Status = "ok" if down == 0 else "degraded"
            value = _component(name=name, cid="wazuh", host=".139", status=status,
                               detail=f"{counts['active']} activos de {counts['total']}"
                                      + (f", {down} sin conexión" if down else ""),
                               latency_ms=latency, metrics={**counts, "agents": items})
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.error(f"API de Wazuh no disponible para el estado de agentes: {type(e).__name__}")
            value = _component("wazuh", name, ".139", "down",
                               f"API de Wazuh sin respuesta: {type(e).__name__}", metrics={"agents": []})
    with _wazuh_lock:
        _wazuh_cache.update(at=time.monotonic(), value=value)
    return value


_status_cache: dict[str, Any] = {"at": 0.0, "value": None}
_status_lock = threading.Lock()


def get_node_status(rdb: redis.Redis | None = None, use_cache: bool = True) -> dict[str, Any]:
    """Estado consolidado de todos los componentes.

    Returns:
        {"generated_at", "overall", "components": [...], "metrics_endpoint"}.
        overall = el peor estado entre los componentes configurados.
    """
    with _status_lock:
        if use_cache and _status_cache["value"] is not None \
                and time.monotonic() - _status_cache["at"] < STATUS_CACHE_SECONDS:
            return _status_cache["value"]
    rdb = rdb or _get_redis()
    components = [check_motor(), check_redis(rdb), check_opensearch()]
    components += [check_pipeline(rdb, *p) for p in PIPELINES]
    components += [check_watcher(), fetch_wazuh_agents()]
    rank = {"ok": 0, "not_configured": 0, "unknown": 1, "degraded": 2, "down": 3}
    worst = max(components, key=lambda c: rank[c["status"]])["status"]
    overall = "ok" if worst in ("ok", "not_configured") else worst
    value = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "components": components,
        # Explícito para no aparentar lo que no existe (observability.md lo pide).
        "metrics_endpoint": {"available": False,
                             "detail": "Ningún servicio expone /metrics Prometheus todavía"},
    }
    with _status_lock:
        _status_cache.update(at=time.monotonic(), value=value)
    return value
