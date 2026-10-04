"""
compliance.py — Vista Gerencial/CISO: cumplimiento Ley 21.663 y tendencias (H43).

Llena el stub de GET /api/v1/dashboard/compliance con datos reales y agrega
GET /api/v1/dashboard/trends. Todo sale de lo que el sistema ya registra:

- soc-decisions,soc-decisions-*  -> volumen y tiers en el tiempo, latencia.
- soc-responses-*                -> acciones (ejecutadas, derivadas a
  aprobación, expiradas, rechazadas) y accesos, con hash-chain (H39).
- soc:response:audit (Redis)     -> fuentes de corroboración: el detalle de
  enrichment no está indexado en soc-responses-* (payload con enabled:false),
  así que se cuenta sobre la ventana que conserva el stream, y se informa
  esa cobertura real.
- Redis                          -> cola de aprobaciones, usuarios, sesiones.

El checklist NO declara cumplimiento legal: dice, por obligación, qué
evidencia aporta R-SOAR y qué queda fuera de su alcance (organizacional o
pendiente). Artículos, literales y plazos verificados el 2026-10-04 contra el
texto oficial de la Ley 21.663 en LeyChile/BCN (idNorma 1202434, versión
2024-04-08, sin modificaciones): Art. 7 deberes generales, Art. 8 deberes
específicos de los operadores de importancia vital (literales a-i), Art. 9
deber de reportar (3 h / 72 h o 24 h OIV / 15 días; plan de acción OIV en 7 días).

Exportar a PDF el reporte ANCI queda pendiente (no implementado).

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import audit_view
import redis
import sessions as sess
import users
from dashboard import (
    OS_INDEX,
    RESPONSE_AUDIT_STREAM,
    _get_redis,
    _os_request,
    get_precision_stats,
    get_stats,
)
from response.approvals import pending_approvals_page
from response.config import get_settings

log = logging.getLogger("motor.compliance")

RESPONSES_PATTERN = "soc-responses-*"
ISM_POLICIES = ("soc-decisions-retention", "soc-responses-retention")
TREND_DAYS_ALLOWED = (1, 7, 30)
TREND_TIME_ZONE = "America/Santiago"
CORROBORATION_SCAN_LIMIT = 60_000   # mismo tope que get_precision_stats
TRENDS_CACHE_SECONDS = 60.0

# H25: Fast Path sin ninguna entrada del 2026-08-18 15:13 (-04) al 2026-09-04.
# Esos buckets se marcan "excluded" (sin dato), nunca como "cero ataques".
H25_EXCLUDED_FROM = datetime(2026, 8, 18, 19, 13, tzinfo=timezone.utc)
H25_EXCLUDED_TO = datetime(2026, 9, 5, 3, 0, tzinfo=timezone.utc)  # fin del 04-sep, hora local (-03)

LEGAL_NOTE = ("Artículos, literales y plazos verificados contra el texto oficial de la Ley 21.663 "
              "(LeyChile/BCN, idNorma 1202434, versión del 08-04-2024). El Art. 8 obliga a los "
              "operadores de importancia vital; el Art. 9, a todas las instituciones del Art. 4. "
              "El checklist muestra la evidencia que aporta R-SOAR, no una declaración de "
              "cumplimiento legal.")

OsRequest = Callable[..., "dict | None"]


def _n(value: int) -> str:
    """Entero con separador de miles es-CL (17.911)."""
    return f"{value:,}".replace(",", ".")


# ── Agregaciones de soc-responses-* ──────────────────────────────────────────

ACTION_FILTERS: dict[str, dict] = {
    "ejecutadas_auto": {"bool": {"filter": [{"term": {"event_type": "response"}},
                                            {"term": {"block_enforced": True}}]}},
    "ejecutadas_manual": {"bool": {"filter": [{"term": {"event_type": "manual_approval"}},
                                              {"term": {"block_enforced": True}}]}},
    "derivadas_aprobacion": {"bool": {"filter": [
        {"term": {"event_type": "response"}},
        {"term": {"accion_recomendada": "alertar_pendiente_aprobacion"}}]}},
    "expiradas": {"term": {"event_type": "approval_expired"}},
    "rechazadas": {"bool": {"filter": [{"term": {"event_type": "access"}},
                                       {"term": {"access_event": "approval_rejected"}}]}},
    "casos_abiertos": {"bool": {"filter": [{"term": {"event_type": "response"}},
                                           {"term": {"accion_recomendada": "alertar_crear_caso"}}]}},
}


def response_counts(since: datetime, request: OsRequest = _os_request) -> dict[str, Any]:
    """Totales de acciones y accesos en soc-responses-* desde `since`."""
    body = {
        "size": 0,
        "query": {"range": {"event_time": {"gte": since.isoformat()}}},
        "aggs": {
            "acciones": {"filters": {"filters": ACTION_FILTERS}},
            "accesos": {"filter": {"term": {"event_type": "access"}},
                        "aggs": {"por_evento": {"terms": {"field": "access_event", "size": 30}}}},
            "primero": {"min": {"field": "event_time"}},
        },
    }
    result = request("POST", f"/{RESPONSES_PATTERN}/_search", body)
    if result is None:
        return {"available": False}
    aggs = result.get("aggregations", {})
    buckets = aggs.get("acciones", {}).get("buckets", {})
    acc = aggs.get("accesos", {}).get("por_evento", {}).get("buckets", [])
    return {
        "available": True,
        "total_eventos": result.get("hits", {}).get("total", {}).get("value", 0),
        "acciones": {k: buckets.get(k, {}).get("doc_count", 0) for k in ACTION_FILTERS},
        "accesos": {b["key"]: b["doc_count"] for b in acc},
        "cobertura_desde": aggs.get("primero", {}).get("value_as_string"),
    }


def ism_policies_present(request: OsRequest = _os_request) -> dict[str, bool]:
    """Si existen las políticas ISM de retención de las cadenas nuevas."""
    return {p: request("GET", f"/_plugins/_ism/policies/{p}") is not None for p in ISM_POLICIES}


# ── Checklist Ley 21.663 ─────────────────────────────────────────────────────

def _item(iid: str, article: str, title: str, status: str, evidence: str, source: str) -> dict[str, str]:
    return {"id": iid, "article": article, "title": title, "status": status,
            "evidence": evidence, "source": source}


def build_checklist(ctx: dict[str, Any]) -> list[dict[str, str]]:
    """Obligaciones vs. evidencia del sistema. Función pura sobre `ctx`.

    Estados: "cumple" (evidencia automática suficiente), "parcial" (R-SOAR
    aporta parte), "no_cubierto" (obligación que R-SOAR no atiende todavía),
    "fuera_de_alcance" (organizacional, se gestiona fuera del sistema).
    """
    stats, chains, resp = ctx["stats"], ctx["chains"], ctx["responses"]
    total = stats.get("total_decisiones") or 0
    nodes = ctx["nodes_overall"]
    items = []

    if stats.get("available") and total > 0 and nodes != "down":
        status, ev = "cumple", (f"{_n(total)} decisiones en la ventana; latencia p95 del Fast Path "
                                f"{stats.get('latencia_p95_ms')} ms; estado de nodos: {nodes}.")
    elif stats.get("available"):
        status, ev = "parcial", f"Sin decisiones en la ventana o nodos caídos (estado: {nodes})."
    else:
        status, ev = "parcial", "OpenSearch no respondió: no se pudo medir el monitoreo."
    items.append(_item("monitoreo", "Art. 8 d)", "Revisión y análisis continuo de redes y sistemas", status, ev, "automático"))

    resp_ok, dec_ok = chains["responses"].get("ok"), chains["decisions"].get("ok")
    ism = ctx["ism"]
    if resp_ok and dec_ok and all(ism.values()):
        status = "cumple"
    elif resp_ok is False or dec_ok is False:
        status = "no_cubierto"
    else:
        status = "parcial"
    ev = (f"Cadena de respuestas: {'íntegra' if resp_ok else 'con problemas' if resp_ok is False else 'sin dato'}; "
          f"cadena de decisiones: {'íntegra' if dec_ok else 'con problemas' if dec_ok is False else 'sin dato'} "
          f"(últimos {_n(ctx['tail_size'])} eslabones de cada una). Retención ISM: "
          + ", ".join(f"{k} {'activa' if v else 'ausente'}" for k, v in ism.items()) + ".")
    items.append(_item("registro", "Art. 8 b)", "Registro de las acciones ejecutadas",
                       status, ev, "automático"))

    roles = ctx["users_by_role"]
    accesos = sum((resp.get("accesos") or {}).values()) if resp.get("available") else None
    status = "cumple" if roles.get("CISO", 0) >= 1 and resp.get("available") else "parcial"
    ev = (f"Usuarios activos por rol: N1 {roles.get('N1', 0)}, N2 {roles.get('N2', 0)}, CISO {roles.get('CISO', 0)}; "
          f"{ctx['active_sessions']} sesiones activas; "
          + (f"{accesos} eventos de acceso registrados en la cadena." if accesos is not None
             else "registro de accesos no disponible."))
    items.append(_item("acceso", "Art. 7", "Medidas permanentes de prevención: control de acceso y trazabilidad",
                       status, ev, "automático"))

    acciones = resp.get("acciones") or {}
    ejecutadas = acciones.get("ejecutadas_auto", 0) + acciones.get("ejecutadas_manual", 0)
    mode = ctx["response_mode"]
    if mode != "enforce":
        status, ev = "parcial", (f"Respuesta activa en modo {mode}: R2 registra los bloqueos pero no los ejecuta. "
                                 f"{ctx['pending_approvals']} aprobaciones pendientes.")
    else:
        status = "cumple" if resp.get("available") else "parcial"
        ev = (f"{ejecutadas} bloqueos ejecutados, {acciones.get('derivadas_aprobacion', 0)} derivados a aprobación, "
              f"{acciones.get('expiradas', 0)} expirados sin resolver, {ctx['pending_approvals']} pendientes ahora.")
    items.append(_item("respuesta", "Art. 8 e)", "Medidas oportunas para reducir impacto y propagación",
                       status, ev, "automático"))

    items.append(_item("alerta_temprana", "Art. 9 a)", "Alerta temprana al CSIRT Nacional (plazo de 3 h)",
                       "no_cubierto",
                       "R-SOAR no genera ni envía el reporte a la ANCI. Las alertas T3 de la vista "
                       "Operativa son el insumo para evaluar si un incidente es reportable.", "pendiente"))
    items.append(_item("informes", "Art. 9 b) y c)", "Actualización (72 h; 24 h si es OIV con servicio "
                       "esencial afectado), informe final (15 días) y plan de acción OIV (7 días)",
                       "no_cubierto", "Generador de reporte ANCI y exportación a PDF pendientes.", "pendiente"))
    items.append(_item("sgsi", "Art. 8 a)", "Sistema de gestión de seguridad de la información (SGSI)",
                       "parcial", "R-SOAR aporta evidencia operativa y de auditoría; políticas, "
                       "revisiones y certificación del SGSI se gestionan fuera del sistema.", "manual"))
    items.append(_item("continuidad", "Art. 8 c)", "Planes de continuidad operacional y ciberseguridad",
                       "fuera_de_alcance", "Planes certificados (Art. 28) y revisados al menos cada dos años; "
                       "no los produce R-SOAR.", "manual"))
    items.append(_item("delegado", "Art. 8 i)", "Delegado de ciberseguridad designado",
                       "fuera_de_alcance", "Designación organizacional; no la registra R-SOAR.", "manual"))
    return items


def _users_by_role(rdb: redis.Redis | None) -> dict[str, int]:
    counts = {"N1": 0, "N2": 0, "CISO": 0}
    for u in users.list_users(rdb):
        if not u.disabled:
            counts[u.role] += 1
    return counts


def compliance_report(window_minutes: int, nodes_overall: str, rdb: redis.Redis | None = None,
                      request: OsRequest = _os_request) -> dict[str, Any]:
    """Reporte CISO: métricas de valor (sección 7, Fase 1) + checklist.

    Args:
        window_minutes: ventana hacia atrás desde ahora.
        nodes_overall: estado consolidado de system_status (lo pasa el endpoint).
        rdb: Redis (tests).
        request: cliente OpenSearch inyectable (tests).

    Returns:
        Reporte con métricas, checklist y nota legal. Cada fuente que falla
        queda marcada como no disponible; el reporte se arma igual.
    """
    rdb = rdb or _get_redis()
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stats = get_stats(window_minutes)
    precision = get_precision_stats(window_minutes)
    total = stats.get("total_decisiones") or 0
    por_decision = stats.get("por_decision", {})
    auto_resuelto = sum(v for k, v in por_decision.items() if k in ("ALLOW", "LOG"))

    try:
        pending = pending_approvals_page(rdb, 1, ttl_seconds=get_settings().approval_ttl_seconds)
        pending_total = pending["total"] if pending["available"] else None
        by_role = _users_by_role(rdb)
        active_sessions = len(sess.list_all_sessions(rdb))
    except redis.RedisError as e:
        log.error(f"reporte de cumplimiento sin datos de Redis: {e}")
        pending_total, by_role, active_sessions = None, {"N1": 0, "N2": 0, "CISO": 0}, 0

    chains = audit_view.chain_status(request=request)
    responses = response_counts(since, request)
    ctx = {"stats": stats, "chains": chains["chains"], "tail_size": chains["tail_size"],
           "responses": responses, "ism": ism_policies_present(request), "nodes_overall": nodes_overall,
           "users_by_role": by_role, "active_sessions": active_sessions,
           "pending_approvals": pending_total if pending_total is not None else "sin dato",
           "response_mode": getattr(get_settings().response_mode, "value", str(get_settings().response_mode))}
    return {
        "window_minutes": window_minutes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        # Campos del stub original (compatibles).
        "fatiga_alertas_pct": round(100 * auto_resuelto / total, 1) if total else None,
        "latencia_avg_ms": stats.get("latencia_avg_ms"),
        "latencia_p95_ms": stats.get("latencia_p95_ms"),
        "precision_bloqueos": precision,
        # H43.
        "decisiones": {"available": stats.get("available", False), "total": total,
                       "por_tier": stats.get("por_tier", {})},
        "respuestas": responses,
        "aprobaciones_pendientes": pending_total,
        "usuarios_por_rol": by_role,
        "sesiones_activas": active_sessions,
        "response_mode": ctx["response_mode"],
        "cadenas": chains,
        "checklist": build_checklist(ctx),
        "mttr_humano": {"available": False,
                        "detail": "No medido todavía: el evento de resolución no registra cuándo se abrió la aprobación."},
        "nota_legal": LEGAL_NOTE,
        "exportacion_pdf": {"available": False, "detail": "Pendiente: no implementado en esta versión."},
    }


# ── Tendencias ───────────────────────────────────────────────────────────────

def _bucket_excluded(start: datetime, interval: timedelta) -> bool:
    return start < H25_EXCLUDED_TO and start + interval > H25_EXCLUDED_FROM


def _histogram_body(field: str, since: datetime, now: datetime, interval: str, sub_aggs: dict) -> dict:
    return {
        "size": 0,
        "query": {"range": {field: {"gte": since.isoformat(), "lte": now.isoformat()}}},
        "aggs": {"t": {
            "date_histogram": {"field": field, "fixed_interval": interval, "time_zone": TREND_TIME_ZONE,
                               "min_doc_count": 0,
                               "extended_bounds": {"min": since.isoformat(), "max": now.isoformat()}},
            "aggs": sub_aggs}},
    }


def tier_trend(since: datetime, now: datetime, interval: str, step: timedelta,
               request: OsRequest = _os_request) -> dict[str, Any]:
    """Decisiones por tier y por bucket. Buckets dentro de H25 -> excluded."""
    result = request("POST", f"/{OS_INDEX}/_search", _histogram_body(
        "timestamp", since, now, interval, {"tiers": {"terms": {"field": "tier", "size": 4}}}))
    if result is None:
        return {"available": False, "buckets": []}
    out = []
    for b in result.get("aggregations", {}).get("t", {}).get("buckets", []):
        start = datetime.fromtimestamp(b["key"] / 1000, tz=timezone.utc)
        excluded = _bucket_excluded(start, step)
        counts = {f"T{t}": 0 for t in range(4)}
        for tb in b.get("tiers", {}).get("buckets", []):
            counts[f"T{int(tb['key'])}"] = tb["doc_count"]
        out.append({"start": start.isoformat(), "excluded": excluded,
                    "counts": None if excluded else counts})
    return {"available": True, "buckets": out}


def action_trend(since: datetime, now: datetime, interval: str,
                 request: OsRequest = _os_request) -> dict[str, Any]:
    """Acciones por bucket (soc-responses-*, desde H39)."""
    result = request("POST", f"/{RESPONSES_PATTERN}/_search", _histogram_body(
        "event_time", since, now, interval, {"a": {"filters": {"filters": ACTION_FILTERS}}}))
    if result is None:
        return {"available": False, "buckets": []}
    out = []
    for b in result.get("aggregations", {}).get("t", {}).get("buckets", []):
        fb = b.get("a", {}).get("buckets", {})
        c = {k: fb.get(k, {}).get("doc_count", 0) for k in ACTION_FILTERS}
        out.append({"start": datetime.fromtimestamp(b["key"] / 1000, tz=timezone.utc).isoformat(),
                    "ejecutadas": c["ejecutadas_auto"] + c["ejecutadas_manual"],
                    "derivadas_aprobacion": c["derivadas_aprobacion"],
                    "expiradas": c["expiradas"], "rechazadas": c["rechazadas"]})
    return {"available": True, "buckets": out}


def corroboration_sources(since: datetime, rdb: redis.Redis) -> dict[str, Any]:
    """Fuentes que corroboraron, contadas sobre soc:response:audit.

    Returns:
        {"available", "sources": [{"source", "count"}], "evaluated",
         "sin_corroboracion", "crowdsec_observado", "coverage_from", "truncated"}.
        coverage_from = evento más viejo efectivamente leído (el stream se
        recorta a ~100k entradas: la ventana real puede ser menor a la pedida).
    """
    since_ts = since.timestamp()
    try:
        entries = rdb.xrevrange(RESPONSE_AUDIT_STREAM, count=CORROBORATION_SCAN_LIMIT)
    except redis.RedisError as e:
        log.error(f"no se pudo leer {RESPONSE_AUDIT_STREAM} para corroboración: {e}")
        return {"available": False}
    counts: dict[str, int] = {}
    evaluated = sin = crowdsec = 0
    oldest: float | None = None
    reached_window_start = False
    for _id, fields in entries:
        try:
            rec = json.loads(fields.get("data", "{}"))
        except json.JSONDecodeError:
            continue
        ts = rec.get("processed_at")
        if not isinstance(ts, (int, float)):
            continue  # accesos / aprobaciones manuales: no son respuestas R1
        if ts < since_ts:
            reached_window_start = True
            break
        enr = rec.get("enrichment")
        if not isinstance(enr, dict):
            continue
        oldest = ts
        evaluated += 1
        srcs = enr.get("corroborating_sources") or []
        if not srcs:
            sin += 1
        for s in srcs:
            counts[str(s)] = counts.get(str(s), 0) + 1
        if enr.get("crowdsec_observado"):
            crowdsec += 1
    return {
        "available": True,
        "sources": [{"source": k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])],
        "evaluated": evaluated, "sin_corroboracion": sin, "crowdsec_observado": crowdsec,
        "coverage_from": datetime.fromtimestamp(oldest, tz=timezone.utc).isoformat() if oldest else None,
        "truncated": not reached_window_start and len(entries) >= CORROBORATION_SCAN_LIMIT,
    }


_trend_cache: dict[int, tuple[float, dict]] = {}
_trend_lock = threading.Lock()


def get_trends(days: int, rdb: redis.Redis | None = None, request: OsRequest = _os_request,
               now: datetime | None = None, use_cache: bool = True) -> dict[str, Any]:
    """Tendencias para la vista CISO (cache 60 s por ventana).

    Args:
        days: 1 (buckets de 1 h), 7 o 30 (buckets de 1 día).

    Raises:
        ValueError: si `days` no es una de TREND_DAYS_ALLOWED.
    """
    if days not in TREND_DAYS_ALLOWED:
        raise ValueError(f"days debe ser uno de {TREND_DAYS_ALLOWED}")
    with _trend_lock:
        hit = _trend_cache.get(days)
        if use_cache and hit and time.monotonic() - hit[0] < TRENDS_CACHE_SECONDS:
            return hit[1]
    rdb = rdb or _get_redis()
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    interval, step = ("1h", timedelta(hours=1)) if days == 1 else ("1d", timedelta(days=1))
    pending = pending_approvals_page(rdb, 1, ttl_seconds=get_settings().approval_ttl_seconds)
    value = {
        "days": days, "interval": interval, "generated_at": now.isoformat(),
        "excluded_range": {"from": H25_EXCLUDED_FROM.isoformat(), "to": H25_EXCLUDED_TO.isoformat(),
                           "reason": "H25: el Fast Path no recibió tráfico (Vector apuntaba a una IP obsoleta)."},
        "tiers": tier_trend(since, now, interval, step, request),
        "actions": action_trend(since, now, interval, request),
        "pending_now": pending["total"] if pending.get("available") else None,
        "corroboration": corroboration_sources(since, rdb),
    }
    with _trend_lock:
        _trend_cache[days] = (time.monotonic(), value)
    return value
