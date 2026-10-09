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
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import audit_view
import redis
import sessions as sess
import users
import yaml
from dashboard import (
    OS_INDEX,
    RESPONSE_AUDIT_STREAM,
    _get_redis,
    _os_request,
    get_precision_stats,
    get_stats,
)
from regimes import policy_version, regime_at, regimes_between
from response.approvals import (
    APPROVALS_MAX_LIMIT,
    list_pending_approvals,
    pending_approvals_page,
)
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

# Score de corroboración de 4 grupos (H52/H53): en modo sombra, no decide
# ningún bloqueo. Período de validación acordado el 2026-10-07 (mismo que
# scripts/shadow_period_checkpoint.py): 20:40 -03 -> 2026-10-10 20:40 -03.
SHADOW_PERIOD_START = datetime(2026, 10, 7, 23, 40, tzinfo=timezone.utc)
SHADOW_PERIOD_END = datetime(2026, 10, 10, 23, 40, tzinfo=timezone.utc)
CORROBORATION_BANDS = ("high", "medium", "low", "ambiguous")
CORROBORATION_GROUPS = ("ml", "ti", "signature", "context")

LEGAL_NOTE = ("Artículos, literales y plazos verificados el 09-10-2026 contra el texto oficial de la Ley 21.663 "
              "(LeyChile/BCN, idNorma 1202434) y del DS 295/2024, reglamento de reporte de incidentes "
              "(idNorma 1211466). El Art. 8 obliga a los operadores de importancia vital; el Art. 9, a todas "
              "las instituciones del Art. 4. Los plazos de 72 h y de 7 días se cuentan desde el conocimiento "
              "del incidente (DS 295 arts. 10 y 11) y el de 15 días desde el envío de la alerta temprana "
              "(Art. 9 c).")
SCOPE_NOTE = ("R-SOAR aporta evidencia técnica de apoyo. La evaluación de cumplimiento legal, la determinación "
              "de si un incidente es reportable y los reportes a la ANCI son responsabilidad de la organización.")

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


def _pct(part: int, total: int) -> float | None:
    return round(100 * part / total, 1) if total else None


def corroboration_shadow(since: datetime, request: OsRequest = _os_request) -> dict[str, Any]:
    """Score de corroboración de 4 grupos sobre las T3 de soc-responses-*.

    Solo reporte: el score sigue en modo sombra (H52/H53) y el gate de R2
    usa corroboration_count, no la banda. `eligible` = band "high" y no
    ambiguo, lo que habilitaría autobloqueo si el score reemplazara al gate.

    El cálculo arranca en max(since, SHADOW_PERIOD_START): antes del período
    el score corrió con reglas previas (H52 sin signature/context, H53 antes
    de P4) y sus bandas no son comparables (H53, "Cómo comparar"). Las T3 de
    la ventana que quedan antes de ese inicio, o sin score, se cuentan en
    `excluded`, nunca en el denominador.

    Denominadores separados, nunca mezclados:
    - `scored`: T3 con score (corroboration_band) desde `from`.
    - `groups.evaluated`: T3 con corroboration_groups_available desde `from`.

    Args:
        since: inicio de la ventana (la misma que el resto del reporte).
        request: cliente OpenSearch inyectable (tests).

    Returns:
        {"available", "shadow", "from", "clamped", "t3_total", "scored",
         "excluded", "eligible", "eligible_pct", "bands",
         "groups": {"evaluated", "available_pct"}, "validation": {"start", "end"}}.
    """
    calc_from = max(since, SHADOW_PERIOD_START)
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"term": {"event_type": "response"}}, {"term": {"tier": 3}},
            {"range": {"event_time": {"gte": since.isoformat()}}}]}},
        "aggs": {"period": {"filter": {"range": {"event_time": {"gte": calc_from.isoformat()}}}, "aggs": {
            "scored": {"filter": {"exists": {"field": "corroboration_band"}}, "aggs": {
                "bands": {"terms": {"field": "corroboration_band", "size": 10}},
                "eligible": {"filter": {"bool": {"filter": [
                    {"term": {"corroboration_band": "high"}},
                    {"term": {"corroboration_ambiguous": False}}]}}},
            }},
            "grouped": {"filter": {"exists": {"field": "corroboration_groups_available"}}, "aggs": {
                "groups": {"terms": {"field": "corroboration_groups_available", "size": 10}},
            }},
        }}},
    }
    base = {"shadow": True, "from": calc_from.isoformat(), "clamped": calc_from > since,
            "validation": {"start": SHADOW_PERIOD_START.isoformat(), "end": SHADOW_PERIOD_END.isoformat()}}
    result = request("POST", f"/{RESPONSES_PATTERN}/_search", body)
    if result is None:
        return {"available": False, **base}
    period = result.get("aggregations", {}).get("period", {})
    t3_total = result.get("hits", {}).get("total", {}).get("value", 0)
    scored_agg = period.get("scored", {})
    scored = scored_agg.get("doc_count", 0)
    band_counts = {b["key"]: b["doc_count"] for b in scored_agg.get("bands", {}).get("buckets", [])}
    eligible = scored_agg.get("eligible", {}).get("doc_count", 0)
    grouped = period.get("grouped", {})
    evaluated = grouped.get("doc_count", 0)
    group_counts = {b["key"]: b["doc_count"] for b in grouped.get("groups", {}).get("buckets", [])}
    return {
        "available": True,
        **base,
        "t3_total": t3_total,
        "scored": scored,
        "excluded": t3_total - scored,
        "eligible": eligible,
        "eligible_pct": _pct(eligible, scored),
        "bands": {b: band_counts.get(b, 0) for b in CORROBORATION_BANDS},
        "groups": {"evaluated": evaluated,
                   "available_pct": {g: _pct(group_counts.get(g, 0), evaluated) for g in CORROBORATION_GROUPS}},
    }


def ism_policies_present(request: OsRequest = _os_request) -> dict[str, bool]:
    """Si existen las políticas ISM de retención de las cadenas nuevas."""
    return {p: request("GET", f"/_plugins/_ism/policies/{p}") is not None for p in ISM_POLICIES}


# ── Diagnóstico de nodos (H57, a2) ───────────────────────────────────────────

def shards_diagnosis(request: OsRequest = _os_request) -> dict[str, Any]:
    """Shards sin asignar por prefijo de índice y tipo (primario o réplica).

    Explica un OpenSearch en amarillo: en un clúster de un solo nodo, todo
    índice creado con number_of_replicas >= 1 deja sus réplicas sin asignar.
    """
    rows = request("GET", "/_cat/shards?h=index,prirep,state&format=json")
    if not isinstance(rows, list):
        return {"available": False}
    by_prefix: dict[str, int] = {}
    replicas = primaries = 0
    for s in rows:
        if s.get("state") != "UNASSIGNED":
            continue
        idx = str(s.get("index", ""))
        prefix = idx.rsplit("-", 1)[0] if idx[-10:-6].isdigit() else idx
        by_prefix[prefix] = by_prefix.get(prefix, 0) + 1
        replicas += s.get("prirep") == "r"
        primaries += s.get("prirep") == "p"
    return {"available": True, "unassigned_total": replicas + primaries, "replicas": replicas,
            "primaries": primaries, "by_prefix": dict(sorted(by_prefix.items(), key=lambda x: -x[1]))}


def _node_observations(nodes: dict[str, Any], shards: dict[str, Any]) -> list[str]:
    """Una línea por componente no "ok", con el diagnóstico de réplicas si aplica."""
    out = []
    for c in nodes.get("components", []):
        if c.get("status") in ("ok", "not_configured"):
            continue
        line = f"{c.get('name', c.get('id'))} ({c.get('host', '')}): {c.get('status')}, {c.get('detail', '')}"
        if c.get("id") == "opensearch" and shards.get("available") and shards.get("replicas"):
            top = ", ".join(f"{k} {v}" for k, v in list(shards["by_prefix"].items())[:4])
            line += (f". Son {shards['replicas']} shards réplica sin asignar ({top}): índices con "
                     "number_of_replicas 1 en un clúster de un solo nodo. No hay pérdida de datos "
                     "(los primarios están asignados).")
        out.append(line)
    return out


# ── Conciliación de aprobaciones (H57, a3) ───────────────────────────────────

def _search_all(request: OsRequest, body: dict, page: int = 5000, max_docs: int = 200_000) -> list[dict] | None:
    """_source de todos los documentos de soc-responses-* que cumplen `body`
    (search_after por event_time y stream_id). None si OpenSearch no respondió."""
    out: list[dict] = []
    after = None
    while len(out) < max_docs:
        q = {**body, "size": page, "sort": [{"event_time": "asc"}, {"stream_id": "asc"}]}
        if after is not None:
            q["search_after"] = after
        res = request("POST", f"/{RESPONSES_PATTERN}/_search", q)
        if res is None:
            return None
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            break
        out.extend(h.get("_source", {}) for h in hits)
        after = hits[-1].get("sort")
    return out


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _window_filter(since: datetime) -> dict:
    return {"range": {"event_time": {"gte": since.isoformat()}}}


DERIVED_FILTER = [{"term": {"event_type": "response"}},
                  {"term": {"accion_recomendada": "alertar_pendiente_aprobacion"}}]
ENFORCED_FILTER = {"bool": {"should": [{"term": {"event_type": "response"}},
                                       {"term": {"event_type": "manual_approval"}}],
                            "minimum_should_match": 1,
                            "filter": [{"term": {"block_enforced": True}}]}}


def approvals_reconciliation(since: datetime, now: datetime, rdb: redis.Redis | None,
                             request: OsRequest = _os_request) -> dict[str, Any]:
    """Respuesta y aprobaciones de la ventana, con unidades explícitas y una
    conciliación por caminos independientes (H57, ajustada en H58 con datos reales).

    Unidades: IPs distintas (lo que importa operativamente), decisiones T3
    (documentos de soc-responses) y aprobaciones (una por IP mientras está
    abierta: las decisiones T3 siguientes de la misma IP se suman como
    recurrencias, dedup de H38).

    1. Aprobaciones creadas en la ventana, por dos caminos:
       - por destino: aprobadas + rechazadas + expiradas + pendientes con
         created_at dentro de la ventana;
       - por documentos: decisiones T3 derivadas de la ventana cuyo trace_id es
         el id de una de esas aprobaciones (el id es el trace_id que la abrió).
    2. Recurrencias, por dos caminos:
       - por documentos: decisiones T3 derivadas con aprobación de por medio
         (block_pending_approval) menos las que abrieron una aprobación;
       - por contador: suma de (occurrences - 1) de las aprobaciones creadas
         en la ventana.
       Diferencia esperable y explicada: las decisiones de la ventana que se
       sumaron a aprobaciones abiertas ANTES de su inicio (TTL de 4 h). Su
       cota es la suma de (occurrences - 1) de esas aprobaciones. Si la
       diferencia cae entre 0 y la cota, es "diferencia explicada"; si no, la
       conciliación no cierra y la vista lo dice.
    Las decisiones derivadas sin aprobación (p. ej. stale, H38) se informan
    aparte y no entran a las recurrencias.
    """
    agg = request("POST", f"/{RESPONSES_PATTERN}/_search", {
        "size": 0, "track_total_hits": True,
        "query": _window_filter(since),
        "aggs": {
            "derivadas": {"filter": {"bool": {"filter": DERIVED_FILTER}},
                          "aggs": {"ips": {"cardinality": {"field": "src_ip", "precision_threshold": 40000}},
                                   "accion": {"terms": {"field": "block_action", "size": 10}}}},
            "bloqueos": {"filter": ENFORCED_FILTER,
                         "aggs": {"ips": {"cardinality": {"field": "src_ip", "precision_threshold": 40000}}}},
        },
    })
    if agg is None:
        return {"available": False}
    a = agg.get("aggregations", {})
    derived_docs = a.get("derivadas", {}).get("doc_count", 0)
    by_action = {b["key"]: b["doc_count"] for b in a.get("derivadas", {}).get("accion", {}).get("buckets", [])}
    with_approval_flow = by_action.get("block_pending_approval", 0)
    out: dict[str, Any] = {
        "available": True,
        "ventana": {"desde": since.isoformat(), "hasta": now.isoformat()},
        "ips_bloqueadas": a.get("bloqueos", {}).get("ips", {}).get("value", 0),
        "acciones_de_bloqueo": a.get("bloqueos", {}).get("doc_count", 0),
        "ips_derivadas": a.get("derivadas", {}).get("ips", {}).get("value", 0),
        "decisiones_t3_derivadas": derived_docs,
        "decisiones_derivadas_sin_aprobacion": derived_docs - with_approval_flow,
    }

    # id -> occurrences, por destino; y las aprobaciones creadas antes de la ventana.
    fates: dict[str, dict[str, int]] = {"aprobadas": {}, "rechazadas": {}, "expiradas": {}, "pendientes": {}}
    before: dict[str, int] = {}
    sin_created_at = 0
    events = _search_all(request, {"query": {"bool": {"filter": [
        _window_filter(since),
        {"terms": {"event_type": ["approval_expired", "manual_approval", "access"]}}]}},
        "_source": ["event_type", "access_event", "trace_id", "payload"]})
    if events is None:
        return {**out, "conciliacion": {"available": False}}
    for e in events:
        p = e.get("payload") or {}
        etype = e.get("event_type")
        if etype == "approval_expired":
            created, fate, tid, occ = p.get("created_at"), "expiradas", e.get("trace_id"), p.get("occurrences", 1)
        elif etype == "manual_approval":
            created, fate, tid, occ = p.get("approval_created_at"), "aprobadas", e.get("trace_id"), 1
        elif etype == "access" and e.get("access_event") == "approval_rejected":
            detail = p.get("detail") or {}
            created, fate, tid, occ = (detail.get("approval_created_at"), "rechazadas",
                                       detail.get("trace_id") or e.get("trace_id"), 1)
        else:
            continue
        ts = _parse_ts(created)
        if ts is None:
            sin_created_at += 1  # eventos previos a H57 sin created_at: no se pueden ubicar
            continue
        if tid:
            (fates[fate] if ts >= since else before)[tid] = int(occ or 1)
    pending_truncated = False
    try:
        pend = list_pending_approvals(rdb, limit=APPROVALS_MAX_LIMIT) if rdb is not None else []
        pending_truncated = len(pend) >= APPROVALS_MAX_LIMIT
        for ap in pend:
            ts = _parse_ts(ap.get("created_at"))
            if ts is not None and ap.get("trace_id"):
                (fates["pendientes"] if ts >= since else before)[ap["trace_id"]] = int(ap.get("occurrences") or 1)
        pend_now = len(pend)
    except (redis.RedisError, AttributeError) as e:
        log.error(f"conciliación sin la foto de pendientes: {e}")
        pend_now = None
    ids = set().union(*(f.keys() for f in fates.values()))
    by_fate = sum(len(v) for v in fates.values())

    by_docs = 0
    id_list = sorted(ids)
    for i in range(0, len(id_list), 10_000):
        res = request("POST", f"/{RESPONSES_PATTERN}/_search", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": [_window_filter(since), *DERIVED_FILTER,
                                          {"terms": {"trace_id": id_list[i:i + 10_000]}}]}}})
        if res is None:
            return {**out, "conciliacion": {"available": False}}
        by_docs += res.get("hits", {}).get("total", {}).get("value", 0)

    rec_docs = with_approval_flow - by_docs
    rec_counter = sum(o - 1 for f in fates.values() for o in f.values())
    edge_bound = sum(o - 1 for o in before.values())
    diff = rec_docs - rec_counter
    if by_fate != by_docs:
        estado, causa = "no_cierra", (f"las aprobaciones creadas difieren: {by_fate} por destino y {by_docs} "
                                      "por documentos (p. ej. una aprobación perdida de Redis)")
    elif diff == 0:
        estado, causa = "cierra", ""
    elif 0 <= diff <= edge_bound:
        estado, causa = "diferencia_explicada", (
            f"{diff} decisiones de la ventana se sumaron a {len(before)} aprobaciones abiertas antes de su "
            f"inicio (TTL de 4 h); esas aprobaciones acumulan hasta {edge_bound} recurrencias")
    else:
        estado, causa = "no_cierra", (f"{diff} recurrencias por documentos sin explicar: la cota por las "
                                      f"aprobaciones abiertas antes de la ventana es {edge_bound}")

    out["aprobaciones"] = {
        "creadas_en_la_ventana": by_fate,
        **{k: len(v) for k, v in fates.items()},
        "recurrencias": rec_docs,
        "recurrencias_por_contador": rec_counter,
        "abiertas_antes_de_la_ventana": len(before),
        "eventos_sin_created_at": sin_created_at,
    }
    out["pendientes_ahora"] = pend_now
    out["pendientes_truncado"] = pending_truncated
    out["conciliacion"] = {
        "available": True,
        "estado": estado,
        "cierra": estado in ("cierra", "diferencia_explicada"),
        "causa": causa,
        "creadas_por_destino": by_fate,
        "creadas_por_documentos": by_docs,
        "recurrencias_por_documentos": rec_docs,
        "recurrencias_por_contador": rec_counter,
        "diferencia": diff if by_fate == by_docs else by_fate - by_docs,
        "cota_borde": edge_bound,
        "regla": ("creadas por destino = creadas por documentos; recurrencias por documentos = recurrencias "
                  "por contador + las sumadas a aprobaciones abiertas antes de la ventana"),
    }
    return out


# ── Tiempos de detección y respuesta (H57, d) ────────────────────────────────

def _pctl(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * len(v)))], 2)


def response_timings(since: datetime, request: OsRequest = _os_request) -> dict[str, Any]:
    """MTTD y MTTR reducidos, desde soc-responses.

    - detección a decisión: event_age_seconds (desde el flujo que detectó
      Suricata hasta que el worker registra la decisión R1/R2), T2 y T3.
    - decisión a bloqueo: entre el inicio del procesamiento (processed_at) y
      el registro del bloqueo ejecutado, en los bloqueos automáticos.
    - detección a bloqueo: event_age_seconds de los bloqueos automáticos.
    - humano: desde que se abre una aprobación hasta que alguien la resuelve.
      Solo desde H57 el evento de resolución guarda created_at.
    """
    res = request("POST", f"/{RESPONSES_PATTERN}/_search", {
        "size": 0, "query": {"bool": {"filter": [_window_filter(since), {"term": {"event_type": "response"}},
                                                 {"range": {"tier": {"gte": 2}}}]}},
        "aggs": {"decision": {"percentiles": {"field": "event_age_seconds", "percents": [50, 95]}},
                 "bloqueo": {"filter": {"term": {"block_enforced": True}},
                             "aggs": {"p": {"percentiles": {"field": "event_age_seconds", "percents": [50, 95]}}}}}})
    if res is None:
        return {"available": False}
    a = res.get("aggregations", {})
    dec = a.get("decision", {}).get("values", {})
    blk = a.get("bloqueo", {})
    blocks = _search_all(request, {"query": {"bool": {"filter": [
        _window_filter(since), {"term": {"event_type": "response"}}, {"term": {"block_enforced": True}}]}},
        "_source": ["event_time", "payload.processed_at"]}, max_docs=50_000) or []
    to_action = []
    for d in blocks:
        t_ev = _parse_ts(d.get("event_time"))
        start = (d.get("payload") or {}).get("processed_at")
        if t_ev is not None and isinstance(start, int | float):
            to_action.append(max(0.0, t_ev.timestamp() - start))
    human = []
    resolved = _search_all(request, {"query": {"bool": {"filter": [
        _window_filter(since), {"terms": {"event_type": ["manual_approval", "access"]}}]}},
        "_source": ["event_type", "access_event", "event_time", "payload"]}) or []
    for e in resolved:
        p = e.get("payload") or {}
        if e.get("event_type") == "manual_approval":
            created = p.get("approval_created_at")
        elif e.get("access_event") == "approval_rejected":
            created = (p.get("detail") or {}).get("approval_created_at")
        else:
            continue
        c, r = _parse_ts(created), _parse_ts(e.get("event_time"))
        if c and r:
            human.append((r - c).total_seconds())
    return {
        "available": True,
        "deteccion_a_decision_s": {"p50": dec.get("50.0"), "p95": dec.get("95.0"),
                                   "n": res.get("hits", {}).get("total", {}).get("value")},
        "deteccion_a_bloqueo_s": {"p50": blk.get("p", {}).get("values", {}).get("50.0"),
                                  "p95": blk.get("p", {}).get("values", {}).get("95.0"),
                                  "n": blk.get("doc_count", 0)},
        "decision_a_bloqueo_s": {"p50": _pctl(to_action, 0.5), "p95": _pctl(to_action, 0.95), "n": len(to_action)},
        "humano_s": ({"p50": _pctl(human, 0.5), "p95": _pctl(human, 0.95), "n": len(human)} if human else
                     {"p50": None, "p95": None, "n": 0,
                      "detalle": "sin datos: no hubo aprobaciones resueltas por una persona con hora de "
                                 "apertura registrada en la ventana (se registra desde H57)"}),
    }


# ── Integridad (H57, b) ──────────────────────────────────────────────────────

AUDIT_VERIFY_JSON = Path(os.environ.get(
    "AUDIT_VERIFY_JSON", str(Path.home() / "tesis" / "motor-runtime" / "audit" / "verify_chain_latest.json")))
AUDIT_GAPS_YAML = Path(__file__).resolve().parent / "audit_gaps.yaml"


def declared_gaps(path: Path = AUDIT_GAPS_YAML) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        log.error(f"huecos declarados no legibles ({path}): {e}")
        return {"available": False, "gaps": []}
    return {"available": True, "version": data.get("version"), "gaps": data.get("gaps", [])}


def full_verification(path: Path = AUDIT_VERIFY_JSON) -> dict[str, Any]:
    """Último informe de scripts/audit/verify_chain.py, si existe."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"available": False, "detail": "todavía no se corrió scripts/audit/verify_chain.py"}
    except (OSError, ValueError) as e:
        return {"available": False, "detail": f"informe no legible: {e}"}
    return {"available": True, **report}


LEGACY_NOT_VERIFIED = ("el índice legado soc-decisions (17,9 M documentos, cadena vieja) no se verificó en "
                       "esta pasada")


def chain_scope_text(full: dict[str, Any]) -> str:
    """Alcance explícito de la verificación completa: cada cadena vigente con
    su rango (fecha de inicio, chain_seq 1 a N), la hora de la verificación y
    lo que no se verificó (H58)."""
    if not full.get("available"):
        return f"sin verificación completa registrada; {LEGACY_NOT_VERIFIED}"
    parts = []
    for name, c in (full.get("cadenas") or {}).items():
        pattern = c.get("pattern", name)
        desde = str(c.get("first_time") or "")[:10] or "sin dato"
        estado = ("abortada: " + str(c["aborted"])) if c.get("aborted") else ("íntegra" if c.get("ok") else "con problemas")
        parts.append(f"{pattern} desde {desde}, chain_seq {c.get('first_seq')} a {c.get('last_seq')}, {estado}")
    when = str(full.get("generated_at") or "")[:16].replace("T", " ")
    return (f"verificación completa ({full.get('alcance')}) del {when} UTC: " + "; ".join(parts)
            + f"; {LEGACY_NOT_VERIFIED}")


def integrity_panel(chains_live: dict[str, Any]) -> dict[str, Any]:
    """Combina la verificación completa (informe JSON), la de la cola en vivo
    y los huecos declarados. "completa" solo si el informe cubrió todas las
    cadenas nuevas sin abortar, sin problemas, y la cola en vivo también está
    íntegra."""
    full = full_verification()
    live_ok = all(c.get("ok") is True for c in chains_live.get("chains", {}).values())
    full_ok = full.get("available") and full.get("alcance") == "completa" and full.get("ok") is True
    if full_ok and live_ok:
        alcance = "completa"
    elif full.get("available"):
        alcance = "parcial"
    else:
        alcance = "solo_cola"
    return {"alcance": alcance, "alcance_texto": chain_scope_text(full), "completa": full,
            "cola_en_vivo": chains_live, "huecos_declarados": declared_gaps()}


# ── Historial diario (H57, f) ────────────────────────────────────────────────

def daily_history(days: int = 30, request: OsRequest = _os_request, now: datetime | None = None) -> dict[str, Any]:
    """Por día (hora de Chile), recalculado desde soc-responses sin guardar
    nada: IPs distintas bloqueadas y derivadas a aprobación, su razón y las
    expiradas, con los regímenes que tocan cada día (antes y después de un
    corte no son el mismo sistema)."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    card = {"cardinality": {"field": "src_ip", "precision_threshold": 40000}}
    res = request("POST", f"/{RESPONSES_PATTERN}/_search", {
        "size": 0, "query": _window_filter(since),
        "aggs": {"dia": {"date_histogram": {"field": "event_time", "calendar_interval": "1d",
                                            "time_zone": TREND_TIME_ZONE, "min_doc_count": 0},
                         "aggs": {"bloqueos": {"filter": ENFORCED_FILTER, "aggs": {"ips": card}},
                                  "derivadas": {"filter": {"bool": {"filter": DERIVED_FILTER}}, "aggs": {"ips": card}},
                                  "expiradas": {"filter": {"term": {"event_type": "approval_expired"}}}}}}})
    if res is None:
        return {"available": False}
    rows = []
    for b in res.get("aggregations", {}).get("dia", {}).get("buckets", []):
        start = _parse_ts(b.get("key_as_string")) or datetime.fromtimestamp(b["key"] / 1000, timezone.utc)
        blocked = b.get("bloqueos", {}).get("ips", {}).get("value", 0)
        derived = b.get("derivadas", {}).get("ips", {}).get("value", 0)
        rows.append({
            "dia": start.date().isoformat(),
            "ips_bloqueadas": blocked,
            "ips_derivadas": derived,
            "razon_bloqueo_sobre_derivacion": round(blocked / derived, 3) if derived else None,
            "aprobaciones_expiradas": b.get("expiradas", {}).get("doc_count", 0),
            "regimenes": [r["id"] for r in regimes_between(start, start + timedelta(days=1))],
        })
    return {"available": True, "zona_horaria": TREND_TIME_ZONE, "unidad": "IPs distintas por día", "dias": rows}


# ── Checklist Ley 21.663 ─────────────────────────────────────────────────────

def _meta(ventana: str, unidad: str, fuente: str, actualizado: str, registros: str) -> dict[str, str]:
    """Contexto de cada número: de qué ventana sale, en qué unidad, de qué
    fuente, cuándo se calculó y dónde ver los registros que lo respaldan."""
    return {"ventana": ventana, "unidad": unidad, "fuente": fuente, "actualizado": actualizado,
            "registros": registros}


def _item(iid: str, article: str, title: str, status: str, evidence: str, source: str,
          meta: dict[str, str] | None = None) -> dict[str, Any]:
    return {"id": iid, "article": article, "title": title, "status": status,
            "evidence": evidence, "source": source, "meta": meta}


def build_checklist(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Obligaciones vs. evidencia técnica de apoyo. Función pura sobre `ctx`.

    Estados: "cumple" (con evidencia técnica de apoyo), "con_observacion"
    (hay evidencia pero algún componente está degradado: nunca "cumple" con
    un nodo degradado), "parcial" (R-SOAR aporta parte), "no_cubierto"
    (obligación que R-SOAR no atiende), "fuera_de_alcance" (organizacional).
    Ningún estado es una declaración de cumplimiento legal.
    """
    stats, chains, resp = ctx["stats"], ctx["chains"], ctx["responses"]
    total = stats.get("total_decisiones") or 0
    nodes = ctx["nodes_overall"]
    obs = ctx.get("node_observations") or []
    when = ctx.get("generated_at", "")
    win = ctx.get("window_label", "ventana móvil")
    oiv = ctx.get("organizacion_es_oiv")
    oiv_note = ("La organización se declaró operador de importancia vital: este literal aplica."
                if oiv is True else "Aplica solo si la organización es operador de importancia vital."
                if oiv is None else "La organización declaró no ser operador de importancia vital.")
    items = []

    meta = _meta(win, "decisiones del Fast Path, todos los tiers; latencia en ms",
                 "soc-decisions,soc-decisions-* (timestamp, latency_ms) y estado de nodos",
                 when, "#nodos")
    # H58: siempre "parcial". El literal exige revisión, ejercicios, simulacros,
    # análisis y comunicar las amenazas al CSIRT; R-SOAR cubre solo el análisis
    # continuo. Un nodo degradado se informa en las observaciones.
    status = "parcial"
    ev = (f"Cubre R-SOAR: análisis continuo de redes y sistemas, con {_n(total)} decisiones en la ventana, "
          f"latencia interna del Fast Path p95 {stats.get('latencia_p95_ms')} ms (procesamiento del motor, sin red "
          f"ni Vector; percentil aproximado de OpenSearch) y estado de nodos {nodes}. Queda en la organización: "
          "ejercicios, simulacros y la comunicación de amenazas al CSIRT Nacional."
          if stats.get("available") else "OpenSearch no respondió: no se pudo medir el análisis continuo. Queda "
          "en la organización: ejercicios, simulacros y la comunicación de amenazas al CSIRT Nacional.")
    if obs:
        ev += " Observaciones: " + " ".join(obs)
    items.append(_item("monitoreo", "Art. 8 d)", "Revisión, ejercicios, simulacros y análisis continuo de redes "
                       "y sistemas", status, ev + " " + oiv_note, "automático", meta))

    integ = ctx.get("integrity") or {}
    resp_ok, dec_ok = chains["responses"].get("ok"), chains["decisions"].get("ok")
    ism = ctx["ism"]
    if resp_ok and dec_ok and all(ism.values()):
        status = "cumple"
    elif resp_ok is False or dec_ok is False:
        status = "no_cubierto"
    else:
        status = "parcial"
    full = integ.get("completa") or {}
    full_txt = chain_scope_text(full)
    gaps = (integ.get("huecos_declarados") or {}).get("gaps", [])
    ev = (f"Cola en vivo: respuestas {'íntegra' if resp_ok else 'con problemas' if resp_ok is False else 'sin dato'}, "
          f"decisiones {'íntegra' if dec_ok else 'con problemas' if dec_ok is False else 'sin dato'} "
          f"(últimos {_n(ctx['tail_size'])} eslabones de cada una); {full_txt}; "
          f"{len(gaps)} huecos declarados ({', '.join(g.get('id', '') for g in gaps)}). Retención ISM: "
          + ", ".join(f"{k} {'activa' if v else 'ausente'}" for k, v in ism.items()) + ". "
          + oiv_note)
    items.append(_item("registro", "Art. 8 b)", "Registro de las acciones ejecutadas", status, ev, "automático",
                       _meta("cola: últimos eslabones al momento; completa: según el informe",
                             "eslabones de las cadenas hash", "soc-responses-*, soc-decisions-*, "
                             "scripts/audit/verify_chain.py, motor/audit_gaps.yaml", when, "#auditoria")))

    roles, ustat = ctx["users_by_role"], ctx.get("users_index") or {"reliable": True}
    accesos = sum((resp.get("accesos") or {}).values()) if resp.get("available") else None
    if not ustat.get("reliable", True):
        users_txt = f"usuarios y sesiones: dato no confiable ({ustat.get('reason')})"
    else:
        users_txt = (f"usuarios activos por rol: N1 {roles.get('N1', 0)}, N2 {roles.get('N2', 0)}, "
                     f"CISO {roles.get('CISO', 0)}; {ctx['active_sessions']} sesiones activas")
    ev = (f"R-SOAR aporta control de acceso por rol y trazabilidad: {users_txt}; "
          + (f"{accesos} eventos de acceso registrados en la cadena en la ventana. " if accesos is not None
             else "registro de accesos no disponible. ")
          + "Las medidas para prevenir, reportar y resolver incidentes son más amplias que el sistema.")
    items.append(_item("acceso", "Art. 7", "Deberes generales: medidas permanentes para prevenir, reportar y "
                       "resolver incidentes", "parcial", ev, "automático",
                       _meta(win + " (eventos de acceso); usuarios y sesiones: foto actual",
                             "usuarios, sesiones vigentes, eventos de acceso",
                             "Redis soc:users:index y soc:sessions:*; soc-responses-* (event_type access)",
                             when, "#usuarios")))

    rec = ctx.get("reconciliation") or {}
    mode = ctx["response_mode"]
    if mode != "enforce":
        status, ev = "parcial", f"Respuesta activa en modo {mode}: R2 registra los bloqueos pero no los ejecuta."
    elif not rec.get("available"):
        status, ev = "parcial", "OpenSearch no respondió: sin datos de respuesta."
    else:
        apr = rec.get("aprobaciones") or {}
        conc = rec.get("conciliacion") or {}
        # Solo una conciliación exacta "cumple". Una diferencia explicada se
        # muestra con su causa pero queda "con observación" (decisión de Antonio, H58).
        status = "cumple" if conc.get("estado") == "cierra" else "con_observacion"
        ev = (f"En la ventana: {_n(rec['ips_bloqueadas'])} IPs distintas bloqueadas "
              f"({_n(rec['acciones_de_bloqueo'])} acciones de bloqueo, incluye re-bloqueos al vencer el TTL); "
              f"{_n(rec['ips_derivadas'])} IPs distintas derivadas a aprobación "
              f"({_n(rec['decisiones_t3_derivadas'])} decisiones T3). Aprobaciones creadas: "
              f"{_n(apr.get('creadas_en_la_ventana', 0))} (aprobadas {apr.get('aprobadas', 0)}, rechazadas "
              f"{apr.get('rechazadas', 0)}, expiradas {apr.get('expiradas', 0)}, pendientes "
              f"{apr.get('pendientes', 0)}); recurrencias sumadas a aprobaciones abiertas: "
              f"{_n(apr.get('recurrencias', 0))}. ")
        estado = conc.get("estado")
        ev += ("La conciliación cierra." if estado == "cierra" else
               f"Diferencia explicada: {conc.get('causa')}." if estado == "diferencia_explicada" else
               f"La conciliación NO cierra: {conc.get('causa')}." if conc.get("available")
               else "Conciliación no disponible.")
        ev += f" Foto actual: {rec.get('pendientes_ahora', 'sin dato')} aprobaciones pendientes."
    items.append(_item("respuesta", "Art. 8 e)", "Medidas oportunas para reducir el impacto y la propagación",
                       status, ev + " " + oiv_note, "automático",
                       _meta(win + "; pendientes: foto actual",
                             "IPs distintas; decisiones T3; aprobaciones (una por IP abierta)",
                             "soc-responses-* (response, manual_approval, approval_expired, access) y Redis "
                             "soc:approvals:pending", when, "#aprobaciones")))

    items.append(_item("alerta_temprana", "Art. 9 a); DS 295 art. 9",
                       "Alerta temprana al CSIRT Nacional: 3 h desde el conocimiento del incidente",
                       "no_cubierto",
                       "R-SOAR no genera ni envía reportes a la ANCI. Las decisiones T3 corroboradas son insumo "
                       "para que la organización evalúe si hay un incidente con impacto significativo; el "
                       "conocimiento del incidente lo determina la organización.", "pendiente"))
    items.append(_item("segundo_reporte", "Art. 9 b); DS 295 art. 10",
                       "Segundo reporte: 72 h desde el conocimiento; 24 h si es OIV con servicio esencial afectado",
                       "no_cubierto", "Generador de reportes pendiente. El plazo de 24 h aplica solo a operadores "
                       "de importancia vital.", "pendiente"))
    items.append(_item("informe_final", "Art. 9 c); DS 295 arts. 12 y 13",
                       "Informe final: 15 días corridos desde el envío de la alerta temprana; informes parciales "
                       "cada 15 días mientras no esté gestionado", "no_cubierto",
                       "Generador de reportes y exportación pendientes (PDF en el roadmap).", "pendiente"))
    items.append(_item("plan_accion", "Art. 9, párrafo final; DS 295 art. 11",
                       "Plan de acción del OIV: hasta 7 días corridos desde el conocimiento del incidente",
                       "no_cubierto", "Aplica solo a operadores de importancia vital; no lo produce R-SOAR.",
                       "pendiente"))
    items.append(_item("sgsi", "Art. 8 a)", "Sistema de gestión de seguridad de la información (SGSI)",
                       "parcial", "R-SOAR aporta evidencia operativa y de auditoría; políticas, revisiones y "
                       "certificación del SGSI se gestionan fuera del sistema.", "manual"))
    items.append(_item("continuidad", "Art. 8 c)", "Planes de continuidad operacional y ciberseguridad",
                       "fuera_de_alcance", "Planes certificados (Art. 28) y revisados al menos cada dos años; "
                       "no los produce R-SOAR.", "manual"))
    items.append(_item("certificaciones", "Art. 8 f)", "Certificaciones del Art. 28", "fuera_de_alcance",
                       "Gestión organizacional; R-SOAR no las emite ni las registra.", "manual"))
    items.append(_item("afectados", "Art. 8 g)", "Informar a los potenciales afectados cuando lo requiera la Agencia",
                       "fuera_de_alcance", "Comunicación organizacional; R-SOAR no la realiza.", "manual"))
    items.append(_item("capacitacion", "Art. 8 h)", "Capacitación y educación continua de trabajadores y "
                       "colaboradores", "fuera_de_alcance", "Programa organizacional; no lo gestiona R-SOAR.",
                       "manual"))
    items.append(_item("delegado", "Art. 8 i)", "Delegado de ciberseguridad designado",
                       "fuera_de_alcance", "Designación organizacional; no la registra R-SOAR.", "manual"))
    return items


def coverage_summary(items: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    """Cobertura sobre lo que corresponde al sistema: no cuenta "fuera del sistema"."""
    system = [i for i in items if i["status"] != "fuera_de_alcance"]
    counts: dict[str, int] = {}
    for i in system:
        counts[i["status"]] = counts.get(i["status"], 0) + 1
    return {"obligaciones_del_sistema": len(system), "por_estado": counts,
            "fuera_del_sistema": len(items) - len(system), "generado": generated_at}


def _users_by_role(rdb: redis.Redis | None) -> dict[str, int]:
    counts = {"N1": 0, "N2": 0, "CISO": 0}
    for u in users.list_users(rdb):
        if not u.disabled:
            counts[u.role] += 1
    return counts


WINDOW_LABELS = {1440: "ventana móvil de 24 h", 10_080: "ventana móvil de 7 días", 43_200: "ventana móvil de 30 días"}


def compliance_report(window_minutes: int, nodes: dict[str, Any] | str, rdb: redis.Redis | None = None,
                      request: OsRequest = _os_request, current_username: str | None = None) -> dict[str, Any]:
    """Reporte CISO: métricas de valor + checklist con evidencia técnica de apoyo.

    Args:
        window_minutes: ventana hacia atrás desde ahora.
        nodes: estado de system_status.get_node_status() (o solo el "overall").
        rdb: Redis (tests).
        request: cliente OpenSearch inyectable (tests).
        current_username: usuario que consulta (chequeo del índice de usuarios).

    Returns:
        Reporte con resumen, métricas, conciliación, tiempos, integridad,
        historial y checklist. Cada fuente que falla queda marcada como no
        disponible; el reporte se arma igual.
    """
    rdb = rdb or _get_redis()
    nodes = nodes if isinstance(nodes, dict) else {"overall": nodes, "components": []}
    now = datetime.now(timezone.utc)
    generated_at = now.isoformat()
    since = now - timedelta(minutes=window_minutes)
    stats = get_stats(window_minutes)
    precision = get_precision_stats(window_minutes)
    total = stats.get("total_decisiones") or 0
    por_decision = stats.get("por_decision", {})
    auto_resuelto = sum(v for k, v in por_decision.items() if k in ("ALLOW", "LOG"))
    settings = get_settings()

    try:
        ustat = users.users_index_status(current_username, rdb)
        by_role = _users_by_role(rdb) if ustat["reliable"] else None
        active_sessions = len(sess.list_all_sessions(rdb)) if ustat["reliable"] else None
    except (redis.RedisError, AttributeError) as e:
        log.error(f"reporte de cumplimiento sin datos de usuarios: {e}")
        ustat, by_role, active_sessions = {"reliable": False, "reason": "Redis no respondió"}, None, None

    chains = audit_view.chain_status(request=request)
    responses = response_counts(since, request)
    shards = shards_diagnosis(request) if nodes.get("overall") != "ok" else {"available": False}
    reconciliation = approvals_reconciliation(since, now, rdb, request)
    regime = regime_at(now)
    pv = policy_version(settings)
    integrity = integrity_panel(chains)
    timings = response_timings(since, request)
    ctx = {"stats": stats, "chains": chains["chains"], "tail_size": chains["tail_size"],
           "responses": responses, "ism": ism_policies_present(request), "nodes_overall": nodes.get("overall"),
           "node_observations": _node_observations(nodes, shards),
           "users_by_role": by_role or {}, "users_index": ustat,
           "active_sessions": active_sessions if active_sessions is not None else "sin dato",
           "reconciliation": reconciliation, "integrity": integrity,
           "generated_at": generated_at, "window_label": WINDOW_LABELS.get(window_minutes, f"ventana de {window_minutes} min"),
           "organizacion_es_oiv": getattr(settings, "organizacion_es_oiv", None),
           "response_mode": getattr(settings.response_mode, "value", str(settings.response_mode))}
    checklist = build_checklist(ctx)
    return {
        "window_minutes": window_minutes,
        "generated_at": generated_at,
        "policy_version": pv,
        "regime": regime,
        "regimes_in_window": regimes_between(since, now),
        "resumen": coverage_summary(checklist, generated_at),
        # Campos del stub original (compatibles).
        "fatiga_alertas_pct": round(100 * auto_resuelto / total, 1) if total else None,
        "latencia_avg_ms": stats.get("latencia_avg_ms"),
        "latencia_p95_ms": stats.get("latencia_p95_ms"),
        "latencia_descripcion": ("Latencia interna del Fast Path: procesamiento del motor, sin red ni Vector; "
                                 "ventana móvil; percentil aproximado de OpenSearch."),
        "precision_bloqueos": precision,
        "corroboracion_sombra": corroboration_shadow(since, request),
        "decisiones": {"available": stats.get("available", False), "total": total,
                       "por_tier": stats.get("por_tier", {})},
        "respuestas": responses,
        "conciliacion_aprobaciones": reconciliation,
        "tiempos": timings,
        "integridad": integrity,
        "historial_diario": daily_history(30, request, now=now),
        "nodos": {"overall": nodes.get("overall"), "observaciones": ctx["node_observations"], "shards": shards},
        "aprobaciones_pendientes": reconciliation.get("pendientes_ahora"),
        "usuarios_por_rol": by_role,
        "indice_usuarios": ustat,
        "sesiones_activas": active_sessions,
        "response_mode": ctx["response_mode"],
        "organizacion_es_oiv": ctx["organizacion_es_oiv"],
        "cadenas": chains,
        "checklist": checklist,
        "mttr_humano": {"available": (timings.get("humano_s") or {}).get("n", 0) > 0,
                        "detail": "Ver tiempos.humano_s: se mide desde H57 con la hora de apertura de la aprobación."},
        "nota_legal": LEGAL_NOTE,
        "nota_alcance": SCOPE_NOTE,
        "exportacion_pdf": {"available": False, "detail": "Pendiente: en docs/ROADMAP_2027.md."},
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

    ADVERTENCIA (H48): desde 2026-10-05 11:56:31 -03 (R1_MIN_TIER=2) las T1
    no generan registro. `evaluated` pierde ~2/3 de sus filas (casi todas IPs
    privadas sin fuentes), así que `sin_corroboracion` baja por cambio de
    denominador, no porque la corroboración mejore. No comparar ventanas que
    crucen ese corte.

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
