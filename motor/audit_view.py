"""
audit_view.py — Historial / auditoría del dashboard (H43).

Lectura pura sobre las dos cadenas append-only que dejaron H39-H42:
- soc-decisions-*  (decisiones del Fast Path, cadena nueva desde el corte de H42)
- soc-decisions    (índice legado, cadena vieja de 4 campos, congelada en el corte)
- soc-responses-*  (auditoría R1/R2, aprobaciones, expiraciones y accesos)

Tres funciones:
1. search_trace(): todo lo que el sistema registró para un trace_id, con la
   verificación del hash de cada documento y de su enlace con el anterior y
   el siguiente de su cadena.
2. chain_status(): verificación en vivo de los últimos CHAIN_TAIL_DOCS
   eslabones de cada cadena con la misma función verify_chain() que usa
   scripts/verify_response_chain.py (se importa, no se reimplementa ni se
   modifica). La verificación COMPLETA sigue siendo el script, corrido en
   .140: recorrer millones de documentos no cabe en una request del panel.
3. access_events(): eventos de acceso persistidos (logins, denegaciones,
   gestión de usuarios), solo CISO.

Ninguna función escribe: cero UPDATE/DELETE (prohibición #6).

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from dashboard import _os_request
from response_audit_indexer import compute_hash, verify_chain

log = logging.getLogger("motor.audit_view")

DECISIONS_PATTERN = "soc-decisions-*"
DECISIONS_LEGACY_INDEX = "soc-decisions"
RESPONSES_PATTERN = "soc-responses-*"

TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")
TRACE_MAX_EVENTS = 200
TRACE_LINK_CHECKS = 20           # eventos con enlace verificado (2 consultas c/u); el resto, solo contenido
CHAIN_TAIL_DOCS = 2_000          # eslabones verificados por cadena en cada consulta
CHAIN_CACHE_SECONDS = 60.0       # paneles abiertos no repiten la verificación
ACCESS_EVENTS_MAX = 500

#: Eventos que un N2 no ve en el historial (vista parcial): son de control de
#: acceso (logins, denegaciones, gestión de cuentas), reservados al CISO.
CISO_ONLY_EVENT_TYPES = {"access"}

OsRequest = Callable[..., "dict | None"]


def valid_trace_id(trace_id: str) -> bool:
    """UUID u otro identificador alfanumérico con guiones (8-64)."""
    return bool(TRACE_ID_PATTERN.fullmatch(trace_id))


def legacy_hash(prev_hash: str, d: dict) -> str:
    """Fórmula de la cadena vieja (H40): solo 4 campos. Misma que
    scripts/verify_decisions_legacy_chain.py:legacy_hash."""
    raw = (prev_hash + d.get("trace_id", "") + d.get("timestamp", "")
           + str(d.get("tier", "")) + str(d.get("risk_score", "")))
    return hashlib.sha256(raw.encode()).hexdigest()


def _hits(result: dict | None) -> list[dict]:
    if result is None:
        return []
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


def _doc_by_seq(pattern: str, seq: int, request: OsRequest) -> dict | None:
    docs = _hits(request("POST", f"/{pattern}/_search",
                         {"size": 1, "query": {"term": {"chain_seq": seq}}}))
    return docs[0] if docs else None


def verify_document(doc: dict, pattern: str, request: OsRequest = _os_request,
                    check_links: bool = True) -> dict[str, Any]:
    """Verifica un documento de una cadena nueva (con chain_seq): su hash
    contra el contenido, y el enlace con el anterior y el siguiente.

    Returns:
        {"content_ok", "prev_link_ok", "next_link_ok", "chain_seq", "hash"};
        un enlace es None si el vecino no existe (cabeza de la cadena, o
        anterior borrado por retención) o si check_links=False.
    """
    hashed = {k: v for k, v in doc.items() if k not in ("prev_hash", "hash")}
    content_ok = compute_hash(hashed, doc.get("prev_hash", "")) == doc.get("hash")
    seq = doc.get("chain_seq")
    prev_ok = next_ok = None
    if check_links and isinstance(seq, int):
        if seq > 1:
            prev = _doc_by_seq(pattern, seq - 1, request)
            prev_ok = None if prev is None else prev.get("hash") == doc.get("prev_hash")
        nxt = _doc_by_seq(pattern, seq + 1, request)
        next_ok = None if nxt is None else nxt.get("prev_hash") == doc.get("hash")
    return {"content_ok": content_ok, "prev_link_ok": prev_ok, "next_link_ok": next_ok,
            "chain_seq": seq, "hash": doc.get("hash"), "prev_hash": doc.get("prev_hash")}


def search_trace(trace_id: str, include_access: bool, request: OsRequest = _os_request) -> dict[str, Any]:
    """Todo lo registrado para un trace_id en las dos cadenas.

    Args:
        trace_id: identificador ya validado con valid_trace_id().
        include_access: True para CISO (eventos de acceso incluidos).
        request: cliente OpenSearch inyectable (tests).

    Returns:
        {"trace_id", "available", "decisions": [...], "events": [...],
         "hidden_events": int}; cada documento con su `verification`.
    """
    term = {"term": {"trace_id": trace_id}}
    new = request("POST", f"/{DECISIONS_PATTERN}/_search", {"size": 10, "query": term})
    legacy = request("POST", f"/{DECISIONS_LEGACY_INDEX}/_search",
                     {"size": 1, "query": {"ids": {"values": [trace_id]}}})
    resp = request("POST", f"/{RESPONSES_PATTERN}/_search", {
        "size": TRACE_MAX_EVENTS, "sort": [{"chain_seq": "asc"}], "query": term})

    decisions = []
    for d in _hits(new):
        decisions.append({"chain": "soc-decisions-*", "doc": d,
                          "verification": verify_document(d, DECISIONS_PATTERN, request)})
    for d in _hits(legacy):
        decisions.append({"chain": "soc-decisions (legado)", "doc": d, "verification": {
            "content_ok": legacy_hash(d.get("prev_hash", ""), d) == d.get("hash"),
            "prev_link_ok": None, "next_link_ok": None, "chain_seq": None,
            "hash": d.get("hash"), "prev_hash": d.get("prev_hash"),
            "note": "Cadena vieja (H40): el hash cubre solo trace_id, timestamp, tier y risk_score.",
        }})

    events, hidden = [], 0
    for e in _hits(resp):
        if not include_access and e.get("event_type") in CISO_ONLY_EVENT_TYPES:
            hidden += 1
            continue
        events.append({"doc": e, "verification": verify_document(
            e, RESPONSES_PATTERN, request, check_links=len(events) < TRACE_LINK_CHECKS)})

    return {"trace_id": trace_id,
            "available": new is not None and resp is not None,
            "decisions": decisions, "events": events, "hidden_events": hidden}


def verify_tail(pattern: str, size: int = CHAIN_TAIL_DOCS, request: OsRequest = _os_request) -> dict[str, Any]:
    """Verifica los últimos `size` + 1 eslabones de una cadena (el más viejo
    hace de ancla para el primer enlace).

    Returns:
        {"pattern", "available", "verified", "from_seq", "to_seq", "ok",
         "problems", "head_hash", "head_time", "cutover"}.
    """
    t0 = time.perf_counter()
    result = request("POST", f"/{pattern}/_search",
                     {"size": size + 1, "sort": [{"chain_seq": "desc"}]})
    out: dict[str, Any] = {"pattern": pattern, "available": result is not None, "verified": 0,
                           "from_seq": None, "to_seq": None, "ok": None, "problems": [],
                           "head_hash": None, "head_time": None, "cutover": None}
    if result is None:
        return out
    docs = list(reversed(_hits(result)))
    if not docs:
        out["ok"] = True
        return out
    problems = verify_chain(docs)
    head = docs[-1]
    out.update(
        verified=len(docs), from_seq=docs[0].get("chain_seq"), to_seq=head.get("chain_seq"), ok=not problems, problems=problems[:20],
        head_hash=head.get("hash"), head_time=head.get("event_time") or head.get("timestamp"),
        duration_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
    first = _hits(request("POST", f"/{pattern}/_search", {
        "size": 1, "sort": [{"chain_seq": "asc"}],
        "_source": ["chain_seq", "prev_hash", "chain_cutover"]}))
    if first:
        out["first_seq"] = first[0].get("chain_seq")
        cut = first[0].get("chain_cutover")
        if cut:
            out["cutover"] = {"legacy_index": cut.get("legacy_index"),
                              "legacy_doc_count": cut.get("legacy_doc_count"),
                              "legacy_head_hash": cut.get("legacy_head_hash"),
                              "cutover_at": cut.get("cutover_at"), "method": cut.get("method"),
                              "prev_hash": first[0].get("prev_hash")}
    return out


_chain_cache: dict[str, Any] = {"at": 0.0, "value": None}
_chain_lock = threading.Lock()


def chain_status(request: OsRequest = _os_request, use_cache: bool = True) -> dict[str, Any]:
    """Verificación en vivo de la cola de ambas cadenas (cache 60 s).

    Returns:
        {"verified_at", "tail_size", "chains": {"responses": {...}, "decisions": {...}}}.
    """
    with _chain_lock:
        if use_cache and _chain_cache["value"] is not None \
                and time.monotonic() - _chain_cache["at"] < CHAIN_CACHE_SECONDS:
            return _chain_cache["value"]
    value = {
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "tail_size": CHAIN_TAIL_DOCS,
        "chains": {
            "responses": verify_tail(RESPONSES_PATTERN, request=request),
            "decisions": verify_tail(DECISIONS_PATTERN, request=request),
        },
        "full_verification": "scripts/verify_response_chain.py (y --pattern \"soc-decisions-*\") en .140",
    }
    with _chain_lock:
        _chain_cache.update(at=time.monotonic(), value=value)
    return value


def access_events(limit: int = 100, username: str | None = None,
                  request: OsRequest = _os_request) -> dict[str, Any]:
    """Eventos de acceso persistidos en soc-responses-* (más recientes primero).

    Args:
        limit: máximo de eventos (acotado a ACCESS_EVENTS_MAX).
        username: filtro opcional por usuario (ya validado por el llamador).

    Returns:
        {"available", "items": [...]}.
    """
    filters: list[dict] = [{"term": {"event_type": "access"}}]
    if username:
        filters.append({"term": {"username": username}})
    result = request("POST", f"/{RESPONSES_PATTERN}/_search", {
        "size": min(limit, ACCESS_EVENTS_MAX), "sort": [{"chain_seq": "desc"}],
        "query": {"bool": {"filter": filters}}})
    items = []
    for d in _hits(result):
        payload = d.get("payload") or {}
        items.append({"event_time": d.get("event_time"), "username": d.get("username"),
                      "access_event": d.get("access_event"), "detail": payload.get("detail") or {},
                      "chain_seq": d.get("chain_seq"), "hash": d.get("hash")})
    return {"available": result is not None, "items": items}
