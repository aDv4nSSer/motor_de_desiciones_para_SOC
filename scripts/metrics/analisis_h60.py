#!/usr/bin/env python3
"""
analisis_h60.py — Tres análisis de solo lectura para las métricas de la tesis (H60).

No cambia ninguna decisión ni escribe en producción. Dos modos:

1. `--extraer` (en .140, desde motor/ para tomar el .env): consulta OpenSearch
   y escribe en stdout tablas CSV crudas, cada una precedida por `## <nombre>`.
2. `--escribir ENTRADA --out DIR` (local): separa las tablas en archivos CSV,
   agrega el régimen (motor/regimes.py) y calcula los derivados (/24,
   campañas, estimación de B, autonomía de C) y un resumen en Markdown.

Análisis:
- A) Infra propia como benigno conocido: decisiones T2/T3 cuyo origen es
  infraestructura propia (misma definición que la safelist de R2:
  is_safelisted exime toda IP privada, loopback o link-local, más
  RESPONSE_SAFELIST_EXTRA). Por día y tier, distribución de ml_score y
  anomaly_score (unidas por trace_id con soc-decisions-*), pares origen y
  puerto dominantes. Salvedad: no representa tráfico externo benigno.
- B) T2 con >= 2 fuentes corroboradas (incluida la caché): IPs por día,
  puertos, /24 y campañas, y cuántas habrían sido bloqueo automático si
  hubieran sido T3. Análisis de sensibilidad, no cambio de política.
- D) Cola de aprobaciones desde el corte de R4 (9-oct 14:21:00Z):
  concentración por /24, % de pendientes de los 5 /24 principales, IPs
  hermanas por campaña y qué fuente falta en cada "1/2 fuentes" (AbuseIPDB
  < 50 o no consultada, OTX sin pulsos). Sin consultar AbuseIPDB: solo lo
  registrado en soc-responses-* y el estado actual de soc:approvals:* en
  Redis (SCARD y SSCAN acotado, nunca SMEMBERS).
- C) Autonomía: bloqueos nuevos separados de TTL extendidos, en IPs
  distintas, y las IPs distintas por hora con la infra propia aparte (el
  complemento de los contadores de 60 min del dashboard, que cuentan
  decisiones).

Límites de lectura (H54, H57): búsquedas paginadas con search_after de a
PAGE documentos, pausa entre páginas, chequeo de heap cada HEAP_EVERY
consultas y aborto si supera --heap-max o si una consulta no responde.

Uso:
    # .140 (una sola conexión SSH, por stdin):
    cd ~/tesis/repo/motor && python3 - --extraer --desde 2026-10-03 < analisis_h60.py > h60.txt
    # local:
    python3 scripts/metrics/analisis_h60.py --escribir h60.txt --out reports/metricas/2026-10-10
    # corrida final: CSV y crudo fuera de git, manifiesto con sha256 en el repo
    python3 scripts/metrics/analisis_h60.py --escribir h60.txt --out reports/metricas/<fecha> \
        --archivar ~/tesis_archivo/metricas_h60

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import itertools
import json
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Por stdin (python3 - < script, desde motor/) el directorio actual ya es motor/.
if Path(__file__).name != "<stdin>":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

DECISIONS = "soc-decisions-*"
RESPONSES = "soc-responses-*"
PAGE = 1000
JOIN_BATCH = 500
PAUSE = 0.3
HEAP_EVERY = 20
MAX_DOCS = 400_000           # tope duro por recorrido; más que esto, se aborta
JOIN_STRIDE = 10             # unión con soc-decisions-* sobre 1 de cada N respuestas de infra (paso fijo)
PROGRESS_EVERY = 20          # una línea de avance a stderr cada N consultas
BINS = [i / 10 for i in range(11)]
PRIVATE_PREFIXES = ["10.", "192.168.", "127.", "169.254.", "fc", "fd", "fe80:", "::1"] + \
    [f"172.{i}." for i in range(16, 32)]
ALREADY_BLOCKED = "ya bloqueada"
CORTE_R4 = "2026-10-09T14:21:00Z"   # régimen R4, apertura del período 2
TOP_REDES = 5
TTL_EXTENDED = "TTL extendido"


class Abort(RuntimeError):
    """Se detiene la extracción (heap, latencia o tope de documentos)."""


# ── Extracción (en .140) ────────────────────────────────────────────────────

class Reader:
    """Consultas a OpenSearch con pausa, chequeo de heap y aborto."""

    def __init__(self, request, heap_max: int) -> None:
        self.request = request
        self.heap_max = heap_max
        self.calls = 0
        self.phase = ""

    def _heap(self) -> int:
        st = self.request("GET", "/_nodes/stats/jvm") or {}
        return max((n["jvm"]["mem"]["heap_used_percent"] for n in st.get("nodes", {}).values()), default=0)

    def search(self, index: str, body: dict) -> dict:
        if self.calls % HEAP_EVERY == 0:
            heap = self._heap()
            if heap > self.heap_max:
                raise Abort(f"heap {heap}% > {self.heap_max}%")
        self.calls += 1
        if self.calls % PROGRESS_EVERY == 0:
            print(f"# avance: {self.calls} consultas, fase {self.phase}, "
                  f"{datetime.now(timezone.utc).strftime('%H:%M:%SZ')}", file=sys.stderr, flush=True)
        t0 = time.monotonic()
        res = self.request("POST", f"/{index}/_search", body)
        if res is None:
            raise Abort(f"OpenSearch no respondió ({index})")
        if time.monotonic() - t0 > 4.0:
            raise Abort("latencia de OpenSearch > 4 s")
        time.sleep(PAUSE)
        return res

    def scroll(self, index: str, query: dict, source: list[str], sort_field: str) -> list[dict]:
        """Todos los documentos de la consulta, de a PAGE, con search_after.
        Cuenta antes de paginar: si pasa MAX_DOCS, aborta sin leer nada."""
        total = self.search(index, {"size": 0, "query": query, "track_total_hits": True})["hits"]["total"]["value"]
        print(f"# {index}: {total} documentos a leer ({self.phase})", file=sys.stderr, flush=True)
        if total > MAX_DOCS:
            raise Abort(f"{total} documentos en {index} > tope {MAX_DOCS}")
        out: list[dict] = []
        after = None
        while True:
            body: dict[str, Any] = {"size": PAGE, "query": query, "_source": source,
                                    "sort": [{sort_field: "asc"}, {"stream_id": "asc"}], "track_total_hits": False}
            if after:
                body["search_after"] = after
            hits = self.search(index, body)["hits"]["hits"]
            out.extend(h["_source"] for h in hits)
            if len(hits) < PAGE:
                return out
            after = hits[-1]["sort"]

    def composite(self, index: str, query: dict, sources: list[dict], aggs: dict | None = None) -> list[dict]:
        """Buckets de una agregación composite, paginada."""
        out: list[dict] = []
        after = None
        while True:
            comp: dict[str, Any] = {"size": PAGE, "sources": sources}
            if after:
                comp["after"] = after
            agg: dict[str, Any] = {"composite": comp}
            if aggs:
                agg["aggs"] = aggs
            res = self.search(index, {"size": 0, "query": query, "aggs": {"c": agg}})
            c = res["aggregations"]["c"]
            out.extend(c["buckets"])
            after = c.get("after_key")
            if not after or len(c["buckets"]) < PAGE:
                return out


def infra_query(safelist: set[str]) -> dict:
    """src_ip de infraestructura propia (definición de is_safelisted)."""
    should: list[dict] = [{"prefix": {"src_ip": p}} for p in PRIVATE_PREFIXES]
    if safelist:
        should.append({"terms": {"src_ip": sorted(safelist)}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _cola_actual(max_items: int = 5000) -> list[dict]:
    """Aprobaciones pendientes hoy en Redis: SCARD (O(1)) y, si son pocas, SSCAN
    acotado (redis_guard) y MGET en lotes. Nunca SMEMBERS (H54)."""
    from dashboard import _get_redis
    from redis_guard import guarded_scan
    rdb = _get_redis()
    total = rdb.scard("soc:approvals:pending")
    if total > max_items:
        return [{"src_ip": "", "created_at": "", "occurrences": "", "approval_level": "",
                 "nota": f"{total} pendientes > tope {max_items}: no se leen"}]
    rows: list[dict] = []
    for batch in guarded_scan(rdb, set_key="soc:approvals:pending"):
        for raw in rdb.mget([f"soc:approvals:{t}" for t in batch]):
            if not raw:
                continue
            a = json.loads(raw)
            if a.get("status") == "pending":
                occ = rdb.hget(f"soc:approvals:meta:{a.get('trace_id')}", "occurrences")
                rows.append({"src_ip": a.get("src_ip"), "created_at": a.get("created_at"),
                             "occurrences": occ or 1, "approval_level": a.get("approval_level"), "nota": ""})
    return rows


def emit(name: str, rows: list[dict], fields: list[str] | None = None) -> None:
    print(f"## {name}")
    keys = fields or (list(rows[0].keys()) if rows else ["vacio"])
    w = csv.DictWriter(sys.stdout, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    sys.stdout.flush()


def extraer(desde: str, hasta: str | None, heap_max: int, stride: int = JOIN_STRIDE) -> int:
    from dashboard import _os_request  # solo en .140: lee el .env del motor
    from response.config import get_settings

    s = get_settings()
    reader = Reader(_os_request, heap_max)
    rng: dict[str, Any] = {"gte": desde}
    if hasta:
        rng["lt"] = hasta
    base = [{"term": {"event_type": "response"}}, {"range": {"event_time": rng}}]
    infra = infra_query(s.safelist)
    emit("parametros", [{
        "desde": desde, "hasta": hasta or "", "extraido_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "min_fuentes_autobloqueo": s.min_corroborating_sources_for_autoblock,
        "stale_max_s": s.stale_event_max_age_seconds, "safelist_extra_n": len(s.safelist),
        "muestra_union_1_de": stride,
    }])

    # Retención: índices diarios presentes y política ISM de cada uno (solo lectura).
    reader.phase = "retencion"
    ism = _os_request("GET", "/_plugins/_ism/explain/soc-responses-*,soc-decisions-*") or {}
    emit("retencion", [{"indice": k, "politica_ism": (v or {}).get("index.plugins.index_state_management.policy_id")
                        or (v or {}).get("policy_id") or "sin política"}
                       for k, v in sorted(ism.items()) if isinstance(v, dict)])

    # Totales por día y tier (todos los T2/T3 y la parte de infra), por agregación.
    day = {"date_histogram": {"field": "event_time", "calendar_interval": "1d"}}
    card = {"cardinality": {"field": "src_ip", "precision_threshold": 40000}}
    res = reader.search(RESPONSES, {"size": 0, "query": {"bool": {"filter": base}}, "aggs": {"d": {**day, "aggs": {
        "t": {"terms": {"field": "tier", "size": 4}, "aggs": {
            "ips": card, "infra": {"filter": infra, "aggs": {"ips": card}}}}}}}})
    emit("tier_por_dia", [
        {"dia_utc": d["key_as_string"][:10], "tier": t["key"], "docs": t["doc_count"], "ips": t["ips"]["value"],
         "docs_infra": t["infra"]["doc_count"], "ips_infra": t["infra"]["ips"]["value"]}
        for d in res["aggregations"]["d"]["buckets"] for t in d["t"]["buckets"]])

    # A) Infra propia: lectura completa de las respuestas T2/T3 (conteos y pares exactos);
    # la unión con la decisión (ml_score, anomaly_score) solo sobre 1 de cada `stride`.
    reader.phase = "A lectura"
    docs = reader.scroll(RESPONSES, {"bool": {"filter": [*base, infra, {"terms": {"tier": [2, 3]}}]}},
                         ["trace_id", "event_time", "src_ip", "tier", "accion_recomendada", "payload.dst_port",
                          "payload.dst_ip"], "event_time")
    dec: dict[str, dict] = {}
    reader.phase = "A union (muestra)"
    ids = [d["trace_id"] for i, d in enumerate(docs) if d.get("trace_id") and i % stride == 0]
    print(f"# A: {len(docs)} respuestas, {len(ids)} en la muestra de la unión", file=sys.stderr, flush=True)
    for i in range(0, len(ids), JOIN_BATCH):
        batch = ids[i:i + JOIN_BATCH]
        hits = reader.search(DECISIONS, {"size": len(batch), "query": {"terms": {"trace_id": batch}},
                                         "_source": ["trace_id", "ml_score", "anomaly_score", "risk_score", "L4_DST_PORT"]})
        for h in hits["hits"]["hits"]:
            dec[h["_source"]["trace_id"]] = h["_source"]
    emit("infra_docs", [{
        "event_time": d.get("event_time"), "src_ip": d.get("src_ip"), "tier": d.get("tier"),
        "accion": d.get("accion_recomendada"), "dst_ip": (d.get("payload") or {}).get("dst_ip") or "",
        "dst_port": (d.get("payload") or {}).get("dst_port") or dec.get(d.get("trace_id"), {}).get("L4_DST_PORT"),
        "ml_score": dec.get(d.get("trace_id"), {}).get("ml_score"),
        "anomaly_score": dec.get(d.get("trace_id"), {}).get("anomaly_score"),
        "risk_score": dec.get(d.get("trace_id"), {}).get("risk_score"),
    } for d in docs], ["event_time", "src_ip", "tier", "accion", "dst_ip", "dst_port", "ml_score", "anomaly_score",
                       "risk_score"])

    reader.phase = "B"
    # B) T2 con >= 2 fuentes corroborando (corroboration_count cuenta la caché).
    t2 = reader.scroll(RESPONSES, {"bool": {"filter": [*base, {"term": {"tier": 2}},
                                                      {"range": {"corroboration_count": {"gte": 2}}}],
                                            "must_not": [infra]}},
                       ["trace_id", "event_time", "src_ip", "case_id", "event_age_seconds", "payload.dst_port",
                        "payload.enrichment.abuseipdb_score", "payload.enrichment.otx_pulse_count",
                        "payload.enrichment.corroborating_sources", "payload.enrichment.cached"], "event_time")
    emit("t2_corroboradas_docs", [{
        "event_time": d.get("event_time"), "src_ip": d.get("src_ip"), "trace_id": d.get("trace_id"),
        "dst_port": (d.get("payload") or {}).get("dst_port"),
        "abuseipdb": ((d.get("payload") or {}).get("enrichment") or {}).get("abuseipdb_score"),
        "otx": ((d.get("payload") or {}).get("enrichment") or {}).get("otx_pulse_count"),
        "fuentes": "+".join(((d.get("payload") or {}).get("enrichment") or {}).get("corroborating_sources") or []),
        "cache": ((d.get("payload") or {}).get("enrichment") or {}).get("cached"),
        "event_age_s": d.get("event_age_seconds"), "case_id": d.get("case_id") or "",
    } for d in t2], ["event_time", "src_ip", "trace_id", "dst_port", "abuseipdb", "otx", "fuentes", "cache",
                     "event_age_s", "case_id"])

    reader.phase = "C"
    # C) T3 por IP y día: bloqueo nuevo, TTL extendido, pendiente, infra.
    t3 = reader.composite(RESPONSES, {"bool": {"filter": [*base, {"term": {"tier": 3}}], "must_not": [infra]}},
                          [{"dia": {"date_histogram": {"field": "event_time", "calendar_interval": "1d"}}},
                           {"ip": {"terms": {"field": "src_ip"}}}],
                          {"nuevo": {"filter": {"bool": {"filter": [{"term": {"block_action": "block"}},
                                                                   {"term": {"block_enforced": True}}]}}},
                           "ext": {"filter": {"prefix": {"block_reason": ALREADY_BLOCKED}}},
                           "pend": {"filter": {"term": {"block_action": "block_pending_approval"}}}})
    emit("t3_ip_dia", [{
        "dia_utc": datetime.fromtimestamp(b["key"]["dia"] / 1000, timezone.utc).date().isoformat(), "src_ip": b["key"]["ip"],
        "docs": b["doc_count"], "bloqueo_nuevo": b["nuevo"]["doc_count"], "ttl_extendido": b["ext"]["doc_count"],
        "pendiente": b["pend"]["doc_count"]} for b in t3])
    bl = reader.composite(RESPONSES, {"bool": {"filter": [*base, {"term": {"block_action": "block"}},
                                                          {"term": {"block_enforced": True}}]}},
                          [{"ip": {"terms": {"field": "src_ip"}}}], {"primero": {"min": {"field": "event_time"}}})
    emit("ips_autobloqueadas", [{"src_ip": b["key"]["ip"], "primer_bloqueo": b["primero"].get("value_as_string")}
                                for b in bl])
    manual = reader.search(RESPONSES, {"size": 0, "query": {"bool": {"filter": [
        {"term": {"event_type": "manual_approval"}}, {"range": {"event_time": rng}}]}},
        "aggs": {"d": {**day, "aggs": {"ips": card, "ok": {"filter": {"term": {"block_enforced": True}}}}}}})
    emit("aprobaciones_manuales_por_dia", [{"dia_utc": d["key_as_string"][:10], "docs": d["doc_count"],
                                            "ips": d["ips"]["value"], "ejecutadas": d["ok"]["doc_count"]}
                                           for d in manual["aggregations"]["d"]["buckets"]])

    # D) Cola de aprobaciones desde el corte de R4: cada T3 que quedó pendiente, con
    # lo que vio R1 (sin consultar AbuseIPDB), el destino por IP y el estado actual en Redis.
    reader.phase = "D"
    since_d: dict[str, Any] = {"gte": max(desde, CORTE_R4)}
    if hasta:
        since_d["lt"] = hasta
    pend = reader.scroll(RESPONSES, {"bool": {"filter": [
        {"term": {"event_type": "response"}}, {"range": {"event_time": since_d}}, {"term": {"tier": 3}},
        {"term": {"block_action": "block_pending_approval"}}], "must_not": [infra]}},
        ["event_time", "src_ip", "trace_id", "corroboration_count", "payload.dst_port",
         "payload.enrichment.abuseipdb_score", "payload.enrichment.abuseipdb_available",
         "payload.enrichment.otx_pulse_count", "payload.enrichment.otx_available",
         "payload.enrichment.corroborating_sources", "payload.enrichment.notes"], "event_time")

    def _enr(d: dict) -> dict:
        return (d.get("payload") or {}).get("enrichment") or {}

    emit("d_pendientes_docs", [{
        "event_time": d.get("event_time"), "src_ip": d.get("src_ip"), "trace_id": d.get("trace_id"),
        "dst_port": (d.get("payload") or {}).get("dst_port"), "count": d.get("corroboration_count"),
        "abuseipdb": _enr(d).get("abuseipdb_score"), "abuseipdb_disponible": _enr(d).get("abuseipdb_available"),
        "otx": _enr(d).get("otx_pulse_count"), "otx_disponible": _enr(d).get("otx_available"),
        "fuentes": "+".join(_enr(d).get("corroborating_sources") or []),
        "nota_abuseipdb": next((n for n in _enr(d).get("notes") or [] if str(n).startswith("abuseipdb")), ""),
        "nota_otx": next((n for n in _enr(d).get("notes") or [] if str(n).startswith("otx")), ""),
    } for d in pend])
    ips_d = reader.composite(RESPONSES, {"bool": {"filter": [
        {"term": {"event_type": "response"}}, {"range": {"event_time": since_d}}, {"terms": {"tier": [2, 3]}}],
        "must_not": [infra]}}, [{"ip": {"terms": {"field": "src_ip"}}}],
        {"t2": {"filter": {"term": {"tier": 2}}}, "t3": {"filter": {"term": {"tier": 3}}},
         "bloqueo": {"filter": {"bool": {"filter": [{"term": {"block_action": "block"}},
                                                    {"term": {"block_enforced": True}}]}}},
         "ext": {"filter": {"prefix": {"block_reason": ALREADY_BLOCKED}}},
         "pend": {"filter": {"term": {"block_action": "block_pending_approval"}}}})
    emit("d_ips_desde_corte", [{"src_ip": b["key"]["ip"], "docs": b["doc_count"], "t2": b["t2"]["doc_count"],
                                "t3": b["t3"]["doc_count"], "bloqueo": b["bloqueo"]["doc_count"],
                                "ttl_extendido": b["ext"]["doc_count"], "pendiente": b["pend"]["doc_count"]}
                               for b in ips_d])
    resol = reader.composite(RESPONSES, {"bool": {"filter": [{"range": {"event_time": since_d}}, {"terms": {
        "event_type": ["approval_expired", "manual_approval", "approval_rejected"]}}]}},
        [{"ip": {"terms": {"field": "src_ip"}}}, {"ev": {"terms": {"field": "event_type"}}}])
    emit("d_resoluciones", [{"src_ip": b["key"]["ip"], "evento": b["key"]["ev"], "docs": b["doc_count"]} for b in resol])
    emit("d_cola_actual", _cola_actual())

    reader.phase = "C horas"
    # C) IPs distintas por hora con la infra aparte (complemento de los contadores de 60 min).
    hour = {"date_histogram": {"field": "event_time", "fixed_interval": "1h"}}
    res = reader.search(RESPONSES, {"size": 0, "query": {"bool": {"filter": base}}, "aggs": {"h": {**hour, "aggs": {
        "t": {"terms": {"field": "tier", "size": 4}, "aggs": {
            "ext": {"filter": {"bool": {"must_not": [infra]}}, "aggs": {"ips": card}},
            "infra": {"filter": infra, "aggs": {"ips": card}}}}}}}})
    emit("ips_por_hora", [
        {"hora_utc": h["key_as_string"], "tier": t["key"], "decisiones": t["doc_count"],
         "decisiones_externas": t["ext"]["doc_count"], "ips_externas": t["ext"]["ips"]["value"],
         "decisiones_infra": t["infra"]["doc_count"], "ips_infra": t["infra"]["ips"]["value"]}
        for h in res["aggregations"]["h"]["buckets"] for t in h["t"]["buckets"]])
    print(f"# consultas: {reader.calls}", file=sys.stderr)
    return 0


# ── Escritura local ─────────────────────────────────────────────────────────

def read_sections(text: str) -> dict[str, list[dict[str, str]]]:
    """Separa la salida cruda en tablas por `## nombre`."""
    out: dict[str, list[dict[str, str]]] = {}
    name, buf = None, []
    for line in text.splitlines():
        if line.startswith("## "):
            if name:
                out[name] = list(csv.DictReader(io.StringIO("\n".join(buf))))
            name, buf = line[3:].strip(), []
        elif name is not None:
            buf.append(line)
    if name:
        out[name] = list(csv.DictReader(io.StringIO("\n".join(buf))))
    return out


def _f(x: str | None) -> float | None:
    try:
        return float(x) if x not in (None, "") else None
    except ValueError:
        return None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * (len(v) - 1) + 0.5))], 4)


def net24(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))


def _dt(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
    except ValueError:
        return None


def regime_of(ts: str) -> str:
    from regimes import regime_at
    d = _dt(ts)
    if d is None:
        return ""
    r = regime_at(d)
    return r["id"] if r else "pre-R0"


def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    keys = fields or (list(rows[0].keys()) if rows else ["vacio"])
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def analisis_a(sec: dict) -> tuple[dict[str, list[dict]], list[str]]:
    docs = sec.get("infra_docs", [])
    totals = {(r["dia_utc"], r["tier"]): r for r in sec.get("tier_por_dia", [])}
    by_day: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for d in docs:
        by_day[(d["event_time"][:10], d["tier"])].append(d)
    dia = []
    for (day, tier), rows in sorted(by_day.items()):
        ml = [v for r in rows if (v := _f(r["ml_score"])) is not None]
        an = [v for r in rows if (v := _f(r["anomaly_score"])) is not None]
        tot = totals.get((day, tier), {})
        n_tot = int(tot.get("docs") or 0)
        dia.append({"dia_utc": day, "tier": tier, "decisiones_infra": len(rows),
                    "decisiones_tier": n_tot, "pct_infra": round(100 * len(rows) / n_tot, 2) if n_tot else None,
                    "ips_infra": len({r["src_ip"] for r in rows}), "unidas_a_decision": len(ml),
                    "ml_p10": _pct(ml, .1), "ml_p50": _pct(ml, .5), "ml_p90": _pct(ml, .9),
                    "anom_p10": _pct(an, .1), "anom_p50": _pct(an, .5), "anom_p90": _pct(an, .9),
                    "regimen_inicio_dia": regime_of(f"{day}T00:00:00+00:00")})
    hist = []
    for var in ("ml_score", "anomaly_score"):
        vals = [v for r in docs if (v := _f(r[var])) is not None]
        for lo, hi in itertools.pairwise(BINS):
            n = sum(1 for v in vals if lo <= v < hi or (hi == 1.0 and v == 1.0))
            hist.append({"variable": var, "desde": lo, "hasta": hi, "decisiones": n,
                         "pct": round(100 * n / len(vals), 2) if vals else None})
    pairs = Counter((d["src_ip"], d["dst_port"]) for d in docs)
    tiers = defaultdict(Counter)
    for d in docs:
        tiers[(d["src_ip"], d["dst_port"])][d["tier"]] += 1
    pares = [{"src_ip": ip, "dst_port": port, "decisiones": n, "t2": tiers[(ip, port)]["2"], "t3": tiers[(ip, port)]["3"],
              "pct_del_total_infra": round(100 * n / len(docs), 2)} for (ip, port), n in pairs.most_common(30)]
    flujos_c = Counter((d["src_ip"], d.get("dst_ip", ""), d["dst_port"]) for d in docs)
    ftier = defaultdict(Counter)
    fseen: dict[tuple, list[str]] = {}
    for d in docs:
        k = (d["src_ip"], d.get("dst_ip", ""), d["dst_port"])
        ftier[k][d["tier"]] += 1
        fs = fseen.setdefault(k, [d["event_time"], d["event_time"]])
        fs[0], fs[1] = min(fs[0], d["event_time"]), max(fs[1], d["event_time"])
    flujos = [{"src_ip": k[0], "dst_ip": k[1] or "sin dato", "dst_port": k[2], "decisiones": n,
               "t2": ftier[k]["2"], "t3": ftier[k]["3"], "primera": fseen[k][0], "ultima": fseen[k][1],
               "pct_del_total_infra": round(100 * n / len(docs), 2)} for k, n in flujos_c.most_common()]
    flujos_dia = []
    for day in sorted({d["event_time"][:10] for d in docs}):
        dd = [d for d in docs if d["event_time"][:10] == day]
        for tier in sorted({d["tier"] for d in dd}):
            dt = [d for d in dd if d["tier"] == tier]
            flujos_dia.append({"dia_utc": day, "tier": tier, "decisiones": len(dt),
                               "flujos_distintos": len({(d["src_ip"], d.get("dst_ip", ""), d["dst_port"]) for d in dt}),
                               "origenes": len({d["src_ip"] for d in dt})})
    t23_total = sum(int(r["docs"]) for r in sec.get("tier_por_dia", []) if r["tier"] in ("2", "3"))
    stride = (sec.get("parametros") or [{}])[0].get("muestra_union_1_de") or "1"
    n_join = sum(1 for d in docs if _f(d["ml_score"]) is not None)
    resumen = [
        ("NO ES UNA TASA DE FALSOS POSITIVOS SOBRE TRÁFICO EXTERNO: mide cuánto tráfico propio, benigno y conocido, "
         "el modelo lleva a T2/T3."),
        (f"Flujos distintos (origen, destino, puerto): {len(flujos)}; los 5 principales concentran "
         f"{round(100 * sum(f['decisiones'] for f in flujos[:5]) / len(docs), 1) if docs else 0}% de las decisiones de infra. "
         "Una decisión por flujo repetido no es un evento independiente: la vista por flujo es la unidad comparable."),
        (f"Decisiones T2/T3 de infra propia: {len(docs)} de {t23_total} T2/T3 "
        f"({round(100 * len(docs) / t23_total, 2) if t23_total else 'sin dato'}%), {len({d['src_ip'] for d in docs})} IPs."),
        ("Tasa de falsos positivos del modelo sobre ese conjunto: toda decisión T2/T3 de infra propia es un falso positivo "
        "del umbral de T2 (tráfico propio conocido como benigno). Las decisiones T0/T1 de infra no tienen src_ip en "
        "soc-decisions-*, así que la tasa sobre todo el tráfico propio no es medible con estos índices."),
        (f"Conteos, IPs y pares origen y puerto: exactos, sobre todas las respuestas. Percentiles e histograma de "
         f"ml_score y anomaly_score: muestra de 1 de cada {stride} respuestas (paso fijo en orden de tiempo), "
         f"{n_join} decisiones unidas por trace_id."),
        ("Salvedad: la infra propia es benigno conocido de un tipo muy particular (API de Wazuh, gestión, bastion); "
        "no representa tráfico externo benigno y no sirve para estimar la tasa de falsos positivos sobre Internet."),
    ]
    return {"a_infra_por_dia.csv": dia, "a_infra_histograma.csv": hist, "a_infra_pares.csv": pares,
            "a_infra_flujos.csv": flujos, "a_infra_flujos_por_dia.csv": flujos_dia}, resumen


def analisis_b(sec: dict) -> tuple[dict[str, list[dict]], list[str]]:
    docs = sec.get("t2_corroboradas_docs", [])
    params = (sec.get("parametros") or [{}])[0]
    stale = _f(params.get("stale_max_s")) or 3600
    blocked = {r["src_ip"]: r["primer_bloqueo"] for r in sec.get("ips_autobloqueadas", [])}
    per_ip: dict[str, dict[str, Any]] = {}
    for d in docs:
        ip = d["src_ip"]
        e = per_ip.setdefault(ip, {"src_ip": ip, "net24": net24(ip), "decisiones": 0, "primera": d["event_time"],
                                   "ultima": d["event_time"], "puertos": Counter(), "abuseipdb_max": None,
                                   "otx_max": None, "fuentes": set(), "no_stale": 0, "dias": set()})
        e["decisiones"] += 1
        e["ultima"] = max(e["ultima"], d["event_time"], key=lambda x: _dt(x) or datetime.min.replace(tzinfo=timezone.utc))
        e["primera"] = min(e["primera"], d["event_time"], key=lambda x: _dt(x) or datetime.max.replace(tzinfo=timezone.utc))
        e["puertos"][d["dst_port"]] += 1
        e["dias"].add(d["event_time"][:10])
        for k, src in (("abuseipdb_max", "abuseipdb"), ("otx_max", "otx")):
            v = _f(d[src])
            if v is not None:
                e[k] = v if e[k] is None else max(e[k], v)
        e["fuentes"].update(x for x in d["fuentes"].split("+") if x)
        age = _f(d["event_age_s"])
        if age is None or age <= stale:
            e["no_stale"] += 1
    ips = []
    for e in sorted(per_ip.values(), key=lambda x: -x["decisiones"]):
        first_block = blocked.get(e["src_ip"])
        fb, fp = _dt(first_block), _dt(e["primera"])
        already = bool(fb and fp and fb <= fp)
        would = e["no_stale"] > 0
        ips.append({**{k: e[k] for k in ("src_ip", "net24", "decisiones", "primera", "ultima", "abuseipdb_max", "otx_max")},
                    "puertos": " ".join(f"{p}:{n}" for p, n in e["puertos"].most_common(5)),
                    "fuentes": "+".join(sorted(e["fuentes"])), "regimen_primera": regime_of(e["primera"]),
                    "autobloqueada_alguna_vez": bool(first_block), "ya_bloqueada_antes": already,
                    "seria_bloqueo_automatico_si_t3": would and not already,
                    "seria_ttl_extendido_si_t3": would and already})
    dia = []
    for day in sorted({d["event_time"][:10] for d in docs}):
        day_ips = {d["src_ip"] for d in docs if d["event_time"][:10] == day}
        dia.append({"dia_utc": day, "decisiones": sum(1 for d in docs if d["event_time"][:10] == day),
                    "ips": len(day_ips), "redes_24": len({net24(i) for i in day_ips}),
                    "ips_nunca_autobloqueadas": len([i for i in day_ips if i not in blocked])})
    nets: dict[str, dict[str, Any]] = {}
    for r in ips:
        n = nets.setdefault(r["net24"], {"net24": r["net24"], "ips": 0, "decisiones": 0, "puertos": Counter(),
                                         "primera": r["primera"], "ultima": r["ultima"]})
        n["ips"] += 1
        n["decisiones"] += r["decisiones"]
        n["primera"] = min(n["primera"], r["primera"])
        n["ultima"] = max(n["ultima"], r["ultima"])
        for tok in r["puertos"].split():
            p, c = tok.rsplit(":", 1)
            n["puertos"][p] += int(c)
    redes = [{**{k: v for k, v in n.items() if k != "puertos"},
              "puertos": " ".join(f"{p}:{c}" for p, c in n["puertos"].most_common(5)),
              "campana_candidata": n["ips"] >= 2}
             for n in sorted(nets.values(), key=lambda x: (-x["ips"], -x["decisiones"]))]
    nuevas = sum(1 for r in ips if r["seria_bloqueo_automatico_si_t3"])
    ext = sum(1 for r in ips if r["seria_ttl_extendido_si_t3"])
    resumen = [
        (f"T2 con >= 2 fuentes corroborando: {len(docs)} decisiones, {len(ips)} IPs, {len(nets)} redes /24, "
        f"{sum(1 for r in redes if r['campana_candidata'])} /24 con 2 o más IPs (campaña candidata)."),
        (f"Si hubieran sido T3 (regla R2-CORROBORADO, mínimo {params.get('min_fuentes_autobloqueo', 2)} fuentes): "
        f"{nuevas} IPs serían bloqueo automático nuevo y {ext} ya estaban bloqueadas (TTL extendido). "
        f"Se excluyen las IPs con todos sus eventos más viejos que {int(stale)} s (R2 no actúa sobre eventos antiguos)."),
        "Cobertura: corroboration_count es buscable en soc-responses-* desde H52 (fe58bdb, 7-oct); antes no hay datos para B.",
        ("Es análisis de sensibilidad sobre lo registrado, no un cambio de política: la regla de tier no se toca en esta "
        "tesis. Cota superior: supone que la corroboración observada en T2 (incluida la caché) se habría repetido en T3."),
    ]
    return {"b_t2_corroboradas_por_dia.csv": dia, "b_t2_corroboradas_ips.csv": ips, "b_t2_corroboradas_redes24.csv": redes}, resumen


def analisis_c(sec: dict) -> tuple[dict[str, list[dict]], list[str]]:
    rows = sec.get("t3_ip_dia", [])
    by_day: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for r in rows:
        s = by_day[r["dia_utc"]]
        s["t3"].add(r["src_ip"])
        if int(r["bloqueo_nuevo"]):
            s["nuevo"].add(r["src_ip"])
        if int(r["ttl_extendido"]):
            s["ext"].add(r["src_ip"])
        if int(r["pendiente"]):
            s["pend"].add(r["src_ip"])
    manual = {r["dia_utc"]: r for r in sec.get("aprobaciones_manuales_por_dia", [])}
    # Primer bloqueo automático de cada IP en toda la ventana: separa la IP nunca
    # bloqueada antes de la que vuelve a bloquearse cuando venció el TTL del bloqueo.
    first_day = {r["src_ip"]: (r["primer_bloqueo"] or "")[:10] for r in sec.get("ips_autobloqueadas", [])}
    dia = []
    for day in sorted(by_day):
        s = by_day[day]
        resueltas = s["nuevo"] | s["ext"]
        dia.append({"dia_utc": day, "ips_t3_externas": len(s["t3"]), "ips_bloqueo_nuevo": len(s["nuevo"]),
                    "ips_primer_bloqueo_en_ventana": len({i for i in s["nuevo"] if first_day.get(i) == day}),
                    "ips_rebloqueo_tras_vencer_ttl": len({i for i in s["nuevo"] if first_day.get(i, day) < day}),
                    "ips_ttl_extendido": len(s["ext"]), "ips_solo_ttl_extendido": len(s["ext"] - s["nuevo"]),
                    "ips_resueltas_automatico": len(resueltas),
                    "ips_pendientes_aprobacion": len(s["pend"] - resueltas),
                    "pct_autonomia_bloqueo_nuevo": round(100 * len(s["nuevo"]) / len(s["t3"]), 2) if s["t3"] else None,
                    "pct_autonomia_incl_ttl": round(100 * len(resueltas) / len(s["t3"]), 2) if s["t3"] else None,
                    "aprobaciones_manuales_ejecutadas": (manual.get(day) or {}).get("ejecutadas", 0),
                    "regimen_inicio_dia": regime_of(f"{day}T00:00:00+00:00")})
    hora = [{**r, "regimen": regime_of(r["hora_utc"])} for r in sec.get("ips_por_hora", [])]
    tot_new = sum(d["ips_bloqueo_nuevo"] for d in dia)
    tot_first = sum(d["ips_primer_bloqueo_en_ventana"] for d in dia)
    tot_re = sum(d["ips_rebloqueo_tras_vencer_ttl"] for d in dia)
    tot_ext = sum(d["ips_ttl_extendido"] for d in dia)
    tot_solo = sum(d["ips_solo_ttl_extendido"] for d in dia)
    resumen = [
        (f"Autonomía (IPs distintas por día UTC, sin infra propia): {tot_new} IP-día con al menos un bloqueo ejecutado; "
         f"de ellas, {tot_first} son la primera vez que la IP se bloquea en la ventana y {tot_re} son re-bloqueos de IPs "
         f"ya bloqueadas otro día, después de vencer el TTL del bloqueo. {tot_ext} IP-día tuvieron además TTL extendido "
         f"y {tot_solo} solo TTL extendido."),
        ("Lectura: la IP que sigue atacando se re-bloquea cuando vence el TTL, así que los bloqueos ejecutados por día no "
         "miden IPs nuevas. Para autonomía sobre amenazas nuevas usar ips_primer_bloqueo_en_ventana; el primer día de la "
         "ventana incluye IPs que ya venían bloqueadas de antes del 3-oct."),
        ("ips_por_hora complementa los contadores de 60 min del dashboard (que cuentan decisiones): por hora y tier, "
        "decisiones e IPs distintas, con la infra propia aparte. Solo T2/T3: T0/T1 no tienen src_ip registrado."),
        "Cardinalidades con precision_threshold 40000 (exactas en estos volúmenes por IP y hora).",
    ]
    return {"c_autonomia_por_dia.csv": dia, "c_ips_por_hora.csv": hora}, resumen


def fuente_faltante(d: dict[str, str]) -> str:
    """Qué fuente falta en una aprobación pendiente (umbrales de R1: AbuseIPDB >= 50,
    OTX >= 1 pulso). Solo con lo registrado; no consulta ninguna API."""
    fuentes = set(filter(None, (d.get("fuentes") or "").split("+")))
    if len(fuentes) >= 2:
        return "dos fuentes (no debería estar pendiente)"
    falta = []
    if "abuseipdb" not in fuentes:
        score = _f(d.get("abuseipdb"))
        nota = d.get("nota_abuseipdb") or ""
        if score is not None:
            falta.append("AbuseIPDB < 50")
        elif "presupuesto" in nota:
            falta.append("AbuseIPDB no consultada (presupuesto de la ventana agotado)")
        elif "no decisiva" in nota:
            falta.append("AbuseIPDB no consultada (no decisiva: OTX no corrobora)")
        elif "throttling" in nota or "cuota" in nota or "r2_min_tier" in nota:
            falta.append("AbuseIPDB no consultada (política de cuota)")
        elif "stale" in nota:
            falta.append("AbuseIPDB no consultada (evento antiguo)")
        else:
            falta.append("AbuseIPDB sin dato (error o sin motivo)")
    if "otx" not in fuentes:
        pulses = _f(d.get("otx"))
        if pulses is not None and pulses < 1:
            falta.append("OTX sin pulsos")
        elif pulses is None:
            falta.append("OTX sin dato (no disponible)")
    return " y ".join(falta) if falta else "sin dato"


def analisis_d(sec: dict) -> tuple[dict[str, list[dict]], list[str]]:
    docs = sec.get("d_pendientes_docs", [])
    if not docs:
        return {}, ["Sin datos de la cola de aprobaciones en la extracción (correr --extraer con la versión H60)."]
    por_ip: dict[str, dict] = {}
    for d in docs:   # el último registro de cada IP describe su estado en R1
        e = por_ip.get(d["src_ip"])
        if e is None or (_dt(d["event_time"]) or datetime.min.replace(tzinfo=timezone.utc)) >= e["_t"]:
            por_ip[d["src_ip"]] = {**d, "_t": _dt(d["event_time"]) or datetime.min.replace(tzinfo=timezone.utc)}
    n_docs = Counter(d["src_ip"] for d in docs)
    ips_info = {r["src_ip"]: r for r in sec.get("d_ips_desde_corte", [])}
    resol = defaultdict(Counter)
    for r in sec.get("d_resoluciones", []):
        resol[r["src_ip"]][r["evento"]] += int(r["docs"])
    actual = {r["src_ip"]: r for r in sec.get("d_cola_actual", []) if r.get("src_ip")}
    redes: dict[str, dict] = {}
    for ip, d in por_ip.items():
        n = redes.setdefault(net24(ip), {"net24": net24(ip), "ips_en_cola": 0, "registros_pendientes": 0,
                                         "pendientes_ahora": 0, "faltante": Counter()})
        n["ips_en_cola"] += 1
        n["registros_pendientes"] += n_docs[ip]
        n["pendientes_ahora"] += int(ip in actual)
        n["faltante"][fuente_faltante(d)] += 1
    total_ips = len(por_ip)
    total_reg = len(docs)
    total_now = len(actual)
    orden = sorted(redes.values(), key=lambda x: (-x["ips_en_cola"], -x["registros_pendientes"]))
    hermanas_by_net = defaultdict(list)
    for ip, r in ips_info.items():
        hermanas_by_net[net24(ip)].append((ip, r))
    tabla_redes, hermanas = [], []
    for rank, n in enumerate(orden, 1):
        sis = hermanas_by_net.get(n["net24"], [])
        tabla_redes.append({
            "rank": rank, "net24": n["net24"], "ips_en_cola": n["ips_en_cola"],
            "pct_ips_en_cola": round(100 * n["ips_en_cola"] / total_ips, 2),
            "registros_pendientes": n["registros_pendientes"],
            "pct_registros": round(100 * n["registros_pendientes"] / total_reg, 2),
            "pendientes_ahora": n["pendientes_ahora"],
            "ips_hermanas_t2_t3": len(sis),
            "hermanas_autobloqueadas": sum(1 for _, r in sis if int(r["bloqueo"]) or int(r["ttl_extendido"])),
            "hermanas_solo_t2": sum(1 for _, r in sis if int(r["t3"]) == 0),
            "fuente_faltante": "; ".join(f"{k}: {v}" for k, v in n["faltante"].most_common()),
            "campana_candidata": len(sis) >= 2,
        })
        if rank <= TOP_REDES:
            for ip, r in sorted(sis, key=lambda x: -int(x[1]["docs"])):
                hermanas.append({"net24": n["net24"], "src_ip": ip, "en_cola": ip in por_ip,
                                 "pendiente_ahora": ip in actual, "t2": r["t2"], "t3": r["t3"],
                                 "autobloqueos": r["bloqueo"], "ttl_extendido": r["ttl_extendido"],
                                 "registros_pendientes": r["pendiente"],
                                 "expiradas": resol[ip]["approval_expired"],
                                 "aprobadas": resol[ip]["manual_approval"], "rechazadas": resol[ip]["approval_rejected"],
                                 "fuente_faltante": fuente_faltante(por_ip[ip]) if ip in por_ip else ""})
    ips_rows = [{"src_ip": ip, "net24": net24(ip), "registros_pendientes": n_docs[ip], "ultimo": d["event_time"],
                 "puerto_ultimo": d["dst_port"], "abuseipdb": d["abuseipdb"], "otx": d["otx"],
                 "fuentes": d["fuentes"], "fuente_faltante": fuente_faltante(d), "pendiente_ahora": ip in actual,
                 "expiradas": resol[ip]["approval_expired"], "aprobadas": resol[ip]["manual_approval"],
                 "rechazadas": resol[ip]["approval_rejected"]}
                for ip, d in sorted(por_ip.items(), key=lambda x: -n_docs[x[0]])]
    falt = Counter(fuente_faltante(d) for d in por_ip.values())
    top = orden[:TOP_REDES]
    top_ips = sum(n["ips_en_cola"] for n in top)
    top_now = sum(n["pendientes_ahora"] for n in top)
    resumen = [
        (f"Desde el corte de R4 ({CORTE_R4}): {total_reg} registros T3 pendientes de aprobación, {total_ips} IPs, "
         f"{len(redes)} redes /24. Pendientes en Redis al extraer: {total_now}."),
        (f"Los {TOP_REDES} /24 principales concentran {top_ips} de {total_ips} IPs en cola "
         f"({round(100 * top_ips / total_ips, 1) if total_ips else 0}%) y {top_now} de {total_now} pendientes actuales "
         f"({round(100 * top_now / total_now, 1) if total_now else 0}%): "
         + ", ".join(f"{n['net24']} ({n['ips_en_cola']})" for n in top) + "."),
        "Fuente que falta, por IP (último registro): " + "; ".join(f"{k}: {v}" for k, v in falt.most_common()) + ".",
        ("IPs hermanas: otras IPs del mismo /24 con T2 o T3 desde el corte, con su desenlace (autobloqueo, TTL "
         "extendido, solo T2). Sin consultar AbuseIPDB: lo que se ve es lo que R1 registró."),
    ]
    return {"d_cola_por_red24.csv": tabla_redes, "d_cola_ips.csv": ips_rows,
            "d_hermanas_top5.csv": hermanas}, resumen


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inside_git(path: Path) -> bool:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],  # nosec B603 B607 - comando fijo
                           capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.stdout.strip() == "true"


def escribir(entrada: Path, out: Path, archivo: Path | None = None) -> int:
    sec = read_sections(entrada.read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    params = (sec.get("parametros") or [{}])[0]
    csv_dir = out
    if archivo is not None:
        stamp = (params.get("extraido_utc") or "sin_fecha").replace(":", "").replace("+0000", "Z")[:17]
        csv_dir = archivo.expanduser().resolve() / f"h60_{stamp}"
        ancestor = next(p for p in (csv_dir, *csv_dir.parents) if p.exists())
        if _inside_git(ancestor):
            print(f"ABORTO: {csv_dir} está dentro de un repositorio git; el archivo va fuera de git", file=sys.stderr)
            return 1
        csv_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(entrada, csv_dir / "extraccion_cruda.txt")
    lines = ["# Análisis H60 (solo lectura): infra propia, T2 corroboradas y autonomía\n",
             (f"Extraído {params.get('extraido_utc', 'sin dato')} UTC, ventana desde {params.get('desde')} "
             f"hasta {params.get('hasta') or 'la extracción'}. Días UTC. Reproducir: ver el docstring de "
             "scripts/metrics/analisis_h60.py.\n"),
             ("Exclusiones: hueco de H54 (8-oct 03:32:41 a 03:32:45Z, a lo sumo 5 registros) y restart del 9-oct "
             "(14:27:00,8Z a 14:27:14,6Z, 13,8 s sin decisiones). La ventana H25 (18-ago a 04-sep) queda fuera del rango.\n")]
    written: list[tuple[str, int]] = []
    for label, fn in (("A) Infra propia", analisis_a), ("B) T2 con >= 2 fuentes", analisis_b), ("C) Autonomía", analisis_c),
                      ("D) Cola de aprobaciones desde R4", analisis_d)):
        tables, resumen = fn(sec)
        lines.append(f"## {label}\n")
        lines += [f"- {r}" for r in resumen]
        lines.append("")
        for name, rows in tables.items():
            write_csv(csv_dir / name, rows)
            written.append((name, len(rows)))
            lines.append(f"- `{name}`: {len(rows)} filas")
        lines.append("")
    write_csv(csv_dir / "tier_por_dia_respuestas.csv", sec.get("tier_por_dia", []))
    written.append(("tier_por_dia_respuestas.csv", len(sec.get("tier_por_dia", []))))
    if archivo is not None:
        script = Path(__file__).resolve()
        rev = subprocess.run(["git", "-C", str(script.parent), "rev-parse", "--short", "HEAD"],  # nosec B603 B607 - comando fijo
                             capture_output=True, text=True, timeout=10, check=False).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(script.parent), "status", "--porcelain", "--", str(script)],  # nosec B603 B607 - comando fijo
                               capture_output=True, text=True, timeout=10, check=False).stdout.strip()
        if rev and dirty:
            rev += ", con cambios sin commitear: vale el sha256"
        man = ["# Manifiesto H60 (salidas archivadas fuera de git)\n",
               (f"Extraído {params.get('extraido_utc', 'sin dato')} UTC; ventana desde {params.get('desde')} hasta "
               f"{params.get('hasta') or 'la extracción'}; muestra de la unión de A: 1 de cada "
               f"{params.get('muestra_union_1_de', '1')}.\n"),
               (f"Archivo: `{csv_dir}`. Script: `scripts/metrics/analisis_h60.py` en `{rev or 'sin dato'}` "
               f"(sha256 `{_sha256(script)}`).\n"),
               "Verificar: `shasum -a 256 <archivo>` debe dar el hash de la tabla.\n",
               "| Archivo | Filas | Bytes | sha256 |", "|---|---|---|---|"]
        for name, n in [("extraccion_cruda.txt", None), *written]:
            f = csv_dir / name
            man.append(f"| `{name}` | {'' if n is None else n} | {f.stat().st_size} | `{_sha256(f)}` |")
        (out / "manifiesto_h60.md").write_text("\n".join(man) + "\n", encoding="utf-8")
        lines.append(f"Salidas CSV archivadas fuera de git en `{csv_dir}`; hashes en `manifiesto_h60.md`.")
    (out / "analisis_h60.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--extraer", action="store_true")
    ap.add_argument("--desde", default="2026-10-03T00:00:00Z")
    ap.add_argument("--hasta", default=None)
    ap.add_argument("--heap-max", type=int, default=85)
    ap.add_argument("--muestra", type=int, default=JOIN_STRIDE, help="unión de A sobre 1 de cada N")
    ap.add_argument("--escribir", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports/metricas/2026-10-10"))
    ap.add_argument("--archivar", type=Path, default=None,
                    help="directorio FUERA de git para los CSV y la extracción cruda; el manifiesto queda en --out")
    args = ap.parse_args()
    if args.extraer:
        try:
            return extraer(args.desde, args.hasta, args.heap_max, max(1, args.muestra))
        except Abort as e:
            print(f"ABORTO: {e}", file=sys.stderr)
            return 1
    if args.escribir:
        return escribir(args.escribir, args.out, args.archivar)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
