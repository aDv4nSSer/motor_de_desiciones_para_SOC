#!/usr/bin/env python3
"""
extraer_metricas.py — Métricas de la tesis desde OpenSearch (H59). Solo lectura.

Corre en .140 (desde motor/, para tomar el .env) y escribe en stdout varias
tablas CSV, cada una precedida por una línea `## <nombre>`:

- tiers_por_hora: decisiones del Fast Path por hora y tier (soc-decisions-*).
- latencia_por_dia: latencia del Fast Path por día (p50, p95, p99, n).
- respuesta_por_dia: por día, IPs distintas bloqueadas automáticamente, IPs
  derivadas a aprobación, IPs con aprobaciones expiradas y aprobaciones
  aprobadas o rechazadas por humanos (soc-responses-*).

Todas son agregaciones acotadas (date_histogram con buckets fijos), con una
pausa entre consultas y aborto si el heap de OpenSearch supera --heap-max.
El consumo de AbuseIPDB por tier sale del worker.log (ver
scripts/metrics/README en H59) y los cortes de régimen de motor/regimes.py,
al graficar (graficar_metricas.py).

Uso (en .140):
    cd ~/tesis/repo/motor && python3 ../scripts/metrics/extraer_metricas.py --desde 2026-10-03 > metricas.txt

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Any

# Por stdin (python3 - < script, desde motor/) el directorio actual ya es motor/;
# no se agrega otra ruta para no tomar código de un directorio viejo.
if Path(__file__).name != "<stdin>":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

DECISIONS = "soc-decisions-*"
RESPONSES = "soc-responses-*"
PAUSE = 0.5


def _bucket_date(b: dict[str, Any]) -> str:
    return b["key_as_string"]


def tiers_por_hora(buckets: list[dict]) -> list[dict[str, Any]]:
    """Filas hora, t0..t3, total a partir de un date_histogram con terms tier."""
    rows = []
    for b in buckets:
        counts = {int(t["key"]): t["doc_count"] for t in b["tier"]["buckets"]}
        rows.append({"hora_utc": _bucket_date(b), **{f"t{i}": counts.get(i, 0) for i in range(4)}, "total": b["doc_count"]})
    return rows


def latencia_por_dia(buckets: list[dict]) -> list[dict[str, Any]]:
    """Filas día, n, p50, p95, p99 (ms) a partir de un date_histogram con percentiles."""
    rows = []
    for b in buckets:
        v = b["lat"]["values"]
        rows.append({"dia_utc": _bucket_date(b)[:10], "n": b["doc_count"],
                     **{f"p{int(float(k))}": (round(x, 2) if x is not None else None) for k, x in v.items()}})
    return rows


def respuesta_por_dia(buckets: list[dict]) -> list[dict[str, Any]]:
    """Filas día con IPs distintas por destino de la respuesta."""
    return [{"dia_utc": _bucket_date(b)[:10],
             "ips_bloqueadas_auto": b["auto"]["ips"]["value"],
             "ips_derivadas_aprobacion": b["der"]["ips"]["value"],
             "ips_aprobacion_expirada": b["exp"]["ips"]["value"],
             "aprobaciones_humanas": b["hum"]["doc_count"],
             "t3_ips": b["t3"]["ips"]["value"]} for b in buckets]


def queries(since: str) -> dict[str, tuple[str, dict[str, Any]]]:
    """Cuerpos de las tres agregaciones (índice, cuerpo)."""
    card = {"cardinality": {"field": "src_ip", "precision_threshold": 40000}}
    rng_ts = {"range": {"timestamp": {"gte": since}}}
    rng_ev = {"range": {"event_time": {"gte": since}}}
    return {
        "tiers_por_hora": (DECISIONS, {"size": 0, "query": rng_ts, "aggs": {"h": {
            "date_histogram": {"field": "timestamp", "fixed_interval": "1h"},
            "aggs": {"tier": {"terms": {"field": "tier", "size": 4}}}}}}),
        "latencia_por_dia": (DECISIONS, {"size": 0, "query": rng_ts, "aggs": {"h": {
            "date_histogram": {"field": "timestamp", "calendar_interval": "1d"},
            "aggs": {"lat": {"percentiles": {"field": "latency_ms", "percents": [50, 95, 99]}}}}}}),
        "respuesta_por_dia": (RESPONSES, {"size": 0, "query": rng_ev, "aggs": {"h": {
            "date_histogram": {"field": "event_time", "calendar_interval": "1d"},
            "aggs": {
                "auto": {"filter": {"term": {"block_enforced": True}}, "aggs": {"ips": card}},
                "der": {"filter": {"term": {"accion_recomendada": "alertar_pendiente_aprobacion"}}, "aggs": {"ips": card}},
                "exp": {"filter": {"term": {"event_type": "approval_expired"}}, "aggs": {"ips": card}},
                "hum": {"filter": {"bool": {"should": [{"term": {"event_type": "manual_approval"}},
                                                      {"term": {"access_event": "approval_rejected"}}]}}},
                "t3": {"filter": {"bool": {"filter": [{"term": {"event_type": "response"}}, {"term": {"tier": 3}}]}},
                       "aggs": {"ips": card}}}}}}),
    }


BUILDERS = {"tiers_por_hora": tiers_por_hora, "latencia_por_dia": latencia_por_dia, "respuesta_por_dia": respuesta_por_dia}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--desde", default="2026-10-03", help="fecha UTC de inicio (cadena nueva desde el 3-oct)")
    ap.add_argument("--heap-max", type=int, default=85)
    args = ap.parse_args()
    from dashboard import _os_request  # solo en .140: lee el .env del motor
    for name, (index, body) in queries(args.desde).items():
        st = _os_request("GET", "/_nodes/stats/jvm") or {}
        heap = max((n["jvm"]["mem"]["heap_used_percent"] for n in st.get("nodes", {}).values()), default=0)
        if heap > args.heap_max:
            print(f"ABORTO: heap {heap}%", file=sys.stderr)
            return 1
        res = _os_request("POST", f"/{index}/_search", body)
        if res is None:
            print(f"ABORTO: OpenSearch no respondió en {name}", file=sys.stderr)
            return 1
        rows = BUILDERS[name](res["aggregations"]["h"]["buckets"])
        print(f"## {name}")
        w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()) if rows else ["vacio"])
        w.writeheader()
        w.writerows(rows)
        time.sleep(PAUSE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
