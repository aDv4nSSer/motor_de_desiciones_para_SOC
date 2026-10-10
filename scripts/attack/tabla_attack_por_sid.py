#!/usr/bin/env python3
"""
tabla_attack_por_sid.py — Tabla ATT&CK por SID de Suricata (H59).

Agrupa las alertas de suricata-alerts-* de los últimos --dias por
signature_id y mapea cada SID a ATT&CK por su classtype (el campo `category`
trae la descripción de classification.config) con motor/classtype_attack.yaml.
El mapeo es por classtype, no por regla: dos SIDs del mismo classtype
comparten técnica, y la columna `fuente_mapeo` lo dice. Es la tabla de
referencia para la tesis y para la traza explicativa; no cambia ninguna
decisión (el classtype no llega al Fast Path, H50).

Solo lectura: una agregación acotada (--max-sids) sobre OpenSearch. CSV por
stdout y un resumen por stderr.

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/attack/tabla_attack_por_sid.py --dias 30 > attack_por_sid.csv

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import argparse
import collections
import csv
import sys
from pathlib import Path
from typing import Any

# Por stdin (python3 - < script, desde motor/) el directorio actual ya es motor/;
# no se agrega otra ruta para no tomar código de un directorio viejo.
if Path(__file__).name != "<stdin>":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from attck_mapping import lookup

ALERTS_PATTERN = "suricata-alerts-*"
COLUMNS = ["sid", "firma", "classtype", "alertas", "primera", "ultima", "severidad",
           "tactica_id", "tactica", "tecnica_id", "tecnica", "confianza", "fuente_mapeo"]


def aggregation(days: int, max_sids: int) -> dict[str, Any]:
    """Cuerpo de la agregación por SID (acotada en tiempo y en cantidad)."""
    return {"size": 0, "query": {"range": {"timestamp": {"gte": f"now-{days}d"}}},
            "aggs": {"sid": {"terms": {"field": "signature_id", "size": max_sids}, "aggs": {
                "ej": {"top_hits": {"size": 1, "_source": ["signature", "category", "severity"]}},
                "desde": {"min": {"field": "timestamp"}}, "hasta": {"max": {"field": "timestamp"}}}}}}


def build_rows(buckets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filas de la tabla a partir de los buckets de la agregación.

    Args:
        buckets: aggregations.sid.buckets de la respuesta de OpenSearch.

    Returns:
        Una fila por SID, ordenadas por cantidad de alertas descendente.
    """
    rows = []
    for b in buckets:
        hits = b.get("ej", {}).get("hits", {}).get("hits", [])
        src = hits[0].get("_source", {}) if hits else {}
        classtype = src.get("category")
        entry = lookup(classtype) if classtype else None
        rows.append({
            "sid": b.get("key"), "firma": src.get("signature"), "classtype": classtype,
            "alertas": b.get("doc_count", 0),
            "primera": (b.get("desde") or {}).get("value_as_string"), "ultima": (b.get("hasta") or {}).get("value_as_string"),
            "severidad": src.get("severity"),
            "tactica_id": entry.tactic_id if entry else None, "tactica": entry.tactic_name if entry else None,
            "tecnica_id": entry.technique_id if entry else None, "tecnica": entry.technique_name if entry else None,
            "confianza": entry.confidence if entry else None,
            "fuente_mapeo": ("classtype_attack.yaml (por classtype)" if entry and entry.technique_id else
                             "classtype sin técnica asignada" if entry else
                             "sin classtype" if not classtype else "classtype fuera del YAML"),
        })
    return sorted(rows, key=lambda r: -r["alertas"])


def summary(rows: list[dict[str, Any]]) -> str:
    """Resumen de cobertura: SIDs y alertas con técnica, y técnicas más frecuentes."""
    total = sum(r["alertas"] for r in rows) or 1
    mapped = [r for r in rows if r["tecnica_id"]]
    by_tech = collections.Counter()
    for r in mapped:
        by_tech[f"{r['tecnica_id']} {r['tecnica']}"] += r["alertas"]
    with_tech = sum(r["alertas"] for r in mapped)
    head = f"SIDs: {len(rows)}; con técnica: {len(mapped)}; alertas con técnica: {with_tech}/{total}"
    lines = [f"{head} ({100 * with_tech / total:.1f}%)"]
    lines += [f"  {n:>8}  {t}" for t, n in by_tech.most_common(10)]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dias", type=int, default=30)
    ap.add_argument("--max-sids", type=int, default=1000)
    args = ap.parse_args()
    from dashboard import _os_request  # solo en .140: lee el .env del motor
    res = _os_request("POST", f"/{ALERTS_PATTERN}/_search", aggregation(args.dias, args.max_sids))
    if res is None:
        print("OpenSearch no respondió", file=sys.stderr)
        return 1
    rows = build_rows(res["aggregations"]["sid"]["buckets"])
    w = csv.DictWriter(sys.stdout, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(rows)
    print(summary(rows), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
