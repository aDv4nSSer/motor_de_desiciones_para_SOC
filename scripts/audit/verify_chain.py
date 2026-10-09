#!/usr/bin/env python3
"""
verify_chain.py — Verificación completa de las cadenas de evidencia, con informe JSON (H57).

Unifica scripts/verify_response_chain.py para las dos cadenas nuevas:
soc-responses-* (H39) y soc-decisions-* (H42). El índice legado soc-decisions
(17,9 M documentos, cadena vieja) no se incluye: tiene su propio verificador
(scripts/verify_decisions_legacy_chain.py).

Solo lectura. Pagina por chain_seq (search_after) con pausa entre páginas y
aborta solo si OpenSearch se ve exigido: heap de la JVM sobre el umbral o una
página más lenta que el máximo. Deja un JSON con el alcance (completa o
parcial, por qué), el rango verificado y el resultado, que el panel de
integridad del dashboard muestra junto a la verificación en vivo de la cola
y a los huecos declarados (motor/audit_gaps.yaml).

La cadena no puede detectar registros perdidos ANTES de encadenarse (H54):
"íntegra" significa "lo indexado no fue alterado y no faltan eslabones", no
"no se perdió nada". Por eso el informe remite a los huecos declarados.

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/audit/verify_chain.py
    python3 ../scripts/audit/verify_chain.py --cadenas responses --pausa 0.5

Código de salida: 0 íntegra, 1 problemas, 2 abortada (parcial).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    _ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_ROOT / "motor"))
except NameError:  # ejecutado por stdin desde motor/: el cwd ya está en sys.path
    pass

from response_audit_indexer import AuditIndexerSettings, OpenSearchClient, verify_chain

CHAINS = {
    "responses": {"pattern": "soc-responses-*", "time_field": "event_time"},
    "decisions": {"pattern": "soc-decisions-*", "time_field": "timestamp"},
}
DEFAULT_OUTPUT = Path.home() / "tesis" / "motor-runtime" / "audit" / "verify_chain_latest.json"
MAX_REPORTED = 20


class Aborted(RuntimeError):
    """OpenSearch exigido: se corta la verificación (queda parcial)."""


def heap_percent(client) -> int | None:
    r = client.request("GET", "/_nodes/stats/jvm")
    if r.status_code != 200:
        return None
    nodes = r.json().get("nodes", {}).values()
    return max((n["jvm"]["mem"]["heap_used_percent"] for n in nodes), default=None)


def verify_one(client, name: str, page: int, pause: float, heap_max: int, latency_max: float,
               check_every: int) -> dict:
    spec = CHAINS[name]
    out = {"pattern": spec["pattern"], "docs": 0, "first_seq": None, "last_seq": None,
           "first_time": None, "last_time": None, "problems": [], "problem_count": 0,
           "ok": None, "aborted": None, "starts_at_genesis": None, "duration_s": None}
    started, search_after, last, pages = time.monotonic(), None, None, 0
    try:
        while True:
            if pages % check_every == 0:
                heap = heap_percent(client)
                if heap is not None and heap > heap_max:
                    raise Aborted(f"heap de OpenSearch en {heap}% (máximo {heap_max}%)")
            body = {"size": page, "sort": [{"chain_seq": "asc"}]}
            if search_after is not None:
                body["search_after"] = search_after
            t0 = time.monotonic()
            r = client.request("POST", f"/{spec['pattern']}/_search", body)
            elapsed = time.monotonic() - t0
            if r.status_code == 404:
                break
            r.raise_for_status()
            if elapsed > latency_max:
                raise Aborted(f"página de {page} documentos en {elapsed:.1f} s (máximo {latency_max} s)")
            hits = r.json()["hits"]["hits"]
            if not hits:
                break
            docs = [h["_source"] for h in hits]
            if out["first_seq"] is None:
                out["first_seq"] = docs[0].get("chain_seq")
                out["first_time"] = docs[0].get(spec["time_field"])
            problems = verify_chain(([last] if last else []) + docs)
            out["problem_count"] += len(problems)
            out["problems"].extend(problems[: max(0, MAX_REPORTED - len(out["problems"]))])
            out["docs"] += len(docs)
            last = docs[-1]
            search_after = hits[-1]["sort"]
            pages += 1
            time.sleep(pause)
    except Aborted as e:
        out["aborted"] = str(e)
    if last is not None:
        out["last_seq"] = last.get("chain_seq")
        out["last_time"] = last.get(spec["time_field"])
    out["starts_at_genesis"] = out["first_seq"] == 1
    out["ok"] = out["problem_count"] == 0 if out["docs"] else None
    out["duration_s"] = round(time.monotonic() - started, 1)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--cadenas", default="responses,decisions", help="responses,decisions")
    ap.add_argument("--salida", type=Path, default=Path(os.environ.get("AUDIT_VERIFY_JSON", DEFAULT_OUTPUT)))
    ap.add_argument("--pagina", type=int, default=1000)
    ap.add_argument("--pausa", type=float, default=0.2, help="segundos entre páginas")
    ap.add_argument("--heap-max", type=int, default=85, help="aborta si el heap de OpenSearch supera este %%")
    ap.add_argument("--latencia-max", type=float, default=10.0, help="aborta si una página tarda más (s)")
    ap.add_argument("--chequeo-cada", type=int, default=20, help="páginas entre chequeos de heap")
    args = ap.parse_args()
    names = [c.strip() for c in args.cadenas.split(",") if c.strip()]
    unknown = [c for c in names if c not in CHAINS]
    if unknown:
        ap.error(f"cadenas desconocidas: {unknown}")

    client = OpenSearchClient(AuditIndexerSettings())
    started = datetime.now(timezone.utc)
    results = {n: verify_one(client, n, args.pagina, args.pausa, args.heap_max, args.latencia_max,
                             args.chequeo_cada) for n in names}
    aborted = [n for n, r in results.items() if r["aborted"]]
    report = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started.isoformat(),
        "alcance": "parcial" if aborted or set(names) != set(CHAINS) else "completa",
        "alcance_detalle": (
            f"abortada en {', '.join(aborted)}" if aborted else
            "todas las cadenas nuevas, sobre los índices retenidos (ISM 90 días)"
            if set(names) == set(CHAINS) else f"solo {', '.join(names)}"),
        "no_incluye": ["soc-decisions (índice legado, cadena vieja): scripts/verify_decisions_legacy_chain.py"],
        "limite": ("La cadena no detecta registros perdidos antes de encadenarse: ver los huecos "
                   "declarados en motor/audit_gaps.yaml."),
        "ok": all(r["ok"] is not False for r in results.values()) and not aborted,
        "cadenas": results,
        "parametros": {"pagina": args.pagina, "pausa_s": args.pausa, "heap_max_pct": args.heap_max,
                       "latencia_max_s": args.latencia_max},
    }
    args.salida.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.salida.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=1, ensure_ascii=False))
    tmp.replace(args.salida)
    stamped = args.salida.with_name(f"verify_chain_{started.strftime('%Y%m%dT%H%M%SZ')}.json")
    stamped.write_text(json.dumps(report, indent=1, ensure_ascii=False))

    for n, r in results.items():
        state = "ABORTADA: " + r["aborted"] if r["aborted"] else ("íntegra" if r["ok"] else
                                                                  f"{r['problem_count']} problemas")
        print(f"{n}: {r['docs']} docs, chain_seq {r['first_seq']} -> {r['last_seq']} "
              f"({r['first_time']} -> {r['last_time']}), {r['duration_s']} s: {state}")
    print(f"alcance: {report['alcance']} ({report['alcance_detalle']}) | informe: {args.salida}")
    if aborted:
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
