#!/usr/bin/env python3
"""
verify_decisions_legacy_chain.py — Verifica la cadena VIEJA de soc-decisions tal cual quedó (H42).

La cadena vieja (índice legado `soc-decisions`, hasta el corte de H42) usaba
hash = sha256(prev_hash + trace_id + timestamp + tier + risk_score) y no tenía
chain_seq. No se recalcula ni se modifica: este script solo la lee y reporta.

Recorre el índice en porciones de una hora de `timestamp` (cada consulta
toca solo su porción: ordenar el índice entero vence cualquier timeout en un
nodo) y con memoria acotada:
- por documento: recalcula el hash con la fórmula vieja (discrepancias);
- por enlace: un prev_hash cuyo padre todavía no apareció queda "pendiente
  de resolver"; si el padre aparece dentro de los siguientes --window
  documentos (en cualquier sentido), no es hueco. El orden por timestamp
  NO es el orden de la cadena: el scoring corre en paralelo y un hijo puede
  tener el mismo timestamp, o uno hasta ~1 ms anterior, que su padre
  (verificado en H42). Solo cuenta como hueco un padre que no aparece en
  toda la ventana: pérdida real, o desorden mayor que la ventana.
  También cuenta prev_hash repetidos (bifurcaciones), listando las primeras.

Por defecto, solo las últimas --hours horas. --all recorre el índice
completo (~17.9 M documentos): lectura pesada sobre producción, solo con
aprobación explícita y después de revisar la salud del clúster.

Uso (en .140, desde motor/):
    python3 ../scripts/verify_decisions_legacy_chain.py --hours 6
    python3 ../scripts/verify_decisions_legacy_chain.py --all
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import time
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "motor"))

from opensearch_indexer import (
    LEGACY_INDEX,
    DecisionsIndexerSettings,
    DecisionsOpenSearchClient,
)

PAGE = 5000
FIELDS = ["trace_id", "timestamp", "tier", "risk_score", "prev_hash", "hash"]
MAX_LISTED = 50


def legacy_hash(prev_hash: str, d: dict) -> str:
    raw = prev_hash + d.get("trace_id", "") + d.get("timestamp", "") + str(d.get("tier", "")) + str(d.get("risk_score", ""))
    return hashlib.sha256(raw.encode()).hexdigest()


class ChainStats:
    """Verificación en streaming con memoria acotada a `window` hashes."""

    def __init__(self, window: int):
        self.window = window
        self.recent: OrderedDict[str, dict] = OrderedDict()   # hash -> doc (últimos N)
        self.children: dict[str, int] = {}                    # prev_hash -> hijos vistos
        self.unresolved: OrderedDict[str, tuple[int, dict]] = OrderedDict()  # prev_hash -> (índice, ejemplo)
        self.total = 0
        self.bad: list[dict] = []
        self.gaps = 0
        self.inversions_resolved = 0
        self.gap_examples: list[dict] = []
        self.forks: list[dict] = []
        self.first: dict | None = None
        self.last: dict | None = None

    def add(self, d: dict) -> None:
        self.total += 1
        if self.first is None:
            self.first = d
        if legacy_hash(d.get("prev_hash", ""), d) != d.get("hash"):
            self.bad.append({"trace_id": d.get("trace_id"), "timestamp": d.get("timestamp")})
        # ¿Este documento es el padre que esperaba un hijo ya visto?
        if self.unresolved.pop(d["hash"], None) is not None:
            self.inversions_resolved += 1
        prev = d.get("prev_hash")
        if self.total > 1 and prev not in self.recent and prev not in self.unresolved:
            self.unresolved[prev] = (self.total, {"trace_id": d.get("trace_id"),
                                                  "timestamp": d.get("timestamp"), "prev_hash": prev})
        n = self.children.get(prev, 0) + 1
        self.children[prev] = n
        if n == 2:
            parent = self.recent.get(prev)
            self.forks.append({"prev_hash": prev, "child_trace_id": d.get("trace_id"),
                               "child_timestamp": d.get("timestamp"),
                               "parent_trace_id": parent and parent.get("trace_id")})
        self.recent[d["hash"]] = {"trace_id": d.get("trace_id")}
        if len(self.recent) > self.window:
            old_hash, _ = self.recent.popitem(last=False)
            self.children.pop(old_hash, None)
        # Pendientes que superaron la ventana sin que aparezca el padre: hueco.
        while self.unresolved:
            _, (idx, ex) = next(iter(self.unresolved.items()))
            if self.total - idx <= self.window:
                break
            self.unresolved.popitem(last=False)
            self._gap(ex)
        self.last = d

    def _gap(self, ex: dict) -> None:
        self.gaps += 1
        if len(self.gap_examples) < MAX_LISTED:
            self.gap_examples.append(ex)

    def finish(self) -> None:
        """Al terminar, lo que quedó sin resolver también es hueco."""
        while self.unresolved:
            _, (_, ex) = self.unresolved.popitem(last=False)
            self._gap(ex)


def hourly_slices(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    t = start.replace(minute=0, second=0, microsecond=0)
    while t <= end:
        yield t, t + timedelta(hours=1)
        t += timedelta(hours=1)


def read_slice(client: DecisionsOpenSearchClient, lo: datetime, hi: datetime) -> Iterable[dict]:
    after = None
    while True:
        body = {"size": PAGE, "_source": FIELDS,
                "query": {"range": {"timestamp": {"gte": lo.isoformat(), "lt": hi.isoformat()}}},
                "sort": [{"timestamp": "asc"}, {"trace_id": "asc"}]}
        if after:
            body["search_after"] = after
        r = client.request("POST", f"/{LEGACY_INDEX}/_search", body)
        r.raise_for_status()
        hits = r.json()["hits"]["hits"]
        if not hits:
            return
        yield from (h["_source"] for h in hits)
        after = hits[-1]["sort"]


def bound(client: DecisionsOpenSearchClient, order: str) -> datetime:
    r = client.request("POST", f"/{LEGACY_INDEX}/_search",
                       {"size": 1, "_source": ["timestamp"], "sort": [{"timestamp": order}]})
    r.raise_for_status()
    return datetime.fromisoformat(r.json()["hits"]["hits"][0]["_source"]["timestamp"]).astimezone(timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6.0, help="ventana: últimas N horas por timestamp")
    ap.add_argument("--all", action="store_true", help="recorrer el índice completo (pesado)")
    ap.add_argument("--window", type=int, default=200_000, help="hashes recientes en memoria para enlaces")
    args = ap.parse_args()
    client = DecisionsOpenSearchClient(DecisionsIndexerSettings())
    client._http.timeout = httpx.Timeout(120.0, connect=2.0)  # lecturas largas, solo este script
    total = client.legacy_count()
    end = bound(client, "desc")
    start = bound(client, "asc") if args.all else end - timedelta(hours=args.hours)
    stats = ChainStats(args.window)
    t0 = time.monotonic()
    for i, (lo, hi) in enumerate(hourly_slices(start, end)):
        for d in read_slice(client, max(lo, start), hi):
            stats.add(d)
        if args.all and i % 24 == 23:
            print(f"  ... {lo:%Y-%m-%d} | {stats.total} docs | {time.monotonic() - t0:.0f}s", flush=True)
    stats.finish()
    if not stats.total:
        print(f"índice {LEGACY_INDEX}: {total} documentos; ninguno en la ventana")
        return 0
    print(f"índice {LEGACY_INDEX}: {total} documentos; verificados {stats.total} "
          f"({stats.first['timestamp']} -> {stats.last['timestamp']}) en {time.monotonic() - t0:.0f}s")
    print(f"hash recalculado distinto (contenido de los 4 campos alterado): {len(stats.bad)}")
    print(f"padre fuera de orden por timestamp, resuelto dentro de la ventana (no es hueco): {stats.inversions_resolved}")
    print(f"padre que no aparece en {args.window} documentos (huecos: pérdida o desorden mayor): {stats.gaps}")
    print(f"bifurcaciones (prev_hash con 2+ hijos): {len(stats.forks)}")
    for f in stats.forks[:MAX_LISTED]:
        print(f"  bifurcación: padre={f['parent_trace_id']} hijo2={f['child_trace_id']} ts={f['child_timestamp']}")
    for g in stats.gap_examples[:10]:
        print(f"  hueco: trace={g['trace_id']} ts={g['timestamp']}")
    for d in stats.bad[:10]:
        print(f"  discrepancia: {d['trace_id']} {d['timestamp']}")
    return 1 if stats.bad else 0


if __name__ == "__main__":
    sys.exit(main())
