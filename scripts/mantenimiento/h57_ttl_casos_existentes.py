#!/usr/bin/env python3
"""
h57_ttl_casos_existentes.py — TTL escalonado para los casos automáticos previos a H57.

Hasta H57 cada T2 de IP pública abría un caso sin TTL ni dedup (~550.000 en
soc:cases:*). El fix (response/cases.py) cubre los casos nuevos; este script
pone un TTL corto y escalonado a los existentes para liberar memoria de Redis
sin borrarlos de golpe. No archiva: los case_id siguen referenciados en
soc-responses-* (append-only), y los conteos agregados por día y tier se
guardan desde OpenSearch (--conteos), no leyendo los casos.

Tres pasos, en este orden (en .140, desde motor/ para tomar el .env):

  1. Muestra (solo lectura, <= 500 casos): estados, kinds, TTL actual. Los
     casos que no estén "abierto" o tengan historial/notas de un analista van
     a una lista de exclusión.
       python3 ../scripts/mantenimiento/h57_ttl_casos_existentes.py --muestra \\
           --excluir ~/tesis/backups/h57_casos_excluidos.json
  2. Conteos agregados por día y tier desde soc-responses (solo lectura):
       python3 ../scripts/mantenimiento/h57_ttl_casos_existentes.py --conteos \\
           --salida ~/tesis/backups/h57_casos_conteos.json
  3. Aplicar (escritura, supervisado): EXPIRE ... NX (no toca casos que ya
     tienen TTL, como los nuevos de H57) con TTL entre 2 y 14 h según el
     case_id. No lee el contenido de los casos. Cada 10 lotes mira INFO y
     aborta si used_memory pasa del 90% de maxmemory o aparecen desalojos.
       python3 ../scripts/mantenimiento/h57_ttl_casos_existentes.py --apply \\
           --excluir ~/tesis/backups/h57_casos_excluidos.json

Redis: solo SSCAN con COUNT chico y pausas, MGET de a 100 en la muestra,
pipelines de EXPIRE de a 200, INFO. Nunca SMEMBERS ni lecturas masivas (H54).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import zlib
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.cases import CASES_INDEX_KEY, CASES_KEY_PREFIX

SAMPLE_MAX = 500
SAMPLE_BATCH = 100
APPLY_BATCH = 200
PAUSE_SECONDS = 0.1
GUARD_EVERY = 10
MEMORY_ABORT_FRACTION = 0.90
TTL_MIN_SECONDS = 2 * 3600
TTL_SPREAD_SECONDS = 12 * 3600
AUTO_NOTE = "Caso creado automáticamente"


def staggered_ttl(case_id: str) -> int:
    """TTL determinista entre 2 y 14 h según el case_id: la memoria baja de a
    poco a lo largo de medio día, no de golpe."""
    return TTL_MIN_SECONDS + zlib.crc32(case_id.encode()) % TTL_SPREAD_SECONDS


def touched_by_analyst(case: dict) -> bool:
    """True si el caso dejó de ser automático puro: otro estado, o un evento
    de historial que no es el de creación automática."""
    if case.get("state") != "abierto":
        return True
    hist = case.get("history") or []
    return len(hist) > 1 or any(AUTO_NOTE not in str(h.get("note", "")) for h in hist)


def sscan_ids(rdb, count: int, pause: float):
    """Recorre soc:cases:index de a `count` ids con pausas (nunca SMEMBERS)."""
    cursor = 0
    while True:
        cursor, ids = rdb.sscan(CASES_INDEX_KEY, cursor=cursor, count=count)
        if ids:
            yield list(ids)
        if cursor == 0:
            return
        time.sleep(pause)


def muestra(rdb, excluir: Path) -> dict:
    ids: list[str] = []
    for batch in sscan_ids(rdb, SAMPLE_BATCH, 0.2):
        ids.extend(batch)
        if len(ids) >= SAMPLE_MAX:
            break
    ids = ids[:SAMPLE_MAX]
    states, kinds, days, ttls = Counter(), Counter(), Counter(), Counter()
    excluded, missing = [], 0
    for i in range(0, len(ids), SAMPLE_BATCH):
        chunk = ids[i:i + SAMPLE_BATCH]
        raws = rdb.mget([f"{CASES_KEY_PREFIX}{c}" for c in chunk])
        pipe = rdb.pipeline()
        for c in chunk:
            pipe.ttl(f"{CASES_KEY_PREFIX}{c}")
        for c, raw, ttl in zip(chunk, raws, pipe.execute()):
            if not raw:
                missing += 1
                continue
            case = json.loads(raw)
            states[case.get("state")] += 1
            kinds[case.get("kind")] += 1
            days[str(case.get("opened_at", ""))[:10]] += 1
            ttls["sin TTL" if ttl == -1 else "con TTL"] += 1
            if touched_by_analyst(case):
                excluded.append(c)
        time.sleep(0.2)
    excluir.write_text(json.dumps(sorted(excluded)))
    return {"muestra": len(ids), "inexistentes": missing, "estados": dict(states), "kinds": dict(kinds),
            "por_dia_muestra": dict(sorted(days.items())), "ttl": dict(ttls), "excluidos": len(excluded),
            "scard_indice": rdb.scard(CASES_INDEX_KEY)}


def memory_guard(rdb, evicted_start: int) -> str | None:
    mem, stats = rdb.info("memory"), rdb.info("stats")
    maxmem = int(mem.get("maxmemory") or 0)
    if maxmem and int(mem["used_memory"]) > MEMORY_ABORT_FRACTION * maxmem:
        return f"used_memory {mem['used_memory']} > {MEMORY_ABORT_FRACTION:.0%} de maxmemory {maxmem}"
    if int(stats["evicted_keys"]) > evicted_start:
        return f"evicted_keys subió de {evicted_start} a {stats['evicted_keys']}"
    return None


def apply(rdb, excluded: set[str], pause: float = PAUSE_SECONDS) -> dict:
    evicted_start = int(rdb.info("stats")["evicted_keys"])
    applied = unchanged = skipped = batches = 0
    for batch in sscan_ids(rdb, APPLY_BATCH, pause):
        todo = [c for c in batch if c not in excluded]
        skipped += len(batch) - len(todo)
        pipe = rdb.pipeline(transaction=False)
        for c in todo:
            pipe.expire(f"{CASES_KEY_PREFIX}{c}", staggered_ttl(c), nx=True)
        for ok in pipe.execute():
            applied += int(bool(ok))
            unchanged += int(not ok)  # ya tenía TTL (casos de H57) o ya no existe
        batches += 1
        if batches % GUARD_EVERY == 0:
            reason = memory_guard(rdb, evicted_start)
            if reason:
                return {"abortado": reason, "aplicados": applied, "sin_cambio": unchanged,
                        "excluidos": skipped, "lotes": batches}
    return {"aplicados": applied, "sin_cambio": unchanged, "excluidos": skipped, "lotes": batches}


def conteos(salida: Path) -> dict:
    """Casos abiertos por día (UTC) y tier, desde soc-responses: cada doc con
    case_id es una apertura (o una ocurrencia deduplicada desde H57)."""
    from response_audit_indexer import AuditIndexerSettings, OpenSearchClient

    c = OpenSearchClient(AuditIndexerSettings())
    q = {"size": 0, "query": {"exists": {"field": "case_id"}},
         "aggs": {"dia": {"date_histogram": {"field": "event_time", "calendar_interval": "day"},
                          "aggs": {"tier": {"terms": {"field": "tier", "size": 5}},
                                   "casos": {"cardinality": {"field": "case_id"}}}}}}
    res = c.request("POST", "/soc-responses-*/_search", q).json()
    out = {b["key_as_string"][:10]: {"docs": b["doc_count"], "casos_distintos": b["casos"]["value"],
                                     "por_tier": {str(t["key"]): t["doc_count"] for t in b["tier"]["buckets"]}}
           for b in res["aggregations"]["dia"]["buckets"]}
    salida.write_text(json.dumps(out, indent=1))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--muestra", action="store_true")
    mode.add_argument("--conteos", action="store_true")
    mode.add_argument("--apply", action="store_true")
    ap.add_argument("--excluir", type=Path, help="JSON con los case_id a excluir (lo escribe --muestra)")
    ap.add_argument("--salida", type=Path, help="JSON de conteos (--conteos)")
    args = ap.parse_args()
    if args.conteos:
        if not args.salida:
            ap.error("--conteos requiere --salida")
        print(json.dumps(conteos(args.salida), indent=1))
        return 0
    if not args.excluir:
        ap.error("--muestra y --apply requieren --excluir")
    from dashboard import _get_redis

    rdb = _get_redis()
    if args.muestra:
        print(json.dumps(muestra(rdb, args.excluir), indent=1))
        return 0
    excluded = set(json.loads(args.excluir.read_text()))
    result = apply(rdb, excluded)
    print(json.dumps(result, indent=1))
    return 1 if "abortado" in result else 0


if __name__ == "__main__":
    sys.exit(main())
