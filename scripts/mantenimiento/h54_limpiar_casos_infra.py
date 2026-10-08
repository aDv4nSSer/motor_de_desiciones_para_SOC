#!/usr/bin/env python3
"""
h54_limpiar_casos_infra.py — Limpieza única de soc:cases:* generados por el bug de H54.

Hasta H54, cada T2 cuyo origen era la propia infraestructura del SOC (Vector,
worker, gateways de VLAN, vistos por Suricata en el trunk de .139) abría un
caso nuevo sin dedup. Este script saca de Redis:

1. Los casos `network_t2_unconfirmed` de hosts en config.OWN_INFRA que nadie
   tocó (estado "abierto", historial de un solo evento).
2. Las entradas de soc:cases:index cuyo documento ya no existe (desalojado
   por allkeys-lru): índice huérfano.

No toca casos de IPs públicas, de otros `kind` (p. ej. quarantine_file) ni
casos que un analista haya movido. soc-responses-* (append-only) no se toca:
los case_id quedan referenciados en la auditoría y se documenta en H54.

Antes de borrar exporta cada entrada a un JSONL gzip (case_id, host,
opened_at, motivo) para poder reconstruir el conteo.

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/mantenimiento/h54_limpiar_casos_infra.py            # solo cuenta
    python3 ../scripts/mantenimiento/h54_limpiar_casos_infra.py --apply \\
        --export ~/tesis/backups/h54_casos_infra.jsonl.gz
"""
from __future__ import annotations

import argparse
import contextlib
import gzip
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from dashboard import _get_redis
from response.cases import CASES_INDEX_KEY, CASES_KEY_PREFIX
from response.enforcer import is_own_infra

# Lotes chicos y SSCAN en vez de SMEMBERS: una sola respuesta con los ~780k
# casos (un pipeline de GETs) llevó used_memory a 1,35 GB > maxmemory y
# allkeys-lru desalojó 72.205 claves, entre ellas soc:response:audit (H54).
CHUNK = 2000


def batches(rdb, size: int):
    """Recorre soc:cases:index con SSCAN en lotes de `size` ids. SSCAN puede
    devolver un elemento más de una vez: se deduplica para no contar doble."""
    seen: set[str] = set()
    batch: list[str] = []
    for cid in rdb.sscan_iter(CASES_INDEX_KEY, count=size):
        if cid in seen:
            continue
        seen.add(cid)
        batch.append(cid)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def classify(raw: str | None) -> str | None:
    """Motivo de borrado para un caso, o None si se conserva."""
    if raw is None:
        return "indice_huerfano"
    case = json.loads(raw)
    untouched = case.get("state") == "abierto" and len(case.get("history") or []) <= 1
    if (case.get("kind") == "network_t2_unconfirmed" and untouched
            and is_own_infra(case.get("host") or "")):
        return "infra_propia"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--apply", action="store_true", help="borrar de verdad (default: solo contar)")
    ap.add_argument("--export", type=Path, help="JSONL gzip con lo que se borra (obligatorio con --apply)")
    args = ap.parse_args()
    if args.apply and not args.export:
        ap.error("--apply requiere --export")
    if args.export and args.export.exists():
        ap.error(f"{args.export} ya existe: no se sobrescribe un export previo")

    rdb = _get_redis()
    total = rdb.scard(CASES_INDEX_KEY)
    reasons: Counter = Counter()
    hosts: Counter = Counter()
    with contextlib.ExitStack() as stack:
        out = stack.enter_context(gzip.open(args.export, "wt", encoding="utf-8")) if args.export else None
        for chunk in batches(rdb, CHUNK):
            raws = rdb.mget([f"{CASES_KEY_PREFIX}{c}" for c in chunk])
            doomed = []
            for cid, raw in zip(chunk, raws):
                reason = classify(raw)
                if reason is None:
                    reasons["conservado"] += 1
                    continue
                reasons[reason] += 1
                case = json.loads(raw) if raw else {}
                hosts[case.get("host", "-")] += 1
                doomed.append(cid)
                if out:
                    out.write(json.dumps({"case_id": cid, "reason": reason, "host": case.get("host"),
                                          "opened_at": case.get("opened_at"),
                                          "trace_id": (case.get("detail") or {}).get("trace_id")}) + "\n")
            if args.apply and doomed:
                pipe = rdb.pipeline(transaction=False)
                pipe.delete(*[f"{CASES_KEY_PREFIX}{c}" for c in doomed])
                pipe.srem(CASES_INDEX_KEY, *doomed)
                pipe.execute()

    print(f"{'BORRADO' if args.apply else 'SIMULACIÓN'} sobre {total} entradas de {CASES_INDEX_KEY}")
    for k, v in reasons.most_common():
        print(f"  {k:16} {v}")
    print("  por host:", hosts.most_common(10))
    if args.apply:
        print(f"SCARD después: {rdb.scard(CASES_INDEX_KEY)} | export: {args.export}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
