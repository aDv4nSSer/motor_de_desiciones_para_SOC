#!/usr/bin/env python3
"""
correlacion_jsonl.py — Agrega SERVER_TCP_FLAGS al corpus etiquetado
correlacionando con los archivos JSONL del pipeline.
Tesis UBO — Motor de Decisiones SOC
"""

import json, csv, os, glob
from collections import defaultdict

BASE     = "/home/ia_ubo/tesis/relabeling"
DATA_DIR = f"{BASE}/data"
CSV_IN   = f"{BASE}/output/corpus_relabeled_v2.csv"
CSV_OUT  = f"{BASE}/output/corpus_relabeled_v3_completo.csv"

def most_common(lst):
    return max(set(lst), key=lst.count) if lst else -1

# ── Paso 1: Construir índice desde todos los JSONL ────────────────────────────
print("[1/3] Cargando archivos JSONL en índice...")

# Índice exacto : (dst_port, out_pkts, in_pkts, duration) → [server_tcp_flags]
# Índice relajado: (dst_port, out_pkts, in_pkts)           → [server_tcp_flags]
idx_exact = defaultdict(list)
idx_relax = defaultdict(list)

jsonl_files = sorted(glob.glob(f"{DATA_DIR}/flows_*.jsonl"))
total_jsonl = 0

for filepath in jsonl_files:
    with open(filepath) as f:
        for line in f:
            try:
                flow  = json.loads(line.strip())
                flags = flow.get("SERVER_TCP_FLAGS", -1)
                dst   = flow.get("L4_DST_PORT", -1)
                outp  = flow.get("OUT_PKTS", -1)
                inp   = flow.get("IN_PKTS", -1)
                dur   = flow.get("FLOW_DURATION_MILLISECONDS", -1)
                idx_exact[(dst, outp, inp, dur)].append(flags)
                idx_relax[(dst, outp, inp)].append(flags)
                total_jsonl += 1
            except Exception:
                continue

print(f"  Flujos JSONL cargados : {total_jsonl:,}")
print(f"  Claves exactas        : {len(idx_exact):,}")
print(f"  Claves relajadas      : {len(idx_relax):,}")

# ── Paso 2: Correlacionar y generar CSV final ─────────────────────────────────
print("\n[2/3] Correlacionando corpus con índice JSONL...")

stats = {"exacto": 0, "relajado": 0, "imputado": 0, "sin_match": 0}

with open(CSV_IN) as fin, open(CSV_OUT, 'w', newline='') as fout:
    reader = csv.DictReader(fin)
    fields = reader.fieldnames + ["SERVER_TCP_FLAGS"]
    writer = csv.DictWriter(fout, fieldnames=fields)
    writer.writeheader()

    for row in reader:
        dst  = int(row["L4_DST_PORT"])
        outp = int(row["OUT_PKTS"])
        inp  = int(row["IN_PKTS"])
        dur  = int(row["FLOW_DURATION_MILLISECONDS"])

        if (dst, outp, inp, dur) in idx_exact:
            row["SERVER_TCP_FLAGS"] = most_common(idx_exact[(dst, outp, inp, dur)])
            stats["exacto"] += 1

        elif outp == 0:
            # Servidor no respondió → flags = 0
            row["SERVER_TCP_FLAGS"] = 0
            stats["imputado"] += 1

        elif (dst, outp, inp) in idx_relax:
            row["SERVER_TCP_FLAGS"] = most_common(idx_relax[(dst, outp, inp)])
            stats["relajado"] += 1

        else:
            row["SERVER_TCP_FLAGS"] = -1
            stats["sin_match"] += 1

        writer.writerow(row)

# ── Paso 3: Resumen ───────────────────────────────────────────────────────────
print("\n[3/3] Resultados:")
total = sum(stats.values())
print(f"  Match exacto   : {stats['exacto']:>8,}  ({stats['exacto']/total*100:.1f}%)")
print(f"  Match relajado : {stats['relajado']:>8,}  ({stats['relajado']/total*100:.1f}%)")
print(f"  Imputados  (0) : {stats['imputado']:>8,}  ({stats['imputado']/total*100:.1f}%)")
print(f"  Sin match (-1) : {stats['sin_match']:>8,}  ({stats['sin_match']/total*100:.1f}%)")
print(f"\n  CSV final: {CSV_OUT}")

# Verificar ataques
with open(CSV_OUT) as f:
    ataques = [r for r in csv.DictReader(f) if r['label'] == '1']
validos = sum(1 for a in ataques if int(a['SERVER_TCP_FLAGS']) >= 0)
print(f"\n  Ataques con SERVER_TCP_FLAGS válido: {validos}/{len(ataques)}")
print("\n✓ Completado.")
