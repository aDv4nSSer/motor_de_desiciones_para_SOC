#!/usr/bin/env python3
"""
shadow_period_checkpoint.py — Checkpoint del período de modo sombra de 72 h (H53). Solo lectura.

Una pasada sobre los docs "response" T2+ de soc-responses-* desde el inicio
del período, pidiendo solo los campos necesarios (alcanza para ~600k docs) y
con salida en markdown, lista para anexar a la sección "Checkpoints" de
docs/PENDIENTES_MODO_SOMBRA.md. Mide los criterios de salida del período:

  1. Invariancia contra el gate binario (misma lógica que
     corroboration_shadow_report.py:matches_r2), sobre todos los T2+.
  2. Bloques /24 distintos con T3 puntuado (meta >= 100).
  3. T3 con corroboration_count >= N (meta >= 20; si no se llega, revisión
     humana de 50 IPs "high & no corroborado").
  4. P2: disponibilidad de TI en T3 NO-stale con IP pública fuera de la
     safelist (meta >= 95%), total y por proveedor.
  5. Bandas T3 y contingencia band x (count >= N).

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/shadow_period_checkpoint.py
    python3 ../scripts/shadow_period_checkpoint.py --until 2026-10-10T23:40:00Z

Código de salida: 0 si la invariancia se sostiene, 1 si hubo discrepancias.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from corroboration_shadow_report import iter_docs, matches_r2
from response.config import get_settings
from response.enforcer import is_safelisted
from response_audit_indexer import AuditIndexerSettings, OpenSearchClient

#: Período acordado el 2026-10-07: 20:40 -03 -> 2026-10-10 20:40 -03.
PERIOD_START = "2026-10-07T23:40:00Z"
PERIOD_HOURS = 72
GOAL_NETS_24 = 100
GOAL_T3_CORROBORATED = 20
GOAL_P2_PCT = 95.0
LOCAL_TZ = timezone(timedelta(hours=-3))

SOURCE = [
    "trace_id", "tier", "src_ip", "event_time", "corroboration_band", "corroboration_count",
    "payload.tier", "payload.src_ip", "payload.accion_recomendada", "payload.event_age_seconds",
    "payload.processed_at",
    "payload.block.action", "payload.block.enforced",
    "payload.enrichment.corroboration_count", "payload.enrichment.otx_available",
    "payload.enrichment.abuseipdb_available",
]


def _public(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip or "").is_global
    except ValueError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--since", default=PERIOD_START)
    ap.add_argument("--until", default=None)
    args = ap.parse_args()

    s = get_settings()
    client = OpenSearchClient(AuditIndexerSettings())
    min_n = s.min_corroborating_sources_for_autoblock

    total = mism = t3 = t3_corr = 0
    mism_ex: list[str] = []
    nets: set[str] = set()
    bands: Counter = Counter()
    cont: Counter = Counter()
    p2 = Counter()
    last_time = ""
    for d in iter_docs(client, args.since, args.until, source=SOURCE, min_tier=2):
        p = d.get("payload") or {}
        total += 1
        last_time = d.get("event_time", last_time)
        if not matches_r2(p, s):
            mism += 1
            if len(mism_ex) < 5:
                mism_ex.append(d.get("trace_id", "?"))
        if d.get("tier") != 3:
            continue
        t3 += 1
        band = d.get("corroboration_band") or "(sin score)"
        corr = (d.get("corroboration_count") or 0) >= min_n
        t3_corr += corr
        bands[band] += 1
        cont[(band, corr)] += 1
        ip = d.get("src_ip")
        if band != "(sin score)" and _public(ip):
            nets.add(".".join(ip.split(".")[:3]))
        age = p.get("event_age_seconds")
        fresh = age is not None and age <= s.stale_event_max_age_seconds
        if fresh and _public(ip) and not is_safelisted(ip, s):
            e = p.get("enrichment") or {}
            otx, abuse = bool(e.get("otx_available")), bool(e.get("abuseipdb_available"))
            p2["n"] += 1
            p2["any"] += otx or abuse
            p2["otx"] += otx
            p2["abuse"] += abuse

    now = datetime.now(LOCAL_TZ)
    start = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
    hours = (now - start).total_seconds() / 3600 if not args.until else PERIOD_HOURS
    pct = lambda a, b: f"{100 * a / b:.1f}%" if b else "n/d"
    p2_pct = 100 * p2["any"] / p2["n"] if p2["n"] else 0.0

    print(f"### Checkpoint {now:%Y-%m-%d %H:%M} -03 ({min(hours, PERIOD_HOURS):.1f}/{PERIOD_HOURS} h)\n")
    print(f"Ventana: `{args.since}` → `{args.until or last_time or 'ahora'}` · docs T2+: {total} · T3: {t3}\n")
    print("| Criterio | Valor | Meta | Estado |")
    print("|---|---|---|---|")
    print(f"| Invariancia contra el gate binario | {total - mism}/{total} | 100% | {'✅' if not mism else '❌ ' + ', '.join(mism_ex)} |")
    print(f"| /24 distintos con T3 puntuado | {len(nets)} | ≥ {GOAL_NETS_24} | {'✅' if len(nets) >= GOAL_NETS_24 else '⏳'} |")
    print(f"| T3 con corroboration_count ≥ {min_n} | {t3_corr} | ≥ {GOAL_T3_CORROBORATED} (o revisión de 50 IPs) | {'✅' if t3_corr >= GOAL_T3_CORROBORATED else '⏳'} |")
    print(f"| P2: TI disponible (T3 no-stale, IP pública) | {pct(p2['any'], p2['n'])} de {p2['n']} | ≥ {GOAL_P2_PCT:.0f}% | {'✅' if p2['n'] and p2_pct >= GOAL_P2_PCT else '⏳'} |")
    print(f"| · OTX / AbuseIPDB por separado | {pct(p2['otx'], p2['n'])} / {pct(p2['abuse'], p2['n'])} | — | — |")
    print(f"| Horas transcurridas | {min(hours, PERIOD_HOURS):.1f} | {PERIOD_HOURS} | {'✅' if hours >= PERIOD_HOURS else '⏳'} |")
    print()
    print("Bandas T3: " + ", ".join(f"{b} {n} ({pct(n, t3)})" for b, n in bands.most_common()))
    print()
    print(f"Contingencia T3 band × (count ≥ {min_n}): " + ", ".join(
        f"{b}: {cont[(b, True)]}/{cont[(b, False)]}" for b in ("high", "medium", "low", "ambiguous")
    ) + " (corroborado/no corroborado)")
    return 1 if mism else 0


if __name__ == "__main__":
    sys.exit(main())
