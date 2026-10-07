#!/usr/bin/env python3
"""
corroboration_shadow_report.py — Modo sombra del score de corroboración (H52). Solo lectura.

Lee los documentos event_type="response" de soc-responses-* en una ventana y reporta:

1. INVARIANCIA: para cada doc, recalcula la accion_recomendada / block_action
   que da la rama R2 de response/worker.py con los insumos guardados (tier,
   enrichment.corroboration_count, safelist, event_age_seconds vs. el umbral
   stale) y la compara con lo registrado. Debe dar 100% de coincidencia: el
   score en sombra no decide nada.
2. Distribución tier x accion_recomendada x block_action x block_enforced.
3. Contingencia sobre T3: corroboration_band x (corroboration_count >= N),
   con las discrepancias high & no-corroborado y no-high & corroborado
   listadas por trace_id. Es la comparación que decide si el score puede
   reemplazar al gate (decisión de Antonio, no de este script).

Excluye siempre la ventana sin datos reales del Fast Path de H25
(2026-08-18 a 2026-09-04).

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/corroboration_shadow_report.py --since 2026-10-07T15:00:00Z
    python3 ../scripts/corroboration_shadow_report.py --since now-24h --max-list 50
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "motor"))

from response.config import get_settings
from response.enforcer import is_safelisted
from response.schemas import (
    ACCION_ALERTAR_CREAR_CASO,
    ACCION_ALERTAR_PENDIENTE_APROBACION,
    ACCION_BLOQUEO_IP,
    ACCION_NINGUNA,
    ActionType,
)
from response_audit_indexer import AuditIndexerSettings, OpenSearchClient

H25_EXCLUDED = {"gte": "2026-08-18T00:00:00-03:00", "lt": "2026-09-05T00:00:00-03:00"}
PAGE = 1000


def expected_r2_options(payload: dict, settings) -> list[tuple[str, str | None]]:
    """Resultados admisibles de expected_r2(). event_age_seconds se audita
    redondeado a 0.1 s y el worker compara la edad sin redondear: si quedó a
    <= 0.05 s del umbral stale, no se puede saber de qué lado cayó y se
    aceptan ambas ramas."""
    age = payload.get("event_age_seconds")
    limit = settings.stale_event_max_age_seconds
    if age is None or abs(age - limit) > 0.05:
        return [expected_r2(payload, settings)]
    return [expected_r2({**payload, "event_age_seconds": limit + 1}, settings),
            expected_r2({**payload, "event_age_seconds": limit - 1}, settings)]


def expected_r2(payload: dict, settings) -> tuple[str, str | None]:
    """(accion_recomendada, block_action) que produce process_task() para
    este registro, recalculado desde los insumos guardados. Para el caso
    corroborado no-stale, la acción depende de respond_block (bloqueo nuevo,
    ya bloqueada, safelist): se acepta lo registrado si es coherente con su
    propia accion_recomendada, y se devuelve block_action=None ("cualquiera
    de BLOCK/BLOCK_SKIPPED")."""
    tier = payload.get("tier", 0)
    e = payload.get("enrichment") or {}
    count = e.get("corroboration_count", 0) if e else 0
    corroborated = count >= settings.min_corroborating_sources_for_autoblock
    src_ip = payload.get("src_ip")
    safelisted = bool(src_ip and is_safelisted(src_ip, settings))
    age = payload.get("event_age_seconds")
    stale = age is not None and age > settings.stale_event_max_age_seconds

    accion = ACCION_ALERTAR_CREAR_CASO if tier == 2 else ACCION_NINGUNA
    if tier < settings.r2_min_tier:
        return accion, "absent"
    if stale:
        if safelisted:
            return ACCION_NINGUNA, ActionType.BLOCK_SKIPPED.value
        if corroborated:
            return ACCION_BLOQUEO_IP, ActionType.BLOCK_SKIPPED.value
        return ACCION_ALERTAR_PENDIENTE_APROBACION, ActionType.BLOCK_SKIPPED.value
    if corroborated:
        recorded = (payload.get("block") or {}).get("action")
        if recorded == ActionType.BLOCK.value:
            return ACCION_BLOQUEO_IP, recorded
        return ACCION_NINGUNA, None
    if safelisted:
        return ACCION_NINGUNA, ActionType.BLOCK_SKIPPED.value
    return ACCION_ALERTAR_PENDIENTE_APROBACION, ActionType.BLOCK_PENDING_APPROVAL.value


def iter_docs(client: OpenSearchClient, since: str, until: str | None):
    rng = {"gte": since, **({"lt": until} if until else {})}
    query = {"bool": {
        "filter": [{"term": {"event_type": "response"}}, {"range": {"event_time": rng}}],
        "must_not": [{"range": {"event_time": H25_EXCLUDED}}]}}
    search_after = None
    while True:
        body = {"size": PAGE, "query": query, "sort": [{"chain_seq": "asc"}]}
        if search_after is not None:
            body["search_after"] = search_after
        r = client.request("POST", "/soc-responses-*/_search", body)
        r.raise_for_status()
        hits = r.json()["hits"]["hits"]
        if not hits:
            return
        yield from (h["_source"] for h in hits)
        search_after = hits[-1]["sort"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--since", required=True, help="inicio (ISO o date math, ej. now-24h)")
    ap.add_argument("--until", default=None)
    ap.add_argument("--max-list", type=int, default=20, help="discrepancias a listar por tipo")
    args = ap.parse_args()

    settings = get_settings()
    client = OpenSearchClient(AuditIndexerSettings())
    min_n = settings.min_corroborating_sources_for_autoblock

    total = mismatches = with_shadow = 0
    mismatch_examples: list[str] = []
    dist: Counter = Counter()
    contingency: Counter = Counter()
    high_not_corr: list[str] = []
    corr_not_high: list[str] = []
    shadow_examples: list[str] = []

    for d in iter_docs(client, args.since, args.until):
        p = d.get("payload") or {}
        total += 1
        block = p.get("block") or {}
        rec_accion = p.get("accion_recomendada")
        rec_action = block.get("action", "absent")
        dist[(d.get("tier"), rec_accion, rec_action, block.get("enforced"))] += 1

        ok = False
        options = expected_r2_options(p, settings)
        for exp_accion, exp_action in options:
            match = rec_accion == exp_accion and (exp_action is None or rec_action == exp_action)
            if exp_action is None:  # corroborado: coherencia interna con respond_block
                match = match and rec_action in (ActionType.BLOCK.value, ActionType.BLOCK_SKIPPED.value)
            ok = ok or match
        exp_accion, exp_action = options[0]
        if rec_action != "absent":  # enforced solo si hubo bloqueo real (enforcer.respond_block)
            ok = ok and bool(block.get("enforced")) == (rec_action == ActionType.BLOCK.value)
        if not ok:
            mismatches += 1
            if len(mismatch_examples) < args.max_list:
                mismatch_examples.append(
                    f"{d.get('trace_id')} T{d.get('tier')} registrado=({rec_accion},{rec_action}) "
                    f"esperado=({exp_accion},{exp_action})")

        band = d.get("corroboration_band")
        if band:
            with_shadow += 1
            if len(shadow_examples) < 3:
                shadow_examples.append(
                    f"{d.get('trace_id')} T{d.get('tier')} score={d.get('corroboration_score')} "
                    f"band={band} count={d.get('corroboration_count')}")
        if d.get("tier") == 3 and band:
            corr = (d.get("corroboration_count") or 0) >= min_n
            contingency[(band, corr)] += 1
            if band == "high" and not corr and len(high_not_corr) < args.max_list:
                high_not_corr.append(f"{d.get('trace_id')} score={d.get('corroboration_score')} "
                                     f"count={d.get('corroboration_count')} ip={d.get('src_ip')}")
            if band != "high" and corr and len(corr_not_high) < args.max_list:
                corr_not_high.append(f"{d.get('trace_id')} band={band} score={d.get('corroboration_score')} "
                                     f"count={d.get('corroboration_count')} ip={d.get('src_ip')}")

    print(f"ventana: {args.since} -> {args.until or 'ahora'} | docs response: {total} "
          f"| con score sombra: {with_shadow}")
    print(f"\n== 1. Invariancia R2: {total - mismatches}/{total} coinciden ({mismatches} discrepancias)")
    for m in mismatch_examples:
        print("   ", m)

    print("\n== 2. Distribución tier x accion_recomendada x block_action x block_enforced")
    for (tier, acc, act, enf), n in sorted(dist.items(), key=lambda kv: (str(kv[0][0]), -kv[1])):
        print(f"   T{tier} {acc!s:30} {act!s:24} enforced={enf!s:5} {n}")
    t3 = sum(n for (t, *_), n in dist.items() if t == 3)
    t3p = sum(n for (t, acc, *_), n in dist.items() if t == 3 and acc == ACCION_ALERTAR_PENDIENTE_APROBACION)
    if t3:
        print(f"   T3 pendiente de aprobación: {t3p}/{t3} = {100 * t3p / t3:.1f}%")

    print(f"\n== 3. Contingencia T3: band x (corroboration_count >= {min_n})")
    for band in ("low", "medium", "high", "ambiguous"):
        print(f"   {band:9} corroborado={contingency[(band, True)]:6}  no_corroborado={contingency[(band, False)]:6}")
    t3s = sum(contingency.values())
    if t3s:
        print(f"   band==high: {sum(n for (b, _), n in contingency.items() if b == 'high')}/{t3s}")
    print(f"   high & no corroborado (primeros {args.max_list}):")
    for x in high_not_corr:
        print("     ", x)
    print(f"   no-high & corroborado (primeros {args.max_list}):")
    for x in corr_not_high:
        print("     ", x)
    print("\nejemplos con score sombra:")
    for x in shadow_examples:
        print("   ", x)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
