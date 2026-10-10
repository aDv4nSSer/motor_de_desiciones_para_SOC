"""
explain.py — Traza explicativa v1 de una decisión (H59).

Reconstruye, a partir de lo ya guardado en las cadenas (soc-decisions-* para
el Fast Path y el evento `response` de soc-responses-* para R1/R2), qué
señales entraron, con qué peso y qué regla fijó el tier y la acción. Es una
lectura: no vuelve a puntuar ni decide nada, y no la llama ningún camino de
decisión. Si la reconstrucción no coincide con lo guardado, lo dice
(`consistente: False`) en lugar de corregirlo.

Pesos y umbrales:
- risk_score = 0,70·ml_score + 0,30·anomaly_score (motor/model.py). Los pesos
  se repiten acá porque model.py carga el modelo al importarse; un test
  compara estos valores con el código de model.py.
- Umbrales de tier: el mismo archivo que carga el modelo (MODEL_DIR /
  thresholds_v6_latest.json) o, si no existe, los mismos valores por defecto.
- R1/R2: ResponseSettings (umbral de AbuseIPDB, pulses de OTX, fuentes
  mínimas para el autobloqueo, antigüedad máxima, tier mínimo de R2).

Limitación declarada: SHAP no está implementado; la traza explica la
combinación de scores y las reglas, no la contribución de cada feature al
ml_score.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from attck_mapping import lookup as attack_lookup
from constants import T3_CLASSTYPES

EXPLAIN_VERSION = "explain-v1"
RISK_WEIGHTS = {"ml_score": 0.70, "anomaly_score": 0.30}
DEFAULT_THRESHOLDS = {"T0_max": 0.25, "T1_max": 0.55, "T2_max": 0.80}
THRESHOLDS_FILE = Path(os.environ.get("MODEL_DIR", "/home/aiayala/tesis/motor/models")) / "thresholds_v6_latest.json"
# Tolerancia de la recomputación: risk_score, ml_score y anomaly_score se
# guardan redondeados a 4 decimales.
RISK_TOLERANCE = 0.0006
STALE_PREFIX = "stale_backlog"
SAFELIST_REASON = "safelisted"
SHAP_PENDING = ("SHAP no implementado: la traza explica la combinación de scores y las reglas, "
                "no la contribución de cada feature del flujo al ml_score.")

# Catálogo de reglas: id estable -> texto. La traza cita el id; el texto se
# completa con los valores del registro.
RULES: dict[str, str] = {
    "FP-T3-CLASSTYPE": "Override del Fast Path: el classtype {classtype} está en T3_CLASSTYPES, T3 sin importar el score.",
    "FP-TIER-T0": "risk_score {risk} <= T0_max {t0}: T0.",
    "FP-TIER-T1": "T0_max {t0} < risk_score {risk} <= T1_max {t1}: T1.",
    "FP-TIER-T2": "T1_max {t1} < risk_score {risk} <= T2_max {t2}: T2.",
    "FP-TIER-T3": "risk_score {risk} > T2_max {t2}: T3.",
    "R-SIN-ACCION": "Tier {tier} por debajo de T2: sin caso, sin aprobación y sin bloqueo.",
    "T2-CASO": "T2 de IP no propia: alerta y caso automático (sin bloqueo).",
    "T2-INFRA-PROPIA": "T2 cuyo origen es infraestructura propia del SOC: se registra, no abre caso.",
    "T2-STALE": "T2 con el evento más viejo que {stale}s: se registra la acción recomendada, sin caso.",
    "R2-STALE": "T3 con el evento más viejo que {stale}s: R2 no actúa; queda la acción que se habría recomendado.",
    "R2-CORROBORADO": "T3 con {count} fuentes corroborando (mínimo {min}): bloqueo automático ({outcome}).",
    "R2-SAFELIST": "T3 sobre una IP de la safelist (infraestructura del laboratorio): nunca se bloquea ni se ofrece aprobar.",
    "R2-PENDIENTE-APROBACION": "T3 con {count} de {min} fuentes: no alcanza para el autobloqueo, queda pendiente de aprobación humana.",
}


class GateSettings(Protocol):
    """Lo que la traza necesita de ResponseSettings."""
    r2_min_tier: int
    min_corroborating_sources_for_autoblock: int
    stale_event_max_age_seconds: int
    abuseipdb_malicious_threshold: int
    otx_min_pulse_count: int


def load_thresholds(path: Path = THRESHOLDS_FILE) -> tuple[dict[str, float], str]:
    """Umbrales de tier con su origen.

    Args:
        path: archivo de umbrales (el mismo que carga motor/model.py).

    Returns:
        (umbrales, origen): origen es la ruta del archivo o "valores por defecto".
    """
    try:
        with open(path) as f:
            data = json.load(f)
        return {k: float(data.get(k, DEFAULT_THRESHOLDS[k])) for k in DEFAULT_THRESHOLDS}, str(path)
    except (OSError, ValueError, TypeError):
        return dict(DEFAULT_THRESHOLDS), "valores por defecto (sin archivo de umbrales)"


def _rule(rule_id: str, **values: Any) -> dict[str, str]:
    return {"id": rule_id, "texto": RULES[rule_id].format(**values)}


def _tier_rule(risk: float, th: dict[str, float]) -> tuple[int, dict[str, str]]:
    t0, t1, t2 = th["T0_max"], th["T1_max"], th["T2_max"]
    values = {"risk": round(risk, 4), "t0": t0, "t1": t1, "t2": t2}
    if risk <= t0:
        return 0, _rule("FP-TIER-T0", **values)
    if risk <= t1:
        return 1, _rule("FP-TIER-T1", **values)
    if risk <= t2:
        return 2, _rule("FP-TIER-T2", **values)
    return 3, _rule("FP-TIER-T3", **values)


def explain_fast_path(decision: dict, thresholds: dict[str, float], thresholds_source: str) -> dict[str, Any]:
    """Señales, pesos y regla de tier de una decisión del Fast Path.

    Args:
        decision: documento de soc-decisions-* (o del índice legado).
        thresholds: umbrales T0_max, T1_max y T2_max.
        thresholds_source: de dónde salieron los umbrales.

    Returns:
        Bloque `fast_path` de la traza.
    """
    ml = float(decision.get("ml_score") or 0.0)
    anomaly = float(decision.get("anomaly_score") or 0.0)
    stored_risk = float(decision.get("risk_score") or 0.0)
    signals = [
        {"senal": "ml_score", "fuente": "LightGBM calibrado (probabilidad de ataque)", "valor": ml,
         "peso": RISK_WEIGHTS["ml_score"], "aporte": round(RISK_WEIGHTS["ml_score"] * ml, 4)},
        {"senal": "anomaly_score", "fuente": "Isolation Forest de red (anomalía normalizada 0-1)", "valor": anomaly,
         "peso": RISK_WEIGHTS["anomaly_score"], "aporte": round(RISK_WEIGHTS["anomaly_score"] * anomaly, 4)},
    ]
    recomputed = RISK_WEIGHTS["ml_score"] * ml + RISK_WEIGHTS["anomaly_score"] * anomaly
    classtype = decision.get("classtype")
    stored_tier = decision.get("tier")
    if classtype and str(classtype).lower() in T3_CLASSTYPES:
        tier, rule = 3, _rule("FP-T3-CLASSTYPE", classtype=classtype)
    else:
        tier, rule = _tier_rule(stored_risk, thresholds)
    out: dict[str, Any] = {
        "senales": signals,
        "risk_score": stored_risk,
        "risk_score_recalculado": round(recomputed, 4),
        "tier": stored_tier,
        "tier_recalculado": tier,
        "regla": rule,
        "umbrales": {**thresholds, "origen": thresholds_source},
        "features": {k: decision.get(k) for k in ("L4_DST_PORT", "OUT_PKTS", "DURATION_MS", "SERVER_FLAGS") if k in decision},
        "consistente": abs(recomputed - stored_risk) <= RISK_TOLERANCE and stored_tier == tier,
    }
    entry = attack_lookup(classtype) if classtype else None
    out["attack"] = ({"classtype": classtype, "tactica": entry.tactic_id, "tecnica": entry.technique_id,
                      "tecnica_nombre": entry.technique_name, "confianza": entry.confidence}
                     if entry else {"classtype": classtype, "nota": "sin classtype en la decisión (H50): sin mapeo ATT&CK"})
    return out


def _sources(enrichment: dict, s: GateSettings) -> list[dict[str, Any]]:
    """Cada fuente de R1 como señal del gate binario (peso 1 si corrobora)."""
    abuse = enrichment.get("abuseipdb_score")
    otx = enrichment.get("otx_pulse_count")
    corroborating = set(enrichment.get("corroborating_sources") or [])
    return [
        {"senal": "abuseipdb", "valor": abuse, "umbral": f">= {s.abuseipdb_malicious_threshold}",
         "disponible": bool(enrichment.get("abuseipdb_available")), "corrobora": "abuseipdb" in corroborating, "peso_gate": 1},
        {"senal": "otx", "valor": otx, "umbral": f">= {s.otx_min_pulse_count} pulses",
         "disponible": bool(enrichment.get("otx_available")), "corrobora": "otx" in corroborating, "peso_gate": 1},
        {"senal": "crowdsec", "valor": enrichment.get("crowdsec_scenario"),
         "observado": bool(enrichment.get("crowdsec_observado")), "corrobora": False, "peso_gate": 0,
         "nota": "observado, no cuenta para el gate (sección 4 de la especificación)"},
    ]


def explain_response(payload: dict, s: GateSettings) -> dict[str, Any]:
    """Regla de R1/R2 que explica la acción guardada en un evento `response`.

    Args:
        payload: payload del evento response (ResponseRecord.to_audit_dict()).
        s: configuración del gate (ResponseSettings).

    Returns:
        Bloque `respuesta` de la traza, con `consistente` si la regla
        reconstruida produce la acción guardada.
    """
    tier = int(payload.get("tier") or 0)
    enrichment = payload.get("enrichment") or {}
    count = int(enrichment.get("corroboration_count") or 0)
    block = payload.get("block") or {}
    action, reason = block.get("action"), str(block.get("reason") or "")
    accion = payload.get("accion_recomendada")
    stale = s.stale_event_max_age_seconds
    minimum = s.min_corroborating_sources_for_autoblock
    corroborated = count >= minimum

    if tier < 2:
        rule, expected = _rule("R-SIN-ACCION", tier=tier), action in (None, "noop")
    elif tier < s.r2_min_tier:
        if accion == "ninguna_infra_propia":
            rule, expected = _rule("T2-INFRA-PROPIA"), True
        elif payload.get("case_id"):
            rule, expected = _rule("T2-CASO"), accion == "alertar_crear_caso"
        else:
            rule, expected = _rule("T2-STALE", stale=stale), accion == "alertar_crear_caso"
    elif reason.startswith(STALE_PREFIX):
        rule, expected = _rule("R2-STALE", stale=stale), action == "block_skipped"
    elif corroborated:
        rule = _rule("R2-CORROBORADO", count=count, min=minimum, outcome=reason or action or "sin detalle")
        expected = action in ("block", "block_skipped")
    elif reason.startswith(SAFELIST_REASON):
        rule, expected = _rule("R2-SAFELIST"), action == "block_skipped"
    else:
        rule = _rule("R2-PENDIENTE-APROBACION", count=count, min=minimum)
        expected = action == "block_pending_approval"

    out: dict[str, Any] = {
        "r1": {"senales": _sources(enrichment, s), "corroboration_count": count,
               "notas": [n for n in enrichment.get("notes") or [] if isinstance(n, str)]},
        "r2": {"regla": rule, "accion_recomendada": accion, "accion": action,
               "ejecutado": bool(block.get("enforced")), "motivo": reason or None,
               "minimo_fuentes": minimum, "edad_evento_s": payload.get("event_age_seconds")},
        "consistente": bool(expected),
    }
    if payload.get("corroboration_band"):
        out["sombra"] = {
            "nota": "score de corroboración ponderado en modo sombra: se audita, no decide",
            "score": payload.get("corroboration_score"), "banda": payload.get("corroboration_band"),
            "grupos": [{"grupo": g.get("name"), "disponible": g.get("available"), "score": g.get("score"),
                        "peso": g.get("weight"), "detalle": g.get("detail")}
                       for g in payload.get("corroboration_groups") or []],
        }
    alert = payload.get("correlated_alert") or {}
    if alert.get("classtype"):
        entry = attack_lookup(alert["classtype"])
        out["attack_alerta_correlacionada"] = ({"classtype": alert["classtype"], "tecnica": entry.technique_id,
                                                "tecnica_nombre": entry.technique_name} if entry else
                                               {"classtype": alert["classtype"], "nota": "classtype sin mapeo"})
    return out


def explain_trace(trace: dict, s: GateSettings, thresholds_path: Path = THRESHOLDS_FILE) -> dict[str, Any]:
    """Traza explicativa a partir de audit_view.search_trace().

    Args:
        trace: salida de search_trace (decisiones y eventos con su verificación).
        s: configuración del gate.
        thresholds_path: archivo de umbrales de tier.

    Returns:
        {"version", "trace_id", "fast_path", "respuesta", "integridad", "limitaciones"};
        cada bloque es None si no hay registro de esa etapa.
    """
    thresholds, source = load_thresholds(thresholds_path)
    decision = next((d for d in trace.get("decisions") or [] if d.get("chain") == "soc-decisions-*"), None) \
        or next(iter(trace.get("decisions") or []), None)
    response = next((e for e in trace.get("events") or [] if (e.get("doc") or {}).get("event_type") == "response"), None)
    return {
        "version": EXPLAIN_VERSION,
        "trace_id": trace.get("trace_id"),
        "fast_path": explain_fast_path(decision["doc"], thresholds, source) if decision else None,
        "respuesta": explain_response((response["doc"] or {}).get("payload") or {}, s) if response else None,
        "integridad": {
            "decision": (decision or {}).get("verification"),
            "respuesta": (response or {}).get("verification"),
        },
        "limitaciones": [SHAP_PENDING],
    }
