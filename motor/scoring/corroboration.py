"""
scoring/corroboration.py — Score de corroboración ponderado multi-grupo.

Reemplaza el gate binario `corroboration_count >= 2` (motor/response/
worker.py, enrichment.py:count_corroborating_sources) por un score 0-100
fusionado sobre 4 grupos de evidencia -- ver reports/Corroboracion
ponderada para respuesta autonoma SOAR.md (investigación aprobada
7-oct-2026) para la justificación contra literatura (Dempster-Shafer
contextual discounting, Covariance Intersection) y plataformas reales
(XSOAR DBotScore, OpenCTI Reliability/Confidence, Cyware CTIX).

PRINCIPIO CENTRAL -- renormalización sobre evidencia disponible:
Hoy, de los 4 grupos de la propuesta original, solo 2 están realmente
instrumentados en producción:
  - g_ml:  SIEMPRE disponible (motor/model.py ya calcula risk_score).
  - g_ti:  disponible si AbuseIPDB u OTX respondieron (enrichment.py).
  - g_sig: NO disponible en producción (H50 -- Vector no manda classtype
           al Fast Path todavía). Queda listo para activarse solo con ese
           fix, sin tocar este módulo otra vez.
  - g_ctx: NO existe ningún instrumento (sin historical-context-svc, sin
           acumulador Redis de riesgo por entidad). Siempre no disponible.

Si se calculara `C = 0.35*g_sig + 0.25*g_ti + 0.20*g_ml + 0.20*g_ctx` con
g_sig=g_ctx=0 SIEMPRE (porque no es que la evidencia sea negativa, es que
no existe el instrumento), el techo alcanzable HOY sería 45/100 -- nunca
llegaría a la banda "high" y el bloqueo autónomo sería *más* difícil que
hoy, una regresión real. Por eso cada grupo no disponible se excluye del
denominador (no se cuenta como 0): `C = 100 * Σ(w_i·g_i disponibles) /
Σ(w_i disponibles)`. El mismo principio que enrichment.py ya aplica a nivel
de fuente individual ("una fuente no disponible no cuenta ni a favor ni en
contra"), extendido a nivel de grupo. Cuando g_sig/g_ctx se instrumenten,
el mismo código empieza a darles su peso real sin ningún cambio aquí.
"""
from __future__ import annotations

from response.config import ResponseSettings
from response.schemas import EnrichmentResult
from scoring.schemas import CorroborationResult, GroupScore


def _score_ml_group(risk_score: float, weight: float) -> GroupScore:
    """g_ml: siempre disponible -- motor/model.py ya calcula risk_score
    (0.70*ml_score + 0.30*anomaly_score, calibrado isotónicamente)."""
    score = max(0.0, min(1.0, risk_score))
    return GroupScore(
        name="ml", available=True, score=score, weight=weight,
        detail=f"risk_score={score:.3f} (LightGBM Golden4 v7.1 + IsolationForest)",
    )


def _score_ti_group(
    enrichment: EnrichmentResult | None, settings: ResponseSettings, weight: float,
) -> GroupScore:
    """
    g_ti: fusión sub-lineal de AbuseIPDB + OTX, normalizados a [0,1] cada
    uno ANTES de combinar (distinto del conteo binario de
    count_corroborating_sources -- acá sí importa la magnitud, no solo si
    pasó un umbral). CrowdSec se deja deliberadamente fuera: sigue siendo
    solo observacional por decisión explícita (H37 Fase 3, reafirmada
    5-oct-2026 -- redundante con OTX, sin señal nueva medida en este
    entorno). Regla sub-lineal (max + 30% del resto, capada a 1.0) para no
    tratar dos fuentes de TI como evidencia totalmente independiente
    cuando en la práctica comparten feeds/heurísticas subyacentes --
    mismo principio que Covariance Intersection en fusión de sensores.

    Disponible si AL MENOS UNA fuente respondió (no "unavailable"); si
    ambas fallaron/no están configuradas, el grupo completo queda
    `available=False` -- ausencia de dato no es evidencia de nada, ni a
    favor ni en contra (mismo criterio que ya documenta enrichment.py).
    """
    if enrichment is None:
        return GroupScore(name="ti", available=False, weight=weight, detail="sin enrichment (R1 no corrió)")

    normalized: list[float] = []
    detail_parts: list[str] = []

    if enrichment.abuseipdb_available and enrichment.abuseipdb_score is not None:
        n = max(0.0, min(1.0, enrichment.abuseipdb_score / 100.0))
        normalized.append(n)
        detail_parts.append(f"abuseipdb={enrichment.abuseipdb_score}/100")

    if enrichment.otx_available and enrichment.otx_pulse_count is not None:
        sat = max(1, settings.corr_otx_pulse_saturation)
        n = max(0.0, min(1.0, enrichment.otx_pulse_count / sat))
        normalized.append(n)
        detail_parts.append(f"otx={enrichment.otx_pulse_count} pulses (sat={sat})")

    if not normalized:
        return GroupScore(
            name="ti", available=False, weight=weight,
            detail="ninguna fuente de TI disponible (cuota/timeout/sin config)",
        )

    normalized.sort(reverse=True)
    score = normalized[0] + 0.3 * sum(normalized[1:])
    score = max(0.0, min(1.0, score))
    return GroupScore(name="ti", available=True, score=score, weight=weight, detail="; ".join(detail_parts))


def _score_signature_group(
    classtype: str, classtype_override: bool, attack_mapped: bool, weight: float,
) -> GroupScore:
    """
    g_sig: evidencia determinística (firma Suricata + ATT&CK). NO
    disponible si `classtype` llega vacío -- hoy SIEMPRE el caso en
    producción (H50: Vector no manda el header X-Suricata-Classtype al
    Fast Path). Este grupo se activa solo cuando ese gap se cierre, sin
    tocar este módulo.

    Dentro de "disponible", dos niveles (no binario 0/1): 1.0 si el
    classtype es de la lista T3_CLASSTYPES (firma madura, bajo FP
    histórico conocido -- ver motor/main.py:T3_CLASSTYPES) Y tiene técnica
    ATT&CK mapeada; 0.6 si hay classtype pero no es T3-crítico o no mapea a
    ATT&CK -- evita que "cualquier classtype" valga lo mismo que una firma
    crítica confirmada (riesgo de FP documentado: Suricata define classtype
    como categoría de IMPACTO, no de certeza -- ver reports/Corroboracion
    ponderada... sección 2). La variante "kill chain progression" (segunda
    técnica ATT&CK distinta en la misma entidad, ventana corta) queda fuera
    de este grupo hasta que exista el acumulador de contexto -- ver g_ctx.
    """
    if not classtype:
        return GroupScore(
            name="signature", available=False, weight=weight,
            detail="sin classtype (Vector no lo manda al Fast Path -- H50)",
        )

    if classtype_override and attack_mapped:
        return GroupScore(
            name="signature", available=True, score=1.0, weight=weight,
            detail=f"classtype='{classtype}' en T3_CLASSTYPES + técnica ATT&CK mapeada",
        )
    if classtype_override:
        return GroupScore(
            name="signature", available=True, score=0.8, weight=weight,
            detail=f"classtype='{classtype}' en T3_CLASSTYPES, sin mapeo ATT&CK",
        )
    return GroupScore(
        name="signature", available=True, score=0.3, weight=weight,
        detail=f"classtype='{classtype}' presente, no crítico",
    )


def _score_context_group(weight: float) -> GroupScore:
    """g_ctx: recidivismo/kill-chain por entidad. NO existe ningún
    instrumento todavía -- no hay historical-context-svc ni acumulador
    Redis de riesgo por entidad (verificado contra el repo real, 7-oct-2026:
    cero referencias a `risk:{entity_type}:{entity_id}` o equivalente).
    Siempre `available=False` hasta construirlo; no es un placeholder a
    medias, es honestidad sobre lo que hoy no se puede calcular."""
    return GroupScore(
        name="context", available=False, weight=weight,
        detail="no instrumentado (sin acumulador de riesgo por entidad ni recidivismo)",
    )


def _band(score: float, ambiguous: bool, n_available: int, settings: ResponseSettings) -> str:
    """La ambigüedad viene SIEMPRE del desacuerdo entre grupos (ver
    `ambiguous` en compute_corroboration), nunca de un techo de score --
    un score=95 por consenso de todos los grupos disponibles es, si acaso,
    MÁS confiable que uno de 75, no menos. `corr_band_high_max` queda solo
    como referencia documental de dónde empieza "alta confianza" para
    dashboards/reasoning, no como un segundo gate hacia "ambiguous".

    P3 (H53): "high" exige al menos `corr_min_groups_for_high` grupos
    disponibles. Con menos, el máximo es "medium" -- la renormalización
    hace que un único grupo valga 100% del score, y eso no es
    corroboración (caso real de H52: T3 con ML solo -> 82,8 -> "high",
    incluido el propio bastion .139)."""
    if ambiguous:
        return "ambiguous"
    if score <= settings.corr_band_low_max:
        return "low"
    if score <= settings.corr_band_medium_max:
        return "medium"
    if n_available < settings.corr_min_groups_for_high:
        return "medium"
    return "high"


def compute_corroboration(
    *,
    risk_score: float,
    classtype: str,
    classtype_override: bool,
    attack_mapped: bool,
    enrichment: EnrichmentResult | None,
    settings: ResponseSettings,
) -> CorroborationResult:
    """
    Punto de entrada único. Pura (sin IO, sin Redis) -- todos los insumos ya
    fueron calculados por el Fast Path (risk_score, classtype*) o por R1
    (enrichment). Nunca lanza excepción: cualquier grupo que no se pueda
    calcular queda `available=False` en vez de romper la llamada, mismo
    criterio de degradación con gracia que el resto del proyecto.
    """
    groups = [
        _score_ml_group(risk_score, settings.corr_weight_ml),
        _score_ti_group(enrichment, settings, settings.corr_weight_ti),
        _score_signature_group(classtype, classtype_override, attack_mapped, settings.corr_weight_signature),
        _score_context_group(settings.corr_weight_context),
    ]

    available = [g for g in groups if g.available]
    weight_available = sum(g.weight for g in available)

    if not available or weight_available <= 0:
        # No debería ocurrir (g_ml siempre disponible) -- fallback explícito
        # en vez de dividir por cero.
        return CorroborationResult(
            score=0.0, band="low", ambiguous=False, groups=groups, weight_available=0.0,
            reasoning=["ningún grupo de evidencia disponible -- score 0 por defecto"],
        )

    raw = sum(g.score * g.weight for g in available)
    score = 100.0 * raw / weight_available

    # Desacuerdo: entre los grupos disponibles con peso suficiente para
    # importar, ¿el más alto y el más bajo difieren fuerte? Un score=75 por
    # consenso no es lo mismo que uno por un grupo en 1.0 contra otro en 0.0.
    comparable = [g for g in available if g.weight >= settings.corr_min_weight_for_disagreement]
    ambiguous = False
    if len(comparable) >= 2:
        scores = [g.score for g in comparable]
        if max(scores) - min(scores) >= settings.corr_disagreement_threshold:
            ambiguous = True

    band = _band(score, ambiguous, len(available), settings)

    reasoning = [g.detail for g in groups]
    reasoning.append(
        f"score={score:.1f}/100 sobre {weight_available:.0f}/100 de peso disponible "
        f"({len(available)}/{len(groups)} grupos instrumentados)"
    )
    if (not ambiguous and score > settings.corr_band_medium_max
            and len(available) < settings.corr_min_groups_for_high):
        reasoning.append(
            f"band limitada a 'medium': {len(available)} grupo(s) disponible(s), "
            f"'high' exige {settings.corr_min_groups_for_high} (P3)"
        )
    if ambiguous:
        reasoning.append(
            "grupos de evidencia en desacuerdo fuerte -- escalado a aprobación aunque "
            "el score agregado sea alto"
        )

    return CorroborationResult(
        score=round(score, 1), band=band, ambiguous=ambiguous,
        groups=groups, weight_available=weight_available, reasoning=reasoning,
    )
