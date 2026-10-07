"""
Verifica motor/scoring/corroboration.py -- el score de corroboración
ponderado que reemplaza (propuesta, todavía NO wireado en worker.py) el
gate binario `corroboration_count >= 2`.

Casos cubiertos:
1. Renormalización sobre evidencia disponible -- sin classtype/contexto
   (el caso de PRODUCCIÓN hoy), solo ml+ti deben poder alcanzar la banda
   "high", sin que el techo quede capado en 45/100.
2. g_sig: disponible solo con classtype no vacío; 1.0 con T3+ATT&CK, 0.8
   con T3 sin ATT&CK, 0.3 con classtype no crítico.
3. g_ti: fusión sub-lineal (max + 30% del resto), ambas fuentes no
   disponibles -> grupo no disponible (no es 0).
4. g_ctx: siempre no disponible (no instrumentado).
5. Desacuerdo entre grupos marca `ambiguous=True` aunque el score agregado
   sea alto.
6. Degradación: función nunca lanza, incluso con enrichment=None.

Ver reports/Corroboracion ponderada para respuesta autonoma SOAR.md para
la justificación de diseño.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings
from response.schemas import EnrichmentResult
from scoring.corroboration import compute_corroboration


def _settings(**overrides) -> ResponseSettings:
    return ResponseSettings(**overrides)


class TestRenormalizacionSobreEvidenciaDisponible:
    """El caso de HOY en producción: classtype siempre vacío (H50), sin
    acumulador de contexto -- solo ml+ti disponibles."""

    def test_sin_classtype_ni_contexto_puede_igual_alcanzar_high(self) -> None:
        settings = _settings()
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=95,
            otx_available=True, otx_pulse_count=10,
        )
        result = compute_corroboration(
            risk_score=0.95, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        # Grupos disponibles: ml(20) + ti(25) = 45 de peso -> el score debe
        # renormalizarse sobre esos 45, NO quedar capado a 45/100.
        assert result.weight_available == 45.0
        assert result.score > 84.0  # alto risk_score + TI fuerte -> banda "high"
        assert result.band == "high"
        sig_group = next(g for g in result.groups if g.name == "signature")
        ctx_group = next(g for g in result.groups if g.name == "context")
        assert sig_group.available is False
        assert ctx_group.available is False

    def test_techo_no_queda_capado_en_45_cuando_solo_ml_y_ti_disponibles(self) -> None:
        """Si el bug de diseño existiera (sumar pesos sin renormalizar), el
        score máximo posible con solo ml+ti sería 45. Confirma que no es así."""
        settings = _settings()
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=100,
            otx_available=True, otx_pulse_count=50,
        )
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        assert result.score > 45.0
        assert result.score == 100.0  # ml=1.0, ti=1.0 -> renormalizado da 100


class TestGrupoFirma:
    def test_sin_classtype_grupo_no_disponible(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=settings,
        )
        sig = next(g for g in result.groups if g.name == "signature")
        assert sig.available is False

    def test_t3_classtype_con_attck_vale_1_0(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="trojan-activity", classtype_override=True,
            attack_mapped=True, enrichment=None, settings=settings,
        )
        sig = next(g for g in result.groups if g.name == "signature")
        assert sig.available is True
        assert sig.score == 1.0

    def test_t3_classtype_sin_attck_vale_0_8(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="trojan-activity", classtype_override=True,
            attack_mapped=False, enrichment=None, settings=settings,
        )
        sig = next(g for g in result.groups if g.name == "signature")
        assert sig.score == 0.8

    def test_classtype_no_critico_vale_0_3(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="misc-activity", classtype_override=False,
            attack_mapped=False, enrichment=None, settings=settings,
        )
        sig = next(g for g in result.groups if g.name == "signature")
        assert sig.score == 0.3


class TestGrupoTI:
    def test_ambas_fuentes_no_disponibles_grupo_no_disponible(self) -> None:
        settings = _settings()
        enrichment = EnrichmentResult(src_ip="1.2.3.4", abuseipdb_available=False, otx_available=False)
        result = compute_corroboration(
            risk_score=0.5, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        ti = next(g for g in result.groups if g.name == "ti")
        assert ti.available is False

    def test_fusion_sublineal_max_mas_30pct_del_resto(self) -> None:
        settings = _settings(corr_otx_pulse_saturation=10)
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=80,  # 0.8
            otx_available=True, otx_pulse_count=5,  # 0.5
        )
        result = compute_corroboration(
            risk_score=0.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        ti = next(g for g in result.groups if g.name == "ti")
        assert ti.available is True
        assert ti.score == 0.8 + 0.3 * 0.5  # 0.95, no 1.3 (capado) ni 0.8+0.5 (suma lineal)

    def test_una_sola_fuente_disponible_no_se_penaliza(self) -> None:
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=False, otx_available=True, otx_pulse_count=5,
        )
        result = compute_corroboration(
            risk_score=0.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=_settings(corr_otx_pulse_saturation=5),
        )
        ti = next(g for g in result.groups if g.name == "ti")
        assert ti.available is True
        assert ti.score == 1.0


class TestGrupoContexto:
    def test_siempre_no_disponible(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.9, classtype="trojan-activity", classtype_override=True,
            attack_mapped=True, enrichment=None, settings=settings,
        )
        ctx = next(g for g in result.groups if g.name == "context")
        assert ctx.available is False


class TestDesacuerdoEntreGrupos:
    def test_score_alto_por_desacuerdo_fuerte_queda_ambiguous(self) -> None:
        settings = _settings()
        # ml altísimo (1.0) pero TI no corrobora nada (score 0.0, disponible) -> desacuerdo.
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=0,
            otx_available=True, otx_pulse_count=0,
        )
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        assert result.ambiguous is True
        assert result.band == "ambiguous"

    def test_score_alto_por_consenso_no_es_ambiguous(self) -> None:
        settings = _settings()
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=90,
            otx_available=True, otx_pulse_count=10,
        )
        result = compute_corroboration(
            risk_score=0.9, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        assert result.ambiguous is False
        assert result.band == "high"


class TestDegradacionConGracia:
    def test_enrichment_none_no_lanza(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=settings,
        )
        assert result.score >= 0.0
        ti = next(g for g in result.groups if g.name == "ti")
        assert ti.available is False

    def test_reasoning_siempre_tiene_una_linea_por_grupo_mas_resumen(self) -> None:
        settings = _settings()
        result = compute_corroboration(
            risk_score=0.5, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=settings,
        )
        assert len(result.reasoning) == 5  # 4 grupos + 1 línea de resumen


class TestDiversidadMinimaParaHigh:
    """P3 (H53): ningún grupo solo alcanza para "high"."""

    def test_solo_ml_con_risk_1_queda_medium_nunca_high(self) -> None:
        """El caso de H52: sin TI, firma ni contexto, el score renormalizado
        es 100*ml (82,8 para el bastion .139). Con risk_score=1.0 da 100."""
        settings = _settings()
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=settings,
        )
        assert result.score == 100.0
        assert [g.name for g in result.groups if g.available] == ["ml"]
        assert result.band == "medium"
        assert result.ambiguous is False
        assert any("P3" in line for line in result.reasoning)

    def test_solo_ml_bajo_sigue_en_low(self) -> None:
        """El cap solo baja "high" a "medium": low/medium no cambian."""
        result = compute_corroboration(
            risk_score=0.2, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=_settings(),
        )
        assert result.band == "low"
        assert not any("P3" in line for line in result.reasoning)

    def test_ml_y_ti_altos_y_de_acuerdo_siguen_llegando_a_high(self) -> None:
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=90,
            otx_available=True, otx_pulse_count=10,
        )
        result = compute_corroboration(
            risk_score=0.9, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=_settings(),
        )
        assert len([g for g in result.groups if g.available]) == 2
        assert result.band == "high"

    def test_grupo_sin_peso_para_desacuerdo_igual_cuenta_para_diversidad(self) -> None:
        """Dos mecanismos distintos: con ti por debajo de
        corr_min_weight_for_disagreement, el desacuerdo no lo compara (un solo
        grupo comparable -> nunca ambiguous), pero la diversidad sí lo cuenta
        (2 disponibles -> "high" permitido)."""
        settings = _settings(corr_weight_ti=10.0)  # < corr_min_weight_for_disagreement (15)
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=40,
            otx_available=False,
        )
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=settings,
        )
        # (20*1.0 + 10*0.4) / 30 = 80 -> sobre el umbral de "high"
        assert result.score == 80.0
        assert result.ambiguous is False  # ml 1.0 vs ti 0.4 discrepan 0.6, pero ti no es comparable
        assert result.band == "high"

    def test_dos_grupos_en_desacuerdo_quedan_ambiguous_no_medium(self) -> None:
        """Con 2 grupos comparables que discrepan, manda el desacuerdo
        ("ambiguous"), no el cap de diversidad: son reglas independientes."""
        enrichment = EnrichmentResult(
            src_ip="1.2.3.4", abuseipdb_available=True, abuseipdb_score=0,
            otx_available=True, otx_pulse_count=0,
        )
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=enrichment, settings=_settings(),
        )
        assert result.band == "ambiguous"
        assert not any("P3" in line for line in result.reasoning)

    def test_umbral_configurable(self) -> None:
        """corr_min_groups_for_high=1 devuelve el comportamiento anterior."""
        result = compute_corroboration(
            risk_score=1.0, classtype="", classtype_override=False, attack_mapped=False,
            enrichment=None, settings=_settings(corr_min_groups_for_high=1),
        )
        assert result.band == "high"
