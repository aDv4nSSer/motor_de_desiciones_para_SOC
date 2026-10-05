"""
Verifica el wiring de rules.yaml dentro de response/worker.py:process_task.

Confirma dos cosas separadas:
1. El motor de reglas es estrictamente ADITIVO -- rules_fired/reasoning se
   pueblan para T2+, quedan vacíos para T0/T1, y en ningún caso cambian
   record.block/record.accion_recomendada/record.case_id (la decisión real
   la sigue tomando la lógica existente de process_task, no rules.yaml).
2. Degradación con gracia -- si evaluate()/rules.yaml falla por cualquier
   motivo, la decisión real sigue firme y solo se pierde la explicación.

Ver motor/rules/rules.yaml para las reglas reales y
response/worker.py:_rule_context() para el contrato de campos.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings
from response.schemas import ActionType, EnrichmentResult, ResponseTask
from response.worker import _rule_context, process_task
from rules.engine import EvaluationResult


def _settings(**overrides) -> ResponseSettings:
    base = {
        "r1_min_tier": 1,
        "r2_min_tier": 3,
        "min_corroborating_sources_for_autoblock": 2,
        "response_mode": "dry_run",
    }
    base.update(overrides)
    return ResponseSettings(**base)


def _task(tier: int, classtype_override: bool = False) -> ResponseTask:
    return ResponseTask(
        trace_id="trace-rules-1", tier=tier, risk_score=0.9,
        src_ip="1.2.3.5", dst_ip="10.10.10.3", L4_DST_PORT=443,
        classtype_override=classtype_override,
    )


class TestRuleContext:
    """_rule_context() -- el mapeo de hechos que recibe evaluate()."""

    def test_sin_enrichment_usa_defaults_seguros(self) -> None:
        from response.schemas import ResponseRecord

        task = _task(tier=2)
        record = ResponseRecord(trace_id=task.trace_id, tier=2, risk_score=0.5)
        ctx = _rule_context(task, record, stale=False, safelisted=False)

        assert ctx["corroboration_count"] == 0
        assert ctx["corroborating_sources"] == []
        assert ctx["crowdsec_observado"] is False
        # otx/abuseipdb "no disponible" solo cuando REALMENTE fallaron -- sin
        # enrichment en absoluto no es lo mismo que una API caída, así que el
        # default es "disponible" (no dispara R011 de forma espuria).
        assert ctx["otx_available"] is True
        assert ctx["abuseipdb_available"] is True

    def test_con_enrichment_propaga_valores_reales(self) -> None:
        from response.schemas import ResponseRecord

        task = _task(tier=3, classtype_override=True)
        record = ResponseRecord(trace_id=task.trace_id, tier=3, risk_score=0.95)
        record.enrichment = EnrichmentResult(
            src_ip="1.2.3.5", corroboration_count=2,
            corroborating_sources=["abuseipdb", "otx"],
            crowdsec_observado=True, otx_available=False,
        )
        ctx = _rule_context(task, record, stale=True, safelisted=True)

        assert ctx["tier"] == 3
        assert ctx["classtype_override"] is True
        assert ctx["corroboration_count"] == 2
        assert ctx["corroborating_sources"] == ["abuseipdb", "otx"]
        assert ctx["crowdsec_observado"] is True
        assert ctx["is_safelisted"] is True
        assert ctx["is_stale"] is True
        assert ctx["otx_available"] is False
        assert ctx["abuseipdb_available"] is True


class TestWiringAditivoNoCambiaLaDecisionReal:
    def test_t3_con_classtype_override_dispara_r001_sin_cambiar_el_bloqueo(
        self, mocker
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="1.2.3.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(
                action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado",
                enforcer="dry_run",
            ),
        )

        record = process_task(_task(tier=3, classtype_override=True), settings, rdb, enforcer)

        # La decisión real (verificada ya en test_response_worker_gating.py)
        # no cambia por el motor de reglas:
        assert record.block.action == ActionType.BLOCK
        # Pero ahora trae su explicación:
        assert "R001_classtype_override_t3" in record.rules_fired
        assert "R008_corroboracion_suficiente_t3" in record.rules_fired
        assert record.rules_total_weight > 0
        assert len(record.reasoning) == len(record.rules_fired)

    def test_t3_corroboracion_insuficiente_dispara_r007_sin_cambiar_la_aprobacion_pendiente(
        self, mocker
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="1.2.3.5", corroboration_count=1,
                corroborating_sources=["abuseipdb"],
            ),
        )
        respond_block = mocker.patch("response.worker.respond_block")
        mocker.patch("response.worker.create_pending_approval")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL
        assert record.block.requires_approval is True
        assert "R007_corroboracion_insuficiente_t3" in record.rules_fired

    def test_t2_dispara_r003_sin_cambiar_la_apertura_de_caso(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="1.2.3.5"),
        )
        mocker.patch(
            "response.worker.open_case",
            return_value={"case_id": "case-123"},
        )

        record = process_task(_task(tier=2), settings, rdb, enforcer)

        assert record.case_id == "case-123"
        assert "R003_t2_score_medio" in record.rules_fired

    def test_t0_y_t1_no_generan_rules_fired(self, mocker) -> None:
        settings = _settings(r1_min_tier=5)  # evita que R1 corra igual
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")
        enrich_mock = mocker.patch("response.worker.enrich")

        record0 = process_task(_task(tier=0), settings, rdb, enforcer)
        record1 = process_task(_task(tier=1), settings, rdb, enforcer)

        enrich_mock.assert_not_called()
        assert record0.rules_fired == []
        assert record0.reasoning == []
        assert record0.rules_total_weight == 0.0
        assert record1.rules_fired == []
        assert record1.reasoning == []

    def test_safelisted_dispara_r009_sin_cambiar_el_skip(self, mocker) -> None:
        settings = _settings(response_safelist_extra="1.2.3.5")
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="1.2.3.5"),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_SKIPPED
        assert "R009_safelisted" in record.rules_fired


class TestDegradacionConGracia:
    def test_evaluate_roto_no_tumba_process_task_ni_pierde_la_decision_real(
        self, mocker
    ) -> None:
        """Si rules.engine.evaluate() lanza por cualquier motivo (rules.yaml
        corrupto, bug del evaluador, lo que sea), process_task() debe seguir
        devolviendo la decisión real intacta -- solo con rules_fired/reasoning
        vacíos (su default) en vez de poblados."""
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="1.2.3.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(
                action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado",
                enforcer="dry_run",
            ),
        )
        mocker.patch(
            "response.worker.evaluate",
            side_effect=RuntimeError("rules.yaml corrupto en este escenario"),
        )

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        # La decisión real (bloqueo) sigue firme pese al fallo del motor de
        # reglas -- la explicación simplemente no se pudo generar.
        assert record.block.action == ActionType.BLOCK
        assert record.rules_fired == []
        assert record.reasoning == []
        assert record.rules_total_weight == 0.0

    def test_evaluate_se_invoca_con_el_contexto_esperado(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="1.2.3.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(
                action=ActionType.BLOCK, enforced=True, reason="x", enforcer="dry_run",
            ),
        )
        evaluate_mock = mocker.patch(
            "response.worker.evaluate",
            return_value=EvaluationResult(rules_fired=["R008"], reasoning=["x"], total_weight=2.0),
        )

        process_task(_task(tier=3), settings, rdb, enforcer)

        evaluate_mock.assert_called_once()
        (context,), _ = evaluate_mock.call_args
        assert context["tier"] == 3
        assert context["corroboration_count"] == 2
        assert context["is_safelisted"] is False
        assert context["is_stale"] is False
