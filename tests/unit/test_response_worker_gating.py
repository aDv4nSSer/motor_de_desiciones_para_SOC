"""
Verifica que la corroboración multi-fuente de R1 sea un aporte REAL a la
decisión de R2 (bloqueo automático vs. pendiente de aprobación humana), no
solo un campo que queda guardado en soc:response:audit sin influir en nada.

Ver especificacion_tecnica_final_r-soar.md sección 4 y BITACORA_TECNICA.md
(continuación de H23).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.schemas import ActionType, EnrichmentResult, ResponseTask  # noqa: E402
from response.worker import process_task  # noqa: E402


def _settings(**overrides) -> ResponseSettings:
    base = {
        "r1_min_tier": 1,
        "r2_min_tier": 2,
        "min_corroborating_sources_for_autoblock": 2,
        "response_mode": "dry_run",
    }
    base.update(overrides)
    return ResponseSettings(**base)


def _task(tier: int = 3) -> ResponseTask:
    return ResponseTask(
        trace_id="trace-corrob-1", tier=tier, risk_score=0.9,
        src_ip="203.0.113.5", dst_ip="10.10.10.3", L4_DST_PORT=443,
    )


class TestTwoOrMoreSourcesGoesAutomatic:
    def test_two_sources_corroborate_calls_respond_block(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        respond_block = mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(
                action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado",
                enforcer="dry_run",
            ),
        )

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_called_once()
        assert record.block.action == ActionType.BLOCK


class TestFewerThanTwoSourcesRequiresApproval:
    def test_one_source_skips_respond_block_and_flags_pending_approval(
        self, mocker
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", corroboration_count=1,
                corroborating_sources=["abuseipdb"],
            ),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL
        assert record.block.enforced is False
        assert record.block.requires_approval is True
        assert record.block.approval_level == "N1"

    def test_zero_sources_skips_respond_block(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", corroboration_count=0, corroborating_sources=[],
            ),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL

    def test_failed_sources_do_not_help_reach_autoblock(self, mocker) -> None:
        """Fuente caída no cuenta a favor: aunque el score haya sido alto,
        si no quedó corroborado por al menos 2 fuentes disponibles, no bloquea."""
        settings = _settings()
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", abuseipdb_score=95, abuseipdb_available=False,
                corroboration_count=0, corroborating_sources=[],
            ),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL


class TestEnrichmentMissingFailsSafe:
    def test_no_enrichment_available_defaults_to_pending_approval(self, mocker) -> None:
        """Si por alguna razón R1 no corrió (enrichment=None), la ausencia de
        corroboración se trata igual que corroboración insuficiente — nunca
        se asume corroborado sin datos."""
        settings = _settings(r1_min_tier=5)  # fuerza a que R1 no dispare
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        enrich_mock = mocker.patch("response.worker.enrich")
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        enrich_mock.assert_not_called()
        respond_block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL


class TestBelowR2ThresholdNeverReachesGate:
    def test_tier_below_r2_min_tier_does_not_touch_block_logic(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="203.0.113.5"),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=1), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block is None


class TestR2MinTierDefaultMatchesSpec:
    """
    Continuación de H28 (H29): la sección 4 de la especificación solo
    contempla bloqueo automático en T3 — T2 (red u host) siempre alerta y
    crea caso, nunca bloquea, sin importar la corroboración. r2_min_tier=2
    (heredado de julio, previo a la especificación de septiembre) permitía
    que T2 llegara al gate de R2 igual. Este test fija el default correcto
    para que una regresión futura no lo vuelva a bajar sin darse cuenta.
    """

    def test_default_r2_min_tier_is_three_not_two(self) -> None:
        assert ResponseSettings().r2_min_tier == 3

    def test_tier_two_never_reaches_r2_gate_even_with_strong_corroboration(
        self, mocker
    ) -> None:
        """Bajo el default real (sin overrides), un T2 con 2+ fuentes
        corroborando NO debe intentar bloquear — la tabla de la especificación
        no contempla bloqueo automático en T2 bajo ninguna circunstancia."""
        settings = ResponseSettings(response_mode="dry_run")
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        respond_block = mocker.patch("response.worker.respond_block")

        record = process_task(_task(tier=2), settings, rdb, enforcer)

        respond_block.assert_not_called()
        assert record.block is None

    def test_tier_three_still_autoblocks_with_strong_corroboration_under_defaults(
        self, mocker
    ) -> None:
        """Confirma que subir r2_min_tier a 3 no rompió el camino automático
        real de T3 con corroboración suficiente."""
        settings = ResponseSettings(response_mode="dry_run")
        rdb = mocker.MagicMock()
        enforcer = mocker.MagicMock(name="dry_run")

        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(
                src_ip="203.0.113.5", corroboration_count=2,
                corroborating_sources=["abuseipdb", "otx"],
            ),
        )
        respond_block = mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(action=ActionType.BLOCK, enforced=False),
        )

        record = process_task(_task(tier=3), settings, rdb, enforcer)

        respond_block.assert_called_once()
        assert record.block.action == ActionType.BLOCK
