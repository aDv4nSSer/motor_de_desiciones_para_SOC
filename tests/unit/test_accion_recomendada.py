"""
Verifica que `accion_recomendada` (ResponseRecord) refleje realmente la
tabla de la sección 4 de docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md para
los renglones de origen RED (los únicos alcanzables hoy — ver comentario en
response/schemas.py sobre por qué los renglones de origen Host y
rate-limiting no están implementados todavía).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings
from response.schemas import (
    ACCION_ALERTAR_CREAR_CASO,
    ACCION_ALERTAR_PENDIENTE_APROBACION,
    ACCION_BLOQUEO_IP,
    ACCION_NINGUNA,
    ActionType,
    EnrichmentResult,
    ResponseTask,
)
from response.worker import process_task


def _settings(**overrides) -> ResponseSettings:
    base = {"r1_min_tier": 1, "r2_min_tier": 3, "min_corroborating_sources_for_autoblock": 2,
            "response_mode": "dry_run"}
    base.update(overrides)
    return ResponseSettings(**base)


def _task(tier: int) -> ResponseTask:
    return ResponseTask(trace_id=f"trace-accion-{tier}", tier=tier, risk_score=0.5,
                         src_ip="203.0.113.9", dst_ip="10.10.10.3", L4_DST_PORT=443)


class TestT0T1SinAccion:
    def test_tier_zero_no_reaches_r1_gives_ninguna(self, mocker) -> None:
        settings = _settings(r1_min_tier=1)
        rdb = mocker.MagicMock()
        record = process_task(_task(0), settings, rdb, mocker.MagicMock())
        assert record.accion_recomendada == ACCION_NINGUNA
        assert record.case_id is None

    def test_tier_one_enriches_pero_sigue_sin_accion(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(src_ip="203.0.113.9"))
        record = process_task(_task(1), settings, rdb, mocker.MagicMock())
        assert record.accion_recomendada == ACCION_NINGUNA


class TestT2AlertaYCaso:
    def test_tier_two_recomienda_alertar_y_abre_caso(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(src_ip="203.0.113.9"))
        open_case_mock = mocker.patch(
            "response.worker.open_case",
            return_value={"case_id": "caso-123", "kind": "network_t2_unconfirmed"},
        )

        record = process_task(_task(2), settings, rdb, mocker.MagicMock())

        open_case_mock.assert_called_once()
        assert record.accion_recomendada == ACCION_ALERTAR_CREAR_CASO
        assert record.case_id == "caso-123"
        # T2 nunca debe tocar el enforcer -- ver H29/test_response_worker_gating.py
        assert record.block is None


class TestT3RedRecomendaciones:
    def test_corroborado_recomienda_bloqueo_ip(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="203.0.113.9", corroboration_count=2,
                                           corroborating_sources=["abuseipdb", "otx"]),
        )
        mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(action=ActionType.BLOCK, enforced=True),
        )

        record = process_task(_task(3), settings, rdb, mocker.MagicMock())

        assert record.accion_recomendada == ACCION_BLOQUEO_IP

    def test_corroboracion_insuficiente_recomienda_pendiente_aprobacion_y_la_registra(
        self, mocker
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="203.0.113.9", corroboration_count=1,
                                           corroborating_sources=["abuseipdb"]),
        )
        create_pending_mock = mocker.patch("response.worker.create_pending_approval")

        record = process_task(_task(3), settings, rdb, mocker.MagicMock())

        assert record.accion_recomendada == ACCION_ALERTAR_PENDIENTE_APROBACION
        create_pending_mock.assert_called_once_with(record, rdb)

    def test_ya_bloqueada_no_recomienda_bloqueo_de_nuevo(self, mocker) -> None:
        """block_skipped (ya bloqueada / safelisted) no debe reportarse como
        si fuera una acción de bloqueo nueva -- accion_recomendada queda en
        ninguna, no en bloqueo_ip."""
        settings = _settings()
        rdb = mocker.MagicMock()
        mocker.patch(
            "response.worker.enrich",
            return_value=EnrichmentResult(src_ip="203.0.113.9", corroboration_count=2,
                                           corroborating_sources=["abuseipdb", "otx"]),
        )
        mocker.patch(
            "response.worker.respond_block",
            return_value=mocker.MagicMock(action=ActionType.BLOCK_SKIPPED, enforced=False),
        )

        record = process_task(_task(3), settings, rdb, mocker.MagicMock())

        assert record.accion_recomendada == ACCION_NINGUNA
