"""
H38 (A): tareas del backlog con la detección original de hace más de 1 h.

Completan R1 y se auditan con su accion_recomendada (trazabilidad), pero no
ejecutan bloqueo, no abren aprobación ni caso, y el registro dice
explícitamente por qué (block_skipped + "stale_backlog_event_age>1h"), sin
confundirse con un skip por safelist.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.schemas import (  # noqa: E402
    ACCION_ALERTAR_CREAR_CASO,
    ACCION_ALERTAR_PENDIENTE_APROBACION,
    ACCION_BLOQUEO_IP,
    ACCION_NINGUNA,
    ActionType,
    EnrichmentResult,
    ResponseTask,
)
from response.worker import event_age_seconds, process_task, stale_reason  # noqa: E402

PUBLIC_IP = "1.2.3.4"


def _settings(**overrides) -> ResponseSettings:
    base = {"r1_min_tier": 1, "r2_min_tier": 3, "min_corroborating_sources_for_autoblock": 2,
            "response_mode": "enforce", "stale_event_max_age_seconds": 3600}
    base.update(overrides)
    return ResponseSettings(**base)


def _task(tier: int, age_s: float | None, ip: str = PUBLIC_IP) -> ResponseTask:
    ts = time.time() - age_s if age_s is not None else 0.0
    return ResponseTask(trace_id=f"trace-stale-{tier}", tier=tier, risk_score=0.95,
                        src_ip=ip, dst_ip="10.10.10.3", L4_DST_PORT=22, ts=ts)


@pytest.fixture
def env(mocker):
    enrich = mocker.patch("response.worker.enrich", return_value=EnrichmentResult(
        src_ip=PUBLIC_IP, corroboration_count=2, corroborating_sources=["abuseipdb", "otx"]))
    respond_block = mocker.patch("response.worker.respond_block")
    create_approval = mocker.patch("response.worker.create_pending_approval")
    open_case = mocker.patch("response.worker.open_case", return_value={"case_id": "c-1"})
    return {"rdb": mocker.MagicMock(), "enforcer": mocker.MagicMock(name="wazuh_api"),
            "enrich": enrich, "respond_block": respond_block,
            "create_approval": create_approval, "open_case": open_case}


def _audited(rdb) -> dict:
    payload = rdb.xadd.call_args.args[1]["data"]
    return json.loads(payload)


class TestStaleT3:
    def test_corroborado_no_bloquea_y_lo_dice(self, env) -> None:
        record = process_task(_task(3, age_s=15 * 3600), _settings(), env["rdb"], env["enforcer"])
        env["enrich"].assert_called_once()                # R1 sí corre
        env["respond_block"].assert_not_called()          # nada de enforcer
        env["enforcer"].block.assert_not_called()
        assert record.block.action == ActionType.BLOCK_SKIPPED
        assert record.block.reason == "stale_backlog_event_age>1h"
        assert record.block.enforced is False
        assert record.accion_recomendada == ACCION_BLOQUEO_IP  # lo que se habría recomendado
        audited = _audited(env["rdb"])
        assert audited["block"]["reason"] == "stale_backlog_event_age>1h"
        assert audited["event_age_seconds"] >= 15 * 3600 - 5

    def test_sin_corroboracion_no_abre_aprobacion(self, env) -> None:
        env["enrich"].return_value = EnrichmentResult(src_ip=PUBLIC_IP, corroboration_count=1)
        record = process_task(_task(3, age_s=2 * 3600), _settings(), env["rdb"], env["enforcer"])
        env["create_approval"].assert_not_called()
        assert record.block.action == ActionType.BLOCK_SKIPPED
        assert record.block.reason == "stale_backlog_event_age>1h"
        assert record.accion_recomendada == ACCION_ALERTAR_PENDIENTE_APROBACION

    def test_ip_de_safelist_recomienda_ninguna_pero_el_motivo_es_la_antiguedad(self, env) -> None:
        record = process_task(_task(3, age_s=2 * 3600, ip="10.30.30.1"), _settings(), env["rdb"], env["enforcer"])
        assert record.block.reason == "stale_backlog_event_age>1h"
        assert record.accion_recomendada == ACCION_NINGUNA


class TestStaleT2:
    def test_no_abre_caso(self, env) -> None:
        record = process_task(_task(2, age_s=2 * 3600), _settings(), env["rdb"], env["enforcer"])
        env["open_case"].assert_not_called()
        assert record.case_id is None
        assert record.accion_recomendada == ACCION_ALERTAR_CREAR_CASO


class TestFrescaSinCambios:
    def test_t3_corroborado_fresco_sigue_bloqueando(self, env, mocker) -> None:
        env["respond_block"].return_value = mocker.MagicMock(
            action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado", enforcer="wazuh_api")
        record = process_task(_task(3, age_s=30), _settings(), env["rdb"], env["enforcer"])
        env["respond_block"].assert_called_once()
        assert record.accion_recomendada == ACCION_BLOQUEO_IP
        assert 25 <= record.event_age_seconds <= 60

    def test_t2_fresco_abre_caso(self, env) -> None:
        record = process_task(_task(2, age_s=30), _settings(), env["rdb"], env["enforcer"])
        env["open_case"].assert_called_once()
        assert record.case_id == "c-1"

    def test_justo_bajo_el_umbral_es_fresca(self, env, mocker) -> None:
        env["respond_block"].return_value = mocker.MagicMock(
            action=ActionType.BLOCK, enforced=True, reason="ok", enforcer="wazuh_api")
        process_task(_task(3, age_s=3500), _settings(), env["rdb"], env["enforcer"])
        env["respond_block"].assert_called_once()


class TestOrigenDeLaAntiguedad:
    def test_sin_ts_usa_el_id_del_mensaje(self, env) -> None:
        task = _task(3, age_s=None)  # ts=0
        enqueued = time.time() - 3 * 3600
        record = process_task(task, _settings(), env["rdb"], env["enforcer"], enqueued_at=enqueued)
        env["respond_block"].assert_not_called()
        assert record.block.reason == "stale_backlog_event_age>1h"

    def test_sin_ninguna_marca_se_trata_como_fresca(self) -> None:
        assert event_age_seconds(_task(3, age_s=None), None, time.time()) is None

    def test_reloj_adelantado_no_da_edad_negativa(self) -> None:
        task = _task(3, age_s=-120)  # ts en el futuro (reloj desfasado)
        assert event_age_seconds(task, None, time.time()) == 0.0

    @pytest.mark.parametrize("secs,expected", [(3600, "stale_backlog_event_age>1h"),
                                                (7200, "stale_backlog_event_age>2h"),
                                                (900, "stale_backlog_event_age>900s")])
    def test_texto_del_motivo(self, secs, expected) -> None:
        assert stale_reason(secs) == expected

    def test_umbral_configurable(self, env) -> None:
        record = process_task(_task(3, age_s=1200), _settings(stale_event_max_age_seconds=900),
                              env["rdb"], env["enforcer"])
        assert record.block.reason == "stale_backlog_event_age>900s"
