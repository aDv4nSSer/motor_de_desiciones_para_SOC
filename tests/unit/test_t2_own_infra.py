"""
H54 — T2 de infraestructura propia del SOC: no abre caso.

Suricata captura en el trunk eno2 de .139 y ve el propio pipeline (Vector ->
motor :8000 / OpenSearch :9201, worker -> API de Wazuh :55000). Cada flow T2
de esos abría un caso nuevo sin dedup (~12k/día). La rama T2 ahora consulta
is_own_infra() -- solo la lista explícita config.OWN_INFRA, sin la exención
genérica por rango privado de is_safelisted(), que sigue igual para R2.
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from response.config import DEFAULT_SAFELIST, OWN_INFRA, ResponseSettings
from response.enforcer import is_own_infra, is_safelisted
from response.schemas import (
    ACCION_ALERTAR_CREAR_CASO,
    ACCION_ALERTAR_PENDIENTE_APROBACION,
    ACCION_NINGUNA,
    ACCION_NINGUNA_INFRA_PROPIA,
    ActionType,
    EnrichmentResult,
    ResponseTask,
)
from response.worker import process_task
from rules.engine import evaluate


def _settings(**overrides) -> ResponseSettings:
    base = {"r1_min_tier": 1, "r2_min_tier": 3, "min_corroborating_sources_for_autoblock": 2,
            "response_mode": "dry_run"}
    base.update(overrides)
    return ResponseSettings(**base)


def _run(mocker, src_ip: str, tier: int = 2, corroboration_count: int = 0):
    mocker.patch("response.worker.enrich",
                 return_value=EnrichmentResult(src_ip=src_ip, corroboration_count=corroboration_count))
    open_case = mocker.patch("response.worker.open_case",
                             return_value={"case_id": "caso-1", "kind": "network_t2_unconfirmed"})
    create_pending = mocker.patch("response.worker.create_pending_approval")
    task = ResponseTask(trace_id=f"trace-h54-{src_ip}", tier=tier, risk_score=0.73,
                        src_ip=src_ip, dst_ip="10.10.10.3", L4_DST_PORT=8000)
    record = process_task(task, _settings(), mocker.MagicMock(), mocker.MagicMock())
    return record, open_case, create_pending


class TestRamaT2:
    @pytest.mark.parametrize("ip", ["10.10.10.1", "10.10.10.3", "10.30.30.2", "200.54.12.139"])
    def test_infra_propia_no_abre_caso(self, mocker, ip) -> None:
        record, open_case, _ = _run(mocker, ip)
        open_case.assert_not_called()
        assert record.accion_recomendada == ACCION_NINGUNA_INFRA_PROPIA
        assert record.case_id is None
        assert record.block is None  # T2 nunca toca el enforcer
        # La explicación no contradice lo que pasó.
        assert "R012_t2_infra_propia" in record.rules_fired
        assert "R003_t2_score_medio" not in record.rules_fired

    def test_ipv6_expandida_de_suricata_coincide(self, mocker) -> None:
        record, open_case, _ = _run(mocker, "2002:c836:0c8b:0000:0000:0000:0000:0000")
        open_case.assert_not_called()
        assert record.accion_recomendada == ACCION_NINGUNA_INFRA_PROPIA

    def test_privada_que_no_es_infra_abre_caso(self, mocker) -> None:
        """Un host comprometido de una VLAN (no listado) sigue abriendo caso,
        aunque is_safelisted() lo exima de bloqueo."""
        record, open_case, _ = _run(mocker, "10.30.30.50")
        open_case.assert_called_once()
        assert record.accion_recomendada == ACCION_ALERTAR_CREAR_CASO
        assert record.case_id == "caso-1"
        assert "R003_t2_score_medio" in record.rules_fired

    def test_publica_sigue_abriendo_caso(self, mocker) -> None:
        record, open_case, _ = _run(mocker, "45.141.233.81")
        open_case.assert_called_once()
        assert record.accion_recomendada == ACCION_ALERTAR_CREAR_CASO

    def test_stale_de_infra_propia_sigue_como_antes(self, mocker) -> None:
        """La rama stale no se tocó: registra alertar_crear_caso sin abrir caso."""
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(src_ip="10.10.10.1"))
        open_case = mocker.patch("response.worker.open_case")
        task = ResponseTask(trace_id="trace-h54-stale", tier=2, risk_score=0.73, src_ip="10.10.10.1",
                            L4_DST_PORT=8000, ts=1.0)  # evento viejísimo
        record = process_task(task, _settings(), mocker.MagicMock(), mocker.MagicMock())
        open_case.assert_not_called()
        assert record.accion_recomendada == ACCION_ALERTAR_CREAR_CASO


class TestR2SinCambios:
    def test_t3_privada_no_listada_sigue_sin_bloquearse(self, mocker) -> None:
        """R2 conserva la exención amplia: is_own_infra no la reemplaza."""
        record, _, create_pending = _run(mocker, "10.30.30.50", tier=3)
        create_pending.assert_not_called()
        assert record.accion_recomendada == ACCION_NINGUNA
        assert record.block.action == ActionType.BLOCK_SKIPPED

    def test_t3_publica_no_corroborada_sigue_pendiente(self, mocker) -> None:
        record, _, create_pending = _run(mocker, "45.141.233.81", tier=3, corroboration_count=1)
        create_pending.assert_called_once()
        assert record.accion_recomendada == ACCION_ALERTAR_PENDIENTE_APROBACION


class TestListas:
    def test_topologia_vlan_actual(self) -> None:
        for ip in ("200.54.12.139", "10.10.10.1", "10.20.20.1", "10.30.30.1",
                   "10.10.10.3", "10.30.30.2", "10.10.10.254"):
            assert ip in OWN_INFRA
        # .138 y .140 ya no tienen IP pública desde la migración.
        assert "200.54.12.138" not in DEFAULT_SAFELIST
        assert "200.54.12.140" not in DEFAULT_SAFELIST

    def test_nunca_bloquear_es_superconjunto_de_infra_propia(self) -> None:
        assert OWN_INFRA <= DEFAULT_SAFELIST
        # Terceros con IP pública: no se bloquean, pero no son infra propia (abren caso).
        for ip in ("200.54.12.141", "200.54.12.142"):
            assert ip in DEFAULT_SAFELIST and not is_own_infra(ip)

    def test_todas_las_entradas_son_ips_validas(self) -> None:
        for ip in DEFAULT_SAFELIST:
            ipaddress.ip_address(ip)

    @pytest.mark.parametrize("ip,own,safe", [
        ("10.10.10.1", True, True),
        ("10.30.30.50", False, True),     # privada no listada: no se bloquea, sí abre caso
        ("45.141.233.81", False, False),
        ("no-es-ip", False, True),        # malformada: no bloquear, pero abrir caso igual
    ])
    def test_is_own_infra_vs_is_safelisted(self, ip, own, safe) -> None:
        assert is_own_infra(ip) is own
        assert is_safelisted(ip, _settings()) is safe


class TestReglas:
    def test_r003_y_r012_son_excluyentes(self) -> None:
        base = {"tier": 2, "is_stale": False, "is_safelisted": True, "corroboration_count": 0,
                "otx_available": True, "abuseipdb_available": True}
        own = evaluate({**base, "is_own_infra": True}).rules_fired
        other = evaluate({**base, "is_own_infra": False}).rules_fired
        assert "R012_t2_infra_propia" in own and "R003_t2_score_medio" not in own
        assert "R003_t2_score_medio" in other and "R012_t2_infra_propia" not in other


class TestInvarianciaSombra:
    """expected_r2() del período de sombra: la regla H54 solo desde el corte."""

    def _payload(self, processed_at: float, accion: str) -> dict:
        return {"tier": 2, "src_ip": "10.10.10.1", "event_age_seconds": 1.0,
                "processed_at": processed_at, "accion_recomendada": accion,
                "enrichment": {"corroboration_count": 0}}

    def test_antes_y_despues_del_corte(self, monkeypatch) -> None:
        import corroboration_shadow_report as rep
        settings = _settings()
        monkeypatch.setattr(rep, "T2_OWN_INFRA_CUT", 1_000.0)
        assert rep.matches_r2(self._payload(999.0, ACCION_ALERTAR_CREAR_CASO), settings)
        assert not rep.matches_r2(self._payload(999.0, ACCION_NINGUNA_INFRA_PROPIA), settings)
        assert rep.matches_r2(self._payload(1_000.0, ACCION_NINGUNA_INFRA_PROPIA), settings)
        assert not rep.matches_r2(self._payload(1_000.0, ACCION_ALERTAR_CREAR_CASO), settings)

    def test_sin_corte_espera_la_regla_vieja(self, monkeypatch) -> None:
        import corroboration_shadow_report as rep
        monkeypatch.setattr(rep, "T2_OWN_INFRA_CUT", None)
        assert rep.matches_r2(self._payload(2e9, ACCION_ALERTAR_CREAR_CASO), _settings())

    def test_privada_no_listada_espera_caso_tambien_despues_del_corte(self, monkeypatch) -> None:
        import corroboration_shadow_report as rep
        monkeypatch.setattr(rep, "T2_OWN_INFRA_CUT", 1_000.0)
        p = {**self._payload(2_000.0, ACCION_ALERTAR_CREAR_CASO), "src_ip": "10.30.30.50"}
        assert rep.matches_r2(p, _settings())


class TestLimpiezaH54:
    """scripts/mantenimiento/h54_limpiar_casos_infra.py: qué se borra y qué no."""

    @staticmethod
    def _case(host: str, kind="network_t2_unconfirmed", state="abierto", history=1) -> str:
        import json
        return json.dumps({"case_id": "c", "kind": kind, "host": host, "state": state,
                           "history": [{"state": state}] * history})

    def test_clasificacion(self) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "mantenimiento"))
        from h54_limpiar_casos_infra import classify
        assert classify(None) == "indice_huerfano"
        assert classify(self._case("10.10.10.1")) == "infra_propia"
        assert classify(self._case("45.141.233.81")) is None          # pública: queda para dedup
        assert classify(self._case("10.30.30.50")) is None            # privada no listada: señal real
        assert classify(self._case("10.10.10.1", history=2)) is None  # alguien la movió
        assert classify(self._case("10.10.10.1", state="en_revision")) is None
        assert classify(self._case("10.10.10.1", kind="quarantine_file")) is None
