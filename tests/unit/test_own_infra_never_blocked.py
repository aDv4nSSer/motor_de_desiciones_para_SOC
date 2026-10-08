"""
H56: el propio motor (10.10.10.3, .140) y el resto de la infraestructura del
SOC nunca pueden ser bloqueados por R2. La protección es doble (OWN_INFRA en
la safelist + exención de todo rango privado), pero si alguien edita la lista
este test tiene que fallar antes del deploy: un firewall-drop sobre .140
cortaría el Fast Path, la API de Wazuh y el acceso por el bastion.

Contexto: campana_automatica.sh corre todas las noches desde .140 contra .139
y genera ~2 T3/día con origen 10.10.10.3 (H56); hoy terminan en block_skipped.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import DEFAULT_SAFELIST, OWN_INFRA, ResponseSettings
from response.enforcer import is_own_infra, is_safelisted, respond_block
from response.schemas import ActionType

CRITICAL = ["10.10.10.3", "200.54.12.139", "10.10.10.1", "10.30.30.1", "10.30.30.2", "10.10.10.254"]


@pytest.mark.parametrize("ip", CRITICAL)
def test_infra_critica_en_own_infra_y_safelist(ip) -> None:
    assert ip in OWN_INFRA and ip in DEFAULT_SAFELIST
    assert is_own_infra(ip)
    assert is_safelisted(ip, ResponseSettings(response_mode="enforce"))


def test_el_motor_no_llega_al_enforcer_ni_en_enforce(mocker) -> None:
    settings = ResponseSettings(response_mode="enforce", enforcer_backend="wazuh_api")
    enforcer = mocker.MagicMock()
    enforcer.name = "wazuh_api"
    rdb = mocker.MagicMock(**{"get.return_value": None})
    r = respond_block("10.10.10.3", settings, rdb, enforcer, "trace-own-infra")
    assert r.action == ActionType.BLOCK_SKIPPED and not r.enforced
    enforcer.block.assert_not_called()
