"""
response/tests/test_crowdsec_observational_no_regression.py — H37 Fase 3.

Confirma que sumar CrowdSec a enrich() es puramente OBSERVACIONAL: un
evento con señal de CrowdSec pero SIN AbuseIPDB ni OTX corroborando debe
producir EXACTAMENTE el mismo corroboration_count/corroborating_sources
que tenía el sistema ANTES de esta fase (0, sin fuentes) — es la prueba de
que se agregó visibilidad sin tocar el comportamiento de decisión
existente (count_corroborating_sources, y por extensión accion_recomendada
en worker.py, que depende únicamente de corroboration_count).
"""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from response.config import ResponseSettings
from response.enrichment import enrich
from response.schemas import CrowdSecDecision


class _FakeRedis:
    """Redis falso mínimo -- get siempre None (fuerza cache miss), setex
    no-op. El test no depende de un Redis real corriendo."""
    def get(self, key):
        return None

    def setex(self, key, ttl, value):
        pass


def test_crowdsec_signal_alone_does_not_trigger_autoblock():
    settings = ResponseSettings(
        abuseipdb_api_key="",   # sin key -> abuseipdb_available=False
        otx_api_key="",         # sin key -> otx_available=False
        crowdsec_lapi_url="http://fake-lapi:8081",
        crowdsec_api_key="fake-key",  # pragma: allowlist secret -- valor de prueba, no un secreto real
    )
    rdb = _FakeRedis()
    ip = "203.0.113.55"  # TEST-NET-3, RFC 5737 -- IP pública de documentación

    fake_decision = CrowdSecDecision(
        ip=ip, scenario="crowdsecurity/ssh-bf", duration="3h59m",
        decision_type="ban", origin="crowdsec",
    )

    with patch("response.enrichment.fetch_decisions_stream", return_value=[fake_decision]):
        result = enrich(ip, settings, rdb)

    # Visibilidad: la señal de CrowdSec SÍ se registra (punto 2/4 de Fase 3).
    assert result.crowdsec_observado is True, "crowdsec_observado debería ser True"
    assert result.crowdsec_scenario == "crowdsecurity/ssh-bf"
    assert result.crowdsec_duration == "3h59m"

    # No-regresión: sin AbuseIPDB/OTX, el gate de corroboración sigue en 0,
    # exactamente igual que si CrowdSec no existiera -- no dispara bloqueo
    # automático (ver worker.py: corroboration_count >= min_corroborating_
    # sources_for_autoblock es lo único que decide R2).
    assert result.corroboration_count == 0, (
        f"corroboration_count debería seguir en 0, dio {result.corroboration_count} "
        "-- CrowdSec no debe sumar al gate en esta fase"
    )
    assert result.corroborating_sources == [], (
        f"corroborating_sources debería seguir vacío, dio {result.corroborating_sources}"
    )


def test_crowdsec_unavailable_still_degrades_gracefully():
    """Sin lapi_url/api_key configurada, enrich() no debe fallar ni afectar
    el resto del resultado -- mismo criterio de degradación elegante que
    AbuseIPDB/OTX."""
    settings = ResponseSettings(
        abuseipdb_api_key="", otx_api_key="",
        crowdsec_lapi_url="", crowdsec_api_key="",
    )
    rdb = _FakeRedis()
    result = enrich("203.0.113.66", settings, rdb)
    assert result.crowdsec_observado is False
    assert result.corroboration_count == 0


if __name__ == "__main__":
    test_crowdsec_signal_alone_does_not_trigger_autoblock()
    test_crowdsec_unavailable_still_degrades_gracefully()
    print("OK: CrowdSec es observacional -- no afecta corroboration_count/corroborating_sources.")
