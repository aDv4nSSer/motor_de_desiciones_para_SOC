"""
Continuación de H23: tras la migración a NAT/VLANs, `src_ip` en el Fast
Path puede llegar como IP interna (ej. `10.10.10.3`, `10.30.30.2`) en vez
de la IP pública real del atacante. Ninguna fuente de TI externa puede
tener reputación real de una IP privada — consultarla desperdicia cuota y,
en OTX, el endpoint la rechaza con HTTP 400 (confirmado con evidencia real
de `soc:response:audit` en producción, ver BITACORA_TECNICA.md).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.enrichment import _abuseipdb_lookup, _otx_lookup  # noqa: E402


def _settings(**overrides) -> ResponseSettings:
    base = {
        "abuseipdb_api_key": "k1",  # pragma: allowlist secret
        "otx_api_key": "k2",  # pragma: allowlist secret
    }
    base.update(overrides)
    return ResponseSettings(**base)


class TestAbuseipdbSkipsPrivateIps:
    def test_private_ip_never_calls_api_or_cache(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        http_get = mocker.patch("response.enrichment.httpx.get")

        result = _abuseipdb_lookup("10.10.10.3", settings, rdb)

        assert result.abuseipdb_available is False
        assert any("IP no pública" in n for n in result.notes)
        http_get.assert_not_called()
        rdb.get.assert_not_called()

    def test_loopback_is_also_skipped(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        http_get = mocker.patch("response.enrichment.httpx.get")

        result = _abuseipdb_lookup("127.0.0.1", settings, rdb)

        assert result.abuseipdb_available is False
        http_get.assert_not_called()

    def test_public_ip_still_calls_api_as_before(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = None
        fake_response = mocker.MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "data": {"abuseConfidenceScore": 10, "totalReports": 1, "countryCode": "US"}
        }
        http_get = mocker.patch(
            "response.enrichment.httpx.get", return_value=fake_response
        )

        result = _abuseipdb_lookup("8.8.8.8", settings, rdb)

        http_get.assert_called_once()
        assert result.abuseipdb_score == 10


class TestOtxSkipsPrivateIps:
    def test_private_ip_never_calls_api_or_cache(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        http_get = mocker.patch("response.enrichment.httpx.get")

        result = _otx_lookup("10.30.30.2", settings, rdb)

        assert result.otx_available is False
        assert any("IP no pública" in n for n in result.notes)
        http_get.assert_not_called()
        rdb.get.assert_not_called()

    def test_public_ip_still_calls_api_as_before(self, mocker) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = None
        fake_response = mocker.MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"pulse_info": {"count": 2}}
        http_get = mocker.patch(
            "response.enrichment.httpx.get", return_value=fake_response
        )

        result = _otx_lookup("1.1.1.1", settings, rdb)

        http_get.assert_called_once()
        assert result.otx_pulse_count == 2
