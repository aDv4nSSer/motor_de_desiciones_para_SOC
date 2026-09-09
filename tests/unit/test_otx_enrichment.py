from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from pytest_mock import MockerFixture

# motor/response usa imports absolutos (`from response...`), así que motor/
# debe estar en sys.path — igual que cuando motor/main.py corre standalone.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.enrichment import _otx_lookup  # noqa: E402


def _settings(**overrides) -> ResponseSettings:
    base = {
        "otx_api_key": "test-otx-key",  # pragma: allowlist secret
        "otx_cache_ttl": 21600,
        "otx_timeout": 4.0,
        "enrich_cache_prefix": "soc:enrich:",
    }
    base.update(overrides)
    return ResponseSettings(**base)


class TestOtxLookupCacheHit:
    def test_returns_cached_pulse_count_without_calling_api(
        self, mocker: MockerFixture
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = json.dumps({"pulse_count": 7}).encode()
        http_get = mocker.patch("response.enrichment.httpx.get")

        result = _otx_lookup("1.2.3.4", settings, rdb)

        assert result.otx_pulse_count == 7
        assert result.otx_available is True
        assert result.cached is True
        http_get.assert_not_called()
        rdb.get.assert_called_once_with("soc:enrich:otx:1.2.3.4")


class TestOtxLookupCacheMiss:
    def test_queries_api_and_caches_result(self, mocker: MockerFixture) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = None
        fake_response = mocker.MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"pulse_info": {"count": 12}}
        mocker.patch("response.enrichment.httpx.get", return_value=fake_response)

        result = _otx_lookup("5.6.7.8", settings, rdb)

        assert result.otx_pulse_count == 12
        assert result.otx_available is True
        assert result.cached is False
        rdb.setex.assert_called_once()
        args, _ = rdb.setex.call_args
        assert args[0] == "soc:enrich:otx:5.6.7.8"
        assert args[1] == settings.otx_cache_ttl
        assert json.loads(args[2]) == {"pulse_count": 12}


class TestOtxLookupUnavailable:
    def test_no_api_key_marks_unavailable_without_calling_api(
        self, mocker: MockerFixture
    ) -> None:
        settings = _settings(otx_api_key="")
        rdb = mocker.MagicMock()
        http_get = mocker.patch("response.enrichment.httpx.get")

        result = _otx_lookup("9.9.9.9", settings, rdb)

        assert result.otx_available is False
        assert "otx_api_key no configurada" in result.notes
        http_get.assert_not_called()

    def test_connection_error_marks_unavailable_without_raising(
        self, mocker: MockerFixture
    ) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = None
        mocker.patch(
            "response.enrichment.httpx.get",
            side_effect=httpx.ConnectTimeout("timeout"),
        )

        result = _otx_lookup("8.8.8.8", settings, rdb)

        assert result.otx_available is False
        assert result.otx_pulse_count is None
        assert any("otx error" in n for n in result.notes)

    def test_http_status_error_marks_unavailable(self, mocker: MockerFixture) -> None:
        settings = _settings()
        rdb = mocker.MagicMock()
        rdb.get.return_value = None
        fake_response = mocker.MagicMock()
        fake_response.status_code = 429
        mocker.patch(
            "response.enrichment.httpx.get",
            side_effect=httpx.HTTPStatusError(
                "rate limited", request=mocker.MagicMock(), response=fake_response
            ),
        )

        result = _otx_lookup("8.8.4.4", settings, rdb)

        assert result.otx_available is False
        assert any("otx HTTP 429" in n for n in result.notes)
