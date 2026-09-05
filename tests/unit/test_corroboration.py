from __future__ import annotations

import sys
from pathlib import Path

# motor/response usa imports absolutos (`from response...`), así que motor/
# debe estar en sys.path — igual que el resto de tests/unit/*.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings  # noqa: E402
from response.enrichment import count_corroborating_sources, enrich  # noqa: E402
from response.schemas import EnrichmentResult  # noqa: E402


def _settings(**overrides) -> ResponseSettings:
    base = {
        "abuseipdb_malicious_threshold": 50,
        "otx_min_pulse_count": 1,
        "min_corroborating_sources_for_autoblock": 2,
    }
    base.update(overrides)
    return ResponseSettings(**base)


class TestCountCorroboratingSourcesZero:
    def test_no_signal_from_either_source(self) -> None:
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=0, abuseipdb_available=True,
            otx_pulse_count=0, otx_available=True,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 0
        assert names == []

    def test_both_sources_unavailable_counts_as_zero_not_as_malicious(self) -> None:
        """Fuente caída no cuenta ni a favor ni en contra (H23/H24 degradación elegante)."""
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=None, abuseipdb_available=False,
            otx_pulse_count=None, otx_available=False,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 0
        assert names == []


class TestCountCorroboratingSourcesOne:
    def test_only_abuseipdb_above_threshold(self) -> None:
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=92, abuseipdb_available=True,
            otx_pulse_count=0, otx_available=True,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 1
        assert names == ["abuseipdb"]

    def test_only_otx_above_threshold(self) -> None:
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=10, abuseipdb_available=True,
            otx_pulse_count=3, otx_available=True,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 1
        assert names == ["otx"]

    def test_high_score_but_source_unavailable_does_not_count(self) -> None:
        """Caso msnbot/Bing: score alto en una sola fuente débil no basta,
        y una fuente caída tampoco puede sumar aunque el otro dato sea alto."""
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=95, abuseipdb_available=False,  # dato descartable
            otx_pulse_count=0, otx_available=True,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 0
        assert names == []

    def test_below_threshold_does_not_count(self) -> None:
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=49, abuseipdb_available=True,
            otx_pulse_count=0, otx_available=True,
        )
        count, _names = count_corroborating_sources(result, settings)
        assert count == 0


class TestCountCorroboratingSourcesTwoPlus:
    def test_both_sources_corroborate(self) -> None:
        settings = _settings()
        result = EnrichmentResult(
            abuseipdb_score=87, abuseipdb_available=True,
            otx_pulse_count=5, otx_available=True,
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 2
        assert set(names) == {"abuseipdb", "otx"}

    def test_thresholds_are_configurable_not_hardcoded(self) -> None:
        settings = _settings(abuseipdb_malicious_threshold=90, otx_min_pulse_count=5)
        result = EnrichmentResult(
            abuseipdb_score=80, abuseipdb_available=True,   # bajo el umbral custom
            otx_pulse_count=5, otx_available=True,           # justo en el umbral custom
        )
        count, names = count_corroborating_sources(result, settings)
        assert count == 1
        assert names == ["otx"]


class TestEnrichPopulatesCorroboration:
    def test_enrich_sets_corroboration_fields_on_result(self, mocker) -> None:
        settings = _settings(abuseipdb_api_key="k1", otx_api_key="k2")  # pragma: allowlist secret
        rdb = mocker.MagicMock()
        rdb.get.return_value = None

        abuse_resp = mocker.MagicMock()
        abuse_resp.raise_for_status.return_value = None
        abuse_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 96, "totalReports": 40, "countryCode": "CN"}
        }
        otx_resp = mocker.MagicMock()
        otx_resp.raise_for_status.return_value = None
        otx_resp.json.return_value = {"pulse_info": {"count": 4}}
        mocker.patch(
            "response.enrichment.httpx.get", side_effect=[abuse_resp, otx_resp]
        )
        mocker.patch("response.enrichment._reverse_dns", return_value=None)

        result = enrich("1.2.3.4", settings, rdb)

        assert result.corroboration_count == 2
        assert set(result.corroborating_sources) == {"abuseipdb", "otx"}
