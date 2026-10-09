"""H57 (e): regímenes de decisión y policy_version (hash de la configuración sin secretos)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from datetime import datetime, timezone

import regimes

NOW = datetime(2026, 10, 9, 3, 0, tzinfo=timezone.utc)


class TestRegimenes:
    def test_regimen_vigente(self) -> None:
        assert regimes.regime_at(datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc))["id"] == "R3"
        assert regimes.regime_at(datetime(2026, 10, 8, 2, 0, tzinfo=timezone.utc))["id"] == "R1"
        assert regimes.regime_at(datetime(2026, 10, 1, tzinfo=timezone.utc)) is None
        ids = [r["id"] for r in regimes.regimes_between(datetime(2026, 10, 8, tzinfo=timezone.utc), NOW)]
        assert ids == ["R0", "R1", "R2", "R3"]

    def test_policy_version_ignora_secretos_y_cambia_con_la_politica(self) -> None:
        from response.config import ResponseSettings
        a = ResponseSettings(abuseipdb_api_key="uno", min_corroborating_sources_for_autoblock=2)
        b = ResponseSettings(abuseipdb_api_key="otro", min_corroborating_sources_for_autoblock=2)
        c = ResponseSettings(abuseipdb_api_key="uno", min_corroborating_sources_for_autoblock=3)
        assert regimes.policy_version(a) == regimes.policy_version(b)
        assert regimes.policy_version(a) != regimes.policy_version(c)
        assert "abuseipdb_api_key" not in regimes.effective_policy(a)
