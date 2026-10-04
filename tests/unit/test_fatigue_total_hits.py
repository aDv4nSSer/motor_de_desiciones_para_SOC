"""
H46 — fatiga_alertas_pct y total_decisiones no se cortan en 10.000.

OpenSearch, sin "track_total_hits", devuelve hits.total = 10.000 con
relation "gte" aunque la ventana tenga más documentos; las agregaciones sí
cuentan todo. get_stats() usaba ese total como denominador de la fatiga.
Caso real reproducido (producción, últimas 24 h al 2026-10-04 ~01:15 -03):
549.891 decisiones, fatiga real 77,8% y mostrada 4.277,6%.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

OS_DEFAULT_TRACK_LIMIT = 10_000
REAL_24H = {"LOG": 287_157, "ALLOW": 140_602, "ALERT": 105_788, "BLOCK": 16_344}
REAL_TOTAL = sum(REAL_24H.values())  # 549.891


class FakeOpenSearch:
    """Imita el conteo de OpenSearch: total exacto solo con track_total_hits=True."""

    def __init__(self, por_decision: dict[str, int]) -> None:
        self.por_decision = por_decision
        self.bodies: list[dict] = []

    def __call__(self, method: str, path: str, body: dict | None = None) -> dict:
        self.bodies.append(body or {})
        real = sum(self.por_decision.values())
        if (body or {}).get("track_total_hits") is True or real <= OS_DEFAULT_TRACK_LIMIT:
            total = {"value": real, "relation": "eq"}
        else:
            total = {"value": OS_DEFAULT_TRACK_LIMIT, "relation": "gte"}
        return {
            "hits": {"total": total, "hits": []},
            "aggregations": {
                "por_tier": {"buckets": []},
                "por_decision": {"buckets": [{"key": k, "doc_count": v} for k, v in self.por_decision.items()]},
                "latencia_avg": {"value": 60.4},
                "latencia_p95": {"values": {"95.0": 91.9}},
            },
        }


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")


@pytest.fixture
def fake_os(monkeypatch):
    import dashboard
    fake = FakeOpenSearch(REAL_24H)
    monkeypatch.setattr(dashboard, "_os_request", fake)
    return fake


def test_el_fake_reproduce_el_tope_de_opensearch() -> None:
    body_sin_track = {"size": 0, "query": {"match_all": {}}}
    assert FakeOpenSearch(REAL_24H)("POST", "/x", body_sin_track)["hits"]["total"] == {
        "value": 10_000, "relation": "gte"}


def test_get_stats_pide_el_total_exacto(fake_os) -> None:
    import dashboard
    dashboard.get_stats(1440)
    assert fake_os.bodies[0]["track_total_hits"] is True


def test_get_stats_cuenta_mas_de_10000(fake_os) -> None:
    import dashboard
    stats = dashboard.get_stats(1440)
    assert stats["total_decisiones"] == REAL_TOTAL == 549_891
    assert stats["por_decision"] == REAL_24H


def test_fatiga_real_del_caso_de_produccion(fake_os, monkeypatch) -> None:
    """compliance_report de punta a punta sobre get_stats real: 77,8%, no 4.277,6%."""
    import compliance
    monkeypatch.setattr(compliance, "get_precision_stats", lambda w: {"available": False})
    monkeypatch.setattr(compliance, "pending_approvals_page", lambda *a, **k: {"available": True, "total": 0})
    monkeypatch.setattr(compliance, "_users_by_role", lambda rdb: {"N1": 0, "N2": 0, "CISO": 1})
    monkeypatch.setattr(compliance.sess, "list_all_sessions", lambda rdb: [])
    monkeypatch.setattr(compliance.audit_view, "chain_status", lambda request: {"chains": {}, "tail_size": 0})
    monkeypatch.setattr(compliance, "response_counts", lambda since, request: {"available": False})
    monkeypatch.setattr(compliance, "ism_policies_present", lambda request: {})
    monkeypatch.setattr(compliance, "build_checklist", lambda ctx: [])

    report = compliance.compliance_report(1440, "ok", rdb=object(), request=lambda *a, **k: None)
    assert report["decisiones"]["total"] == 549_891
    assert report["fatiga_alertas_pct"] == 77.8
    assert report["fatiga_alertas_pct"] <= 100
