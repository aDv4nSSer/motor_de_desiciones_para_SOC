"""
H52: score de corroboración ponderado en MODO SOMBRA dentro de
response/worker.py:process_task, y sus campos buscables en soc-responses-*.

Lo que se verifica, en orden de importancia:
1. INVARIANCIA -- el score no cambia la decisión real. Para cada escenario
   (corroborado/no corroborado por el gate viejo, safelist, stale, sin
   enrichment, T2 y T3) process_task se corre dos veces: con
   compute_corroboration real y con uno parcheado que devuelve el extremo
   (band="high", score=100). block, accion_recomendada y las llamadas al
   enforcer / aprobación / caso tienen que ser idénticas.
2. Degradación con gracia -- si compute_corroboration o attack_fields
   fallan, la decisión real queda intacta y los campos en su default.
3. T0/T1 no calculan nada.
4. response_audit_indexer extrae los campos top-level sin romper payloads
   viejos, y la cadena hash sigue íntegra mezclando docs viejos y nuevos.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.config import ResponseSettings
from response.schemas import (
    ActionType,
    BlockResult,
    EnrichmentResult,
    ResponseTask,
)
from response.worker import process_task
from response_audit_indexer import STREAM, build_content, verify_chain
from scoring.schemas import CorroborationResult, GroupScore

from tests.unit.test_response_audit_indexer import (
    FakeOpenSearch,
    FakeStreamRedis,
    _drain,
    _indexer,
)

PUBLIC_IP = "1.2.3.5"
PRIVATE_IP = "10.30.30.2"  # safelisted (rango privado, ver enforcer.is_safelisted)

EXTREME = CorroborationResult(
    score=100.0, band="high", ambiguous=False,
    groups=[GroupScore(name="ml", available=True, score=1.0, weight=20.0, detail="forzado")],
    weight_available=20.0, reasoning=["forzado por el test"],
)


def _settings(**overrides) -> ResponseSettings:
    base = {
        "r1_min_tier": 2,
        "r2_min_tier": 3,
        "min_corroborating_sources_for_autoblock": 2,
        "response_mode": "dry_run",
    }
    base.update(overrides)
    return ResponseSettings(**base)


def _task(tier: int, src_ip: str = PUBLIC_IP, stale: bool = False) -> ResponseTask:
    return ResponseTask(
        trace_id=f"trace-shadow-t{tier}", tier=tier, risk_score=0.93,
        src_ip=src_ip, dst_ip="10.10.10.3", L4_DST_PORT=443,
        ts=time.time() - (7200 if stale else 1),
    )


def _enrichment(count: int) -> EnrichmentResult:
    sources = ["abuseipdb", "otx"][:count]
    return EnrichmentResult(
        src_ip=PUBLIC_IP, corroboration_count=count, corroborating_sources=sources,
        abuseipdb_score=90 if "abuseipdb" in sources else None,
        otx_pulse_count=4 if "otx" in sources else 0,
    )


# (id, tier, src_ip, stale, enrichment count | None = R1 no corre, overrides de settings)
SCENARIOS = [
    ("t3_corroborado", 3, PUBLIC_IP, False, 2, {}),
    ("t3_count_1", 3, PUBLIC_IP, False, 1, {}),
    ("t3_count_0", 3, PUBLIC_IP, False, 0, {}),
    ("t3_safelisted", 3, PRIVATE_IP, False, 0, {}),
    ("t3_safelisted_corroborado", 3, PRIVATE_IP, False, 2, {}),
    ("t3_stale_corroborado", 3, PUBLIC_IP, True, 2, {}),
    ("t3_stale_no_corroborado", 3, PUBLIC_IP, True, 0, {}),
    ("t3_sin_enrichment", 3, PUBLIC_IP, False, None, {"r1_min_tier": 5}),
    ("t2_corroborado", 2, PUBLIC_IP, False, 2, {}),
    ("t2_count_0", 2, PUBLIC_IP, False, 0, {}),
    ("t2_stale", 2, PUBLIC_IP, True, 1, {}),
    ("t2_sin_enrichment", 2, PUBLIC_IP, False, None, {"r1_min_tier": 5}),
    ("t2_con_r2_desde_t2", 2, PUBLIC_IP, False, 0, {"r2_min_tier": 2}),
]


def _run(mocker, tier, src_ip, stale, count, overrides, corr_patch=None):
    """Corre process_task con todas las dependencias con IO mockeadas y
    devuelve (record, llamadas observables, payload auditado)."""
    settings = _settings(**overrides)
    rdb = mocker.MagicMock(**{"get.return_value": None})
    enforcer = mocker.MagicMock(name="dry_run")
    mocker.patch(
        "response.worker.enrich",
        return_value=_enrichment(count) if count is not None else EnrichmentResult(),
    )
    respond_block = mocker.patch(
        "response.worker.respond_block",
        return_value=BlockResult(src_ip=src_ip, action=ActionType.BLOCK, enforced=True,
                                 reason="bloqueo ejecutado", enforcer="dry_run"),
    )
    pending = mocker.patch("response.worker.create_pending_approval")
    open_case = mocker.patch("response.worker.open_case", return_value={"case_id": "case-1"})
    if corr_patch is not None:
        mocker.patch("response.worker.compute_corroboration", **corr_patch)

    record = process_task(_task(tier, src_ip, stale), settings, rdb, enforcer)

    def norm(v):
        # rdb/enforcer son mocks nuevos en cada corrida: se comparan por rol,
        # no por identidad.
        if v is rdb:
            return "<rdb>"
        if v is enforcer:
            return "<enforcer>"
        if isinstance(v, dict):
            return {k: norm(x) for k, x in v.items()}
        if isinstance(v, tuple | list):
            return type(v)(norm(x) for x in v)
        return v

    calls = {
        "respond_block": [norm((c.args, c.kwargs)) for c in respond_block.call_args_list],
        # create_pending_approval recibe el record entero; lo que persiste
        # son campos explícitos (approvals.py), ninguno corroboration_*.
        # Se compara todo menos la sombra y los timestamps de la corrida.
        "pending_approval": [
            norm((c.args[0].model_dump(exclude=_VOLATILE), *c.args[1:]))
            for c in pending.call_args_list
        ],
        "open_case": [norm(c.kwargs) for c in open_case.call_args_list],
        "enforcer": enforcer.mock_calls,
    }
    (_stream, fields), _ = rdb.xadd.call_args
    return record, calls, json.loads(fields["data"])


_VOLATILE = {
    "corroboration_score", "corroboration_band", "corroboration_ambiguous",
    "corroboration_groups", "processed_at", "event_age_seconds",
}


def _decision(record) -> tuple:
    b = record.block
    return (
        record.accion_recomendada, record.case_id,
        None if b is None else (b.action, b.enforced, b.reason, b.requires_approval, b.approval_level),
    )


class TestInvariancia:
    @pytest.mark.parametrize(
        "tier,src_ip,stale,count,overrides",
        [s[1:] for s in SCENARIOS], ids=[s[0] for s in SCENARIOS],
    )
    def test_score_extremo_no_cambia_la_decision_real(
        self, mocker, tier, src_ip, stale, count, overrides,
    ) -> None:
        real, real_calls, _ = _run(mocker, tier, src_ip, stale, count, overrides)
        mocker.stopall()
        forced, forced_calls, _ = _run(
            mocker, tier, src_ip, stale, count, overrides,
            corr_patch={"return_value": EXTREME},
        )

        assert _decision(forced) == _decision(real)
        assert forced_calls == real_calls
        # El parche realmente se aplicó (si no, el test no probaría nada):
        assert forced.corroboration_band == "high"
        assert forced.corroboration_score == 100.0

    @pytest.mark.parametrize(
        "tier,src_ip,stale,count,overrides",
        [s[1:] for s in SCENARIOS], ids=[s[0] for s in SCENARIOS],
    )
    def test_t2_plus_quedan_poblados_y_viajan_al_audit(
        self, mocker, tier, src_ip, stale, count, overrides,
    ) -> None:
        record, _, audited = _run(mocker, tier, src_ip, stale, count, overrides)

        assert record.corroboration_band in {"low", "medium", "high", "ambiguous"}
        assert 0.0 <= record.corroboration_score <= 100.0
        assert [g["name"] for g in record.corroboration_groups] == ["ml", "ti", "signature", "context"]
        # g_sig / g_ctx sin instrumento en producción (H50, sin acumulador):
        by_name = {g["name"]: g for g in record.corroboration_groups}
        assert by_name["signature"]["available"] is False
        assert by_name["context"]["available"] is False
        assert audited["corroboration_band"] == record.corroboration_band
        assert audited["corroboration_score"] == record.corroboration_score
        assert audited["corroboration_groups"] == record.corroboration_groups

    def test_sin_ti_disponible_el_score_es_solo_ml(self, mocker) -> None:
        record, _, _ = _run(mocker, 3, PUBLIC_IP, False, None, {"r1_min_tier": 5})
        # risk_score 0.93 renormalizado sobre g_ml sola -> 93/100, pero con
        # un solo grupo disponible la banda se capa en "medium" (P3, H53).
        assert record.corroboration_score == 93.0
        assert record.corroboration_band == "medium"
        assert record.corroboration_ambiguous is False


class TestDegradacionConGracia:
    @pytest.mark.parametrize("target", ["compute_corroboration", "attack_fields"])
    @pytest.mark.parametrize(
        "tier,count", [(3, 2), (3, 0), (2, 1)], ids=["t3_corroborado", "t3_pendiente", "t2"],
    )
    def test_falla_no_toca_la_decision_y_deja_defaults(
        self, mocker, caplog, target, tier, count,
    ) -> None:
        baseline, baseline_calls, _ = _run(mocker, tier, PUBLIC_IP, False, count, {})
        mocker.stopall()
        mocker.patch(f"response.worker.{target}", side_effect=RuntimeError("roto a propósito"))
        with caplog.at_level(logging.ERROR, logger="response.worker"):
            record, calls, audited = _run(mocker, tier, PUBLIC_IP, False, count, {})

        assert _decision(record) == _decision(baseline)
        assert calls == baseline_calls
        assert record.corroboration_score == 0.0
        assert record.corroboration_band == ""
        assert record.corroboration_ambiguous is False
        assert record.corroboration_groups == []
        assert any(
            "corroboración sombra falló" in r.getMessage() and "roto a propósito" in r.getMessage()
            for r in caplog.records
        )
        # Y el audit sigue saliendo (la decisión se registra igual).
        assert audited["accion_recomendada"] == record.accion_recomendada


class TestT0T1:
    @pytest.mark.parametrize("tier", [0, 1])
    def test_no_se_calcula(self, mocker, tier) -> None:
        settings = _settings(r1_min_tier=1)
        rdb = mocker.MagicMock(**{"get.return_value": None})
        mocker.patch("response.worker.enrich", return_value=_enrichment(2))
        spy = mocker.patch("response.worker.compute_corroboration")

        record = process_task(_task(tier), settings, rdb, mocker.MagicMock())

        spy.assert_not_called()
        assert record.corroboration_score == 0.0
        assert record.corroboration_band == ""
        assert record.corroboration_ambiguous is False
        assert record.corroboration_groups == []


class TestIndexer:
    def test_extrae_los_4_campos_de_un_payload_nuevo(self, mocker) -> None:
        record, _, audited = _run(mocker, 3, PUBLIC_IP, False, 1, {})
        d = build_content("1790000000001-0", {"data": json.dumps(audited)})

        assert d["event_type"] == "response"
        assert d["corroboration_score"] == record.corroboration_score
        assert d["corroboration_band"] == record.corroboration_band
        assert d["corroboration_ambiguous"] is record.corroboration_ambiguous
        assert d["corroboration_count"] == 1
        # groups solo en payload (no indexado):
        assert "corroboration_groups" not in d
        assert d["payload"]["corroboration_groups"] == record.corroboration_groups

    def test_payload_viejo_sin_campos_no_rompe(self) -> None:
        payload = {"trace_id": "t", "tier": 3, "risk_score": 0.9, "src_ip": PUBLIC_IP,
                   "accion_recomendada": "alertar_pendiente_aprobacion",
                   "enrichment": {"src_ip": PUBLIC_IP, "corroboration_count": 0},
                   "block": {"action": "block_pending_approval", "enforced": False, "reason": "x"}}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})

        assert d["event_type"] == "response"
        assert d["corroboration_count"] == 0
        for k in ("corroboration_score", "corroboration_band", "corroboration_ambiguous"):
            assert k not in d

    def test_sin_enrichment_ni_score_no_agrega_nada(self) -> None:
        payload = {"trace_id": "t", "tier": 3, "risk_score": 0.9, "accion_recomendada": "ninguna",
                   "corroboration_score": 0.0, "corroboration_band": "",
                   "corroboration_ambiguous": False, "corroboration_groups": []}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})

        for k in ("corroboration_score", "corroboration_band", "corroboration_ambiguous",
                  "corroboration_count"):
            assert k not in d

    def test_mapping_declara_los_campos(self) -> None:
        import response_audit_indexer as rai

        props = rai.INDEX_MAPPINGS["properties"]
        assert props["corroboration_score"] == {"type": "float"}
        assert props["corroboration_band"] == {"type": "keyword"}
        assert props["corroboration_ambiguous"] == {"type": "boolean"}
        assert props["corroboration_count"] == {"type": "integer"}
        assert rai.INDEX_MAPPINGS["dynamic"] is False

    def test_cadena_mixta_viejo_y_nuevo_integra(self, mocker) -> None:
        _, _, nuevo = _run(mocker, 3, PUBLIC_IP, False, 2, {})
        viejo = {k: v for k, v in nuevo.items() if not k.startswith("corroboration_")}
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for p in (viejo, nuevo, viejo, nuevo):
            rdb.xadd(STREAM, {"data": json.dumps(p)})
        _drain(_indexer(rdb, osc))

        docs = osc.all_docs()
        assert [("corroboration_band" in d) for d in docs] == [False, True, False, True]
        assert verify_chain(docs) == []
        # Alterar un campo nuevo rompe la cadena igual que cualquier otro.
        docs[1]["corroboration_band"] = "low" if docs[1]["corroboration_band"] != "low" else "high"
        assert any("alterado" in p for p in verify_chain(docs))
