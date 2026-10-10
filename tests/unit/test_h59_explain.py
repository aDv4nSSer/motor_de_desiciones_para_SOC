"""
H59: traza explicativa v1 (motor/explain.py).

La traza es una lectura de lo guardado: no decide. Estos tests verifican que
1. los pesos y umbrales por defecto coinciden con motor/model.py;
2. la regla de tier reconstruida es la que corresponde y una inconsistencia
   se informa, no se corrige;
3. sobre los 180 docs reales del fixture de H56, la regla de R1/R2 que da la
   traza produce exactamente la acción que tomó process_task;
4. ningún camino de decisión importa explain.py.
"""
from __future__ import annotations

import ast
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "motor"))

import explain
from response.enrichment import enrich
from response.schemas import ActionType, AlertLookupResult, BlockResult, ResponseTask
from response.worker import process_task

from tests.unit.test_abuseipdb_tier_policy import DOCS, FakeRedis, FakeTI, _settings

TH = dict(explain.DEFAULT_THRESHOLDS)


class TestPesosYUmbrales:
    def test_pesos_iguales_a_model_py(self) -> None:
        src = (ROOT / "motor" / "model.py").read_text()
        m = re.search(r"risk_score\s*=\s*([\d.]+)\s*\*\s*ml_score\s*\+\s*([\d.]+)\s*\*\s*anomaly_score", src)
        assert m, "model.py ya no calcula risk_score con la forma esperada: revisar explain.RISK_WEIGHTS"
        assert (float(m.group(1)), float(m.group(2))) == (explain.RISK_WEIGHTS["ml_score"], explain.RISK_WEIGHTS["anomaly_score"])

    def test_umbrales_por_defecto_iguales_a_model_py(self) -> None:
        src = (ROOT / "motor" / "model.py").read_text()
        m = re.search(r"DEFAULT_THRESHOLDS\s*=\s*(\{[^}]*\})", src)
        assert m and ast.literal_eval(m.group(1)) == explain.DEFAULT_THRESHOLDS

    def test_sin_archivo_usa_los_valores_por_defecto(self, tmp_path) -> None:
        th, origin = explain.load_thresholds(tmp_path / "no-existe.json")
        assert th == explain.DEFAULT_THRESHOLDS and "por defecto" in origin

    def test_con_archivo_usa_sus_valores(self, tmp_path) -> None:
        f = tmp_path / "t.json"
        f.write_text('{"T0_max": 0.2, "T1_max": 0.5, "T2_max": 0.75, "otro": 1}')
        th, origin = explain.load_thresholds(f)
        assert th == {"T0_max": 0.2, "T1_max": 0.5, "T2_max": 0.75} and origin == str(f)


def _decision(ml: float, anomaly: float, tier: int, classtype: str | None = None) -> dict:
    return {"ml_score": ml, "anomaly_score": anomaly, "risk_score": round(0.7 * ml + 0.3 * anomaly, 4),
            "tier": tier, "classtype": classtype, "L4_DST_PORT": 80}


class TestFastPath:
    @pytest.mark.parametrize("ml,anomaly,tier,rule", [
        (0.1, 0.1, 0, "FP-TIER-T0"), (0.5, 0.4, 1, "FP-TIER-T1"),
        (0.8, 0.6, 2, "FP-TIER-T2"), (0.95, 0.9, 3, "FP-TIER-T3"),
    ])
    def test_regla_de_tier(self, ml, anomaly, tier, rule) -> None:
        out = explain.explain_fast_path(_decision(ml, anomaly, tier), TH, "test")
        assert out["regla"]["id"] == rule and out["tier_recalculado"] == tier and out["consistente"]
        assert sum(s["aporte"] for s in out["senales"]) == pytest.approx(out["risk_score"], abs=explain.RISK_TOLERANCE)

    def test_limite_exacto_cae_en_el_tier_inferior(self) -> None:
        d = {"ml_score": 0.0, "anomaly_score": 0.0, "risk_score": 0.80, "tier": 2}
        assert explain.explain_fast_path(d, TH, "test")["regla"]["id"] == "FP-TIER-T2"

    def test_override_por_classtype(self) -> None:
        ct = min(explain.T3_CLASSTYPES)
        out = explain.explain_fast_path(_decision(0.1, 0.1, 3, ct), TH, "test")
        assert out["regla"]["id"] == "FP-T3-CLASSTYPE" and out["consistente"]
        assert out["attack"]["classtype"] == ct

    def test_inconsistencia_se_informa_no_se_corrige(self) -> None:
        out = explain.explain_fast_path(_decision(0.95, 0.9, 1), TH, "test")
        assert out["consistente"] is False and out["tier"] == 1 and out["tier_recalculado"] == 3

    def test_sin_classtype_lo_declara(self) -> None:
        out = explain.explain_fast_path(_decision(0.5, 0.5, 1), TH, "test")
        assert "sin classtype" in out["attack"]["nota"]


def _record(mocker, doc):
    """process_task real sobre un doc del fixture (mismas dependencias falsas
    que la foto fija de R2), devolviendo el registro auditado."""
    ip = doc["src_ip"]
    mocker.patch("response.enrichment.httpx.get", side_effect=FakeTI({ip: doc["otx"]}, {ip: doc["abuseipdb_score"]}))
    mocker.patch("response.enrichment.abuseipdb_window_budget", return_value=10**6)
    mocker.patch("response.worker.enrich", side_effect=enrich)
    mocker.patch("response.enrichment.ABUSEIPDB_NON_DECISIVE_SHARE", 0.0)
    mocker.patch("response.worker.lookup_suricata_alert", return_value=AlertLookupResult(status="no_match"))
    mocker.patch("response.worker.respond_block", return_value=BlockResult(
        src_ip=ip, action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado", enforcer="dry_run"))
    mocker.patch("response.worker.create_pending_approval")
    mocker.patch("response.worker.open_case", return_value={"case_id": "c"})
    rdb = FakeRedis()
    rdb.pipeline = mocker.MagicMock()
    rdb.pipeline.return_value.execute.return_value = [0, 1, 0, 0, True]
    rdb.xadd = mocker.MagicMock()
    task = ResponseTask(trace_id="t-explain", tier=doc["tier"], risk_score=doc["risk_score"], src_ip=ip,
                        dst_ip="200.54.12.139", L4_DST_PORT=doc["dst_port"] or 80, ts=time.time())
    return process_task(task, _settings(), rdb, mocker.MagicMock())


EXPECTED_ACTION = {
    "T2-CASO": "alertar_crear_caso", "T2-INFRA-PROPIA": "ninguna_infra_propia",
    "R2-PENDIENTE-APROBACION": "alertar_pendiente_aprobacion", "R2-CORROBORADO": "bloqueo_ip",
}


class TestRespuestaSobreDocsReales:
    def test_la_regla_explica_la_accion_de_cada_doc(self, mocker) -> None:
        settings, seen = _settings(), set()
        for doc in DOCS:
            rec = _record(mocker, doc)
            out = explain.explain_response(rec.to_audit_dict(), settings)
            rule = out["r2"]["regla"]["id"]
            seen.add(rule)
            assert out["consistente"], (doc["src_ip"], rule)
            assert rec.accion_recomendada == EXPECTED_ACTION[rule], (doc["src_ip"], rule)
            assert out["r1"]["corroboration_count"] == rec.enrichment.corroboration_count
            assert [s["senal"] for s in out["r1"]["senales"] if s["corrobora"]] == sorted(rec.enrichment.corroborating_sources)
        assert {"T2-CASO", "R2-PENDIENTE-APROBACION", "R2-CORROBORADO"} <= seen  # cubre las ramas reales


class TestRespuestaSintetica:
    def _payload(self, **kw) -> dict:
        base = {"tier": 3, "accion_recomendada": "alertar_pendiente_aprobacion",
                "enrichment": {"corroboration_count": 1, "corroborating_sources": ["otx"], "otx_available": True,
                               "otx_pulse_count": 3, "abuseipdb_available": False},
                "block": {"action": "block_pending_approval", "enforced": False, "reason": "corroboración insuficiente (1/2 fuentes)"}}
        base.update(kw)
        return base

    def test_pendiente(self) -> None:
        out = explain.explain_response(self._payload(), _settings())
        assert out["r2"]["regla"]["id"] == "R2-PENDIENTE-APROBACION" and out["consistente"]

    def test_stale(self) -> None:
        p = self._payload(block={"action": "block_skipped", "enforced": False, "reason": "stale_backlog_event_age>1h"})
        out = explain.explain_response(p, _settings())
        assert out["r2"]["regla"]["id"] == "R2-STALE" and out["consistente"]

    def test_safelist(self) -> None:
        p = self._payload(accion_recomendada="ninguna",
                          block={"action": "block_skipped", "enforced": False, "reason": "safelisted (infra del lab)"})
        assert explain.explain_response(p, _settings())["r2"]["regla"]["id"] == "R2-SAFELIST"

    def test_accion_que_no_corresponde_se_marca_inconsistente(self) -> None:
        p = self._payload(block={"action": "block", "enforced": True, "reason": "bloqueo ejecutado"})
        out = explain.explain_response(p, _settings())
        assert out["consistente"] is False  # 1 fuente y bloqueo: la traza no lo justifica

    def test_sombra_no_decide(self) -> None:
        p = self._payload(corroboration_band="high", corroboration_score=80.0,
                          corroboration_groups=[{"name": "ml", "available": True, "score": 0.9, "weight": 25, "detail": "x"}])
        out = explain.explain_response(p, _settings())
        assert "no decide" in out["sombra"]["nota"] and out["sombra"]["grupos"][0]["peso"] == 25

    def test_t0_t1_sin_accion(self) -> None:
        out = explain.explain_response({"tier": 1, "accion_recomendada": "ninguna"}, _settings())
        assert out["r2"]["regla"]["id"] == "R-SIN-ACCION" and out["consistente"]


def test_traza_completa_y_limitacion_shap(tmp_path) -> None:
    trace = {"trace_id": "t-1",
             "decisions": [{"chain": "soc-decisions-*", "doc": _decision(0.95, 0.9, 3), "verification": {"content_ok": True}}],
             "events": [{"doc": {"event_type": "response", "payload": {"tier": 3, "accion_recomendada": "bloqueo_ip",
                         "enrichment": {"corroboration_count": 2, "corroborating_sources": ["abuseipdb", "otx"]},
                         "block": {"action": "block", "enforced": True, "reason": "bloqueo ejecutado"}}},
                         "verification": {"content_ok": True}}]}
    out = explain.explain_trace(trace, _settings(), tmp_path / "sin-umbrales.json")
    assert out["version"] == "explain-v1" and out["fast_path"]["regla"]["id"] == "FP-TIER-T3"
    assert out["respuesta"]["r2"]["regla"]["id"] == "R2-CORROBORADO" and out["respuesta"]["consistente"]
    assert out["integridad"]["decision"] == {"content_ok": True}
    assert any("SHAP" in x for x in out["limitaciones"])


def test_ningun_camino_de_decision_importa_explain() -> None:
    for path in [ROOT / "motor" / "model.py", *(ROOT / "motor" / "response").glob("*.py"), *(ROOT / "motor" / "scoring").glob("*.py")]:
        tree = ast.parse(path.read_text())
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert "explain" not in names, path
