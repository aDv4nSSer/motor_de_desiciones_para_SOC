"""
H57: vista Cumplimiento consistente, auditable y honesta.

- a1: índice de usuarios vacío o inconsistente: "dato no confiable", nunca 0.
- a2: nunca "con evidencia" con un nodo degradado; diagnóstico de réplicas.
- a3: conciliación de aprobaciones por dos caminos, con datos sintéticos.
- a4: cada fila con ventana, unidad, fuente, hora y enlace.
- b: panel de integridad con alcance y huecos declarados.
- d: tiempos; el humano queda "sin datos" sin aprobaciones resueltas.
- e: cobertura sin "fuera del sistema", policy_version y regime_id.
- f: historial diario con regímenes.
- g: contenido legal verificado (Ley 21.663 y DS 295/2024).
OpenSearch y Redis siempre falsos.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import compliance

NOW = datetime(2026, 10, 9, 3, 0, tzinfo=timezone.utc)
SINCE = NOW - timedelta(hours=24)
IN = (SINCE + timedelta(hours=2)).isoformat()      # creada dentro de la ventana
BEFORE = (SINCE - timedelta(hours=2)).isoformat()  # creada antes de la ventana


def _ctx(**over):
    base = {
        "stats": {"available": True, "total_decisiones": 12_000, "latencia_p95_ms": 61.0},
        "chains": {"responses": {"ok": True}, "decisions": {"ok": True}}, "tail_size": 2000,
        "responses": {"available": True, "accesos": {"login_success": 3}},
        "ism": {"soc-decisions-retention": True, "soc-responses-retention": True},
        "nodes_overall": "ok", "node_observations": [], "users_by_role": {"N1": 0, "N2": 0, "CISO": 1},
        "users_index": {"reliable": True}, "active_sessions": 1, "response_mode": "enforce",
        "reconciliation": {"available": True, "ips_bloqueadas": 3, "acciones_de_bloqueo": 4, "ips_derivadas": 2,
                           "decisiones_t3_derivadas": 7, "pendientes_ahora": 1,
                           "aprobaciones": {"creadas_en_la_ventana": 2, "expiradas": 1, "pendientes": 1,
                                            "aprobadas": 0, "rechazadas": 0, "recurrencias": 5},
                           "conciliacion": {"available": True, "estado": "cierra", "cierra": True, "diferencia": 0}},
        "integrity": {"completa": {"available": False}, "huecos_declarados": {"gaps": [{"id": "H54"}]}},
        "generated_at": NOW.isoformat(), "window_label": "ventana móvil de 24 h", "organizacion_es_oiv": None,
    }
    base.update(over)
    return base


def _by_id(ctx):
    return {i["id"]: i for i in compliance.build_checklist(ctx)}


# ── a1 (vista) ──

class TestVistaUsuarios:
    def test_la_vista_dice_dato_no_confiable_y_no_cero(self) -> None:
        items = _by_id(_ctx(users_index={"reliable": False, "reason": "índice de usuarios vacío en Redis"},
                            users_by_role={}, active_sessions="sin dato"))
        ev = items["acceso"]["evidence"]
        assert "dato no confiable" in ev and "CISO 0" not in ev and "0 sesiones" not in ev


# ── a2 ───────────────────────────────────────────────────────────────────────

class TestNodos:
    @pytest.mark.parametrize("overall", ["ok", "degraded", "unknown"])
    def test_art_8_d_siempre_parcial_y_dice_que_queda_en_la_organizacion(self, overall) -> None:
        it = _by_id(_ctx(nodes_overall=overall))["monitoreo"]
        assert it["status"] == "parcial"  # nunca "con evidencia", con o sin nodo degradado
        assert "Cubre R-SOAR: análisis continuo" in it["evidence"]
        assert "Queda en la organización: ejercicios, simulacros y la comunicación de amenazas al CSIRT" in it["evidence"]

    def test_diagnostico_de_replicas_visible(self) -> None:
        nodes = {"components": [{"id": "opensearch", "name": "OpenSearch", "host": ".140", "status": "degraded",
                                 "detail": "Clúster yellow, 180 shards sin asignar"},
                                {"id": "redis", "status": "ok"}]}
        shards = {"available": True, "replicas": 180, "by_prefix": {"security-auditlog": 100, "suricata-alerts": 71}}
        obs = compliance._node_observations(nodes, shards)
        assert len(obs) == 1 and "180 shards réplica sin asignar" in obs[0] and "suricata-alerts 71" in obs[0]

    def test_shards_diagnosis_por_prefijo(self) -> None:
        rows = [{"index": "suricata-alerts-2026.10.08", "prirep": "r", "state": "UNASSIGNED"},
                {"index": "suricata-alerts-2026.10.07", "prirep": "r", "state": "UNASSIGNED"},
                {"index": "soc-responses-2026.10.08", "prirep": "p", "state": "STARTED"},
                {"index": ".opendistro-ism-config", "prirep": "r", "state": "UNASSIGNED"}]
        d = compliance.shards_diagnosis(lambda *a, **k: rows)
        assert d["replicas"] == 3 and d["primaries"] == 0
        assert d["by_prefix"] == {"suricata-alerts": 2, ".opendistro-ism-config": 1}


# ── a3 ───────────────────────────────────────────────────────────────────────

class FakeOS:
    """soc-responses sintético. Aprobaciones creadas en la ventana: A1 expirada
    (4 ocurrencias), A2 aprobada (1), A3 pendiente (3, en la foto de Redis).
    Creadas ANTES de la ventana: A0 expirada dentro (3 ocurrencias) y P0
    pendiente (1). `derived_ids` es el trace_id de cada decisión derivada con
    aprobación de por medio; `stale` son derivadas sin aprobación (H38)."""

    def __init__(self, derived_ids, stale=0, a0_occ=3):
        self.derived_ids, self.stale = derived_ids, stale
        self.events = [
            {"event_type": "approval_expired", "trace_id": "A1", "payload": {"created_at": IN, "occurrences": 4}},
            {"event_type": "approval_expired", "trace_id": "A0", "payload": {"created_at": BEFORE, "occurrences": a0_occ}},
            {"event_type": "manual_approval", "trace_id": "A2", "payload": {"approval_created_at": IN}},
        ]

    def __call__(self, method, path, body=None):
        if "aggs" in (body or {}):
            buckets = [{"key": "block_pending_approval", "doc_count": len(self.derived_ids)}]
            if self.stale:
                buckets.append({"key": "block_skipped", "doc_count": self.stale})
            return {"hits": {"total": {"value": 0}}, "aggregations": {
                "derivadas": {"doc_count": len(self.derived_ids) + self.stale, "ips": {"value": 3},
                              "accion": {"buckets": buckets}},
                "bloqueos": {"doc_count": 4, "ips": {"value": 2}}}}
        filt = body["query"]["bool"]["filter"]
        terms = [f["terms"] for f in filt if "terms" in f]
        if terms and "trace_id" in terms[0]:
            wanted = set(terms[0]["trace_id"])
            return {"hits": {"total": {"value": sum(1 for t in self.derived_ids if t in wanted)}}}
        if body.get("search_after"):
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_source": e, "sort": [i]} for i, e in enumerate(self.events)]}}


@pytest.fixture
def pending(monkeypatch):
    monkeypatch.setattr(compliance, "list_pending_approvals",
                        lambda rdb, limit: [{"trace_id": "A3", "created_at": IN, "occurrences": 3},
                                            {"trace_id": "P0", "created_at": BEFORE, "occurrences": 1}])


# Creaciones A1, A2, A3; recurrencias: 3 de A1, 2 de A3 (contador: 5) y las de A0 (abierta antes).
def _derived(extra_a0: int) -> list[str]:
    return ["A1", "a1", "a1", "a1", "A2", "A3", "a3", "a3"] + ["a0"] * extra_a0


class TestConciliacion:
    def test_cierra_exacto_sin_borde(self, pending) -> None:
        rec = compliance.approvals_reconciliation(SINCE, NOW, object(), FakeOS(_derived(0)))
        apr, c = rec["aprobaciones"], rec["conciliacion"]
        assert apr["creadas_en_la_ventana"] == 3
        assert (apr["aprobadas"], apr["rechazadas"], apr["expiradas"], apr["pendientes"]) == (1, 0, 1, 1)
        assert c["creadas_por_destino"] == c["creadas_por_documentos"] == 3
        assert c["recurrencias_por_documentos"] == c["recurrencias_por_contador"] == 5
        assert c["estado"] == "cierra" and c["cierra"] is True
        assert rec["pendientes_ahora"] == 2  # foto actual: incluye P0, creada antes

    def test_diferencia_explicada_por_aprobaciones_abiertas_antes(self, pending) -> None:
        rec = compliance.approvals_reconciliation(SINCE, NOW, object(), FakeOS(_derived(2)))
        c = rec["conciliacion"]
        assert c["recurrencias_por_documentos"] == 7 and c["recurrencias_por_contador"] == 5
        assert c["diferencia"] == 2 and c["cota_borde"] == 2  # A0: 3 ocurrencias, hasta 2 recurrencias
        assert c["estado"] == "diferencia_explicada" and c["cierra"] is True
        assert "aprobaciones abiertas antes" in c["causa"]
        items = _by_id(_ctx(reconciliation=rec))
        assert items["respuesta"]["status"] == "con_observacion"
        assert "Diferencia explicada" in items["respuesta"]["evidence"]

    def test_no_cierra_si_la_diferencia_supera_la_cota(self, pending) -> None:
        rec = compliance.approvals_reconciliation(SINCE, NOW, object(), FakeOS(_derived(5)))
        c = rec["conciliacion"]
        assert c["estado"] == "no_cierra" and c["cierra"] is False
        items = _by_id(_ctx(reconciliation=rec))
        assert items["respuesta"]["status"] == "con_observacion" and "NO cierra" in items["respuesta"]["evidence"]

    def test_no_cierra_si_falta_la_decision_que_abrio_una_aprobacion(self, pending) -> None:
        derived = [t for t in _derived(0) if t != "A3"]  # la apertura de A3 no está en la ventana
        c = compliance.approvals_reconciliation(SINCE, NOW, object(), FakeOS(derived))["conciliacion"]
        assert c["estado"] == "no_cierra" and "difieren" in c["causa"]

    def test_derivadas_sin_aprobacion_se_informan_aparte(self, pending) -> None:
        rec = compliance.approvals_reconciliation(SINCE, NOW, object(), FakeOS(_derived(0), stale=4))
        assert rec["decisiones_derivadas_sin_aprobacion"] == 4
        assert rec["conciliacion"]["estado"] == "cierra"  # no entran a las recurrencias

    def test_evento_sin_created_at_se_declara(self, pending) -> None:
        os_ = FakeOS(_derived(0))
        os_.events.append({"event_type": "approval_expired", "trace_id": "A9", "payload": {}})
        rec = compliance.approvals_reconciliation(SINCE, NOW, object(), os_)
        assert rec["aprobaciones"]["eventos_sin_created_at"] == 1

    def test_unidades_explicitas_en_la_fila(self) -> None:
        ev = _by_id(_ctx())["respuesta"]["evidence"]
        assert "IPs distintas bloqueadas" in ev and "IPs distintas derivadas" in ev
        assert "recurrencias" in ev and "Foto actual" in ev


# ── a4 ───────────────────────────────────────────────────────────────────────

def test_cada_fila_medida_trae_ventana_unidad_fuente_hora_y_enlace() -> None:
    for i in compliance.build_checklist(_ctx()):
        if i["source"] == "automático":
            m = i["meta"]
            assert all(m.get(k) for k in ("ventana", "unidad", "fuente", "actualizado", "registros")), i["id"]
    mon = _by_id(_ctx())["monitoreo"]["evidence"]
    assert "latencia interna del Fast Path" in mon and "sin red ni Vector" in mon and "percentil aproximado" in mon


# ── b ────────────────────────────────────────────────────────────────────────

class TestIntegridad:
    def test_huecos_declarados_incluyen_h54_con_su_rango(self) -> None:
        gaps = {g["id"]: g for g in compliance.declared_gaps()["gaps"]}
        assert gaps["H54"]["desde"] == "2026-10-08T03:32:41.987Z" and gaps["H54"]["hasta"] == "2026-10-08T03:32:45.538Z"
        assert gaps["H54"]["detectable_por_cadena"] is False
        assert {"H25", "H42-corte"} <= set(gaps)

    @staticmethod
    def _with_report(monkeypatch, tmp_path, report):
        rep = tmp_path / "verify_chain_latest.json"
        if report is not None:
            rep.write_text(json.dumps(report))
        real = compliance.full_verification
        monkeypatch.setattr(compliance, "full_verification", lambda: real(rep))

    def test_sin_informe_el_alcance_es_solo_la_cola(self, tmp_path, monkeypatch) -> None:
        self._with_report(monkeypatch, tmp_path, None)
        live = {"chains": {"responses": {"ok": True}, "decisions": {"ok": True}}}
        panel = compliance.integrity_panel(live)
        assert panel["alcance"] == "solo_cola" and panel["completa"]["available"] is False

    def test_informe_completo_e_integro(self, tmp_path, monkeypatch) -> None:
        self._with_report(monkeypatch, tmp_path, {"alcance": "completa", "ok": True, "generated_at": NOW.isoformat()})
        live_ok = {"chains": {"responses": {"ok": True}, "decisions": {"ok": True}}}
        live_bad = {"chains": {"responses": {"ok": False}, "decisions": {"ok": True}}}
        assert compliance.integrity_panel(live_ok)["alcance"] == "completa"
        assert compliance.integrity_panel(live_bad)["alcance"] == "parcial"

    def test_informe_abortado_es_parcial(self, tmp_path, monkeypatch) -> None:
        self._with_report(monkeypatch, tmp_path, {"alcance": "parcial", "ok": False})
        live = {"chains": {"responses": {"ok": True}, "decisions": {"ok": True}}}
        assert compliance.integrity_panel(live)["alcance"] == "parcial"


# ── d ────────────────────────────────────────────────────────────────────────

def test_tiempo_humano_sin_datos_sin_aprobaciones_resueltas() -> None:
    def req(method, path, body=None):
        if "aggs" in (body or {}):
            return {"hits": {"total": {"value": 5}}, "aggregations": {
                "decision": {"values": {"50.0": 12.0, "95.0": 900.0}},
                "bloqueo": {"doc_count": 2, "p": {"values": {"50.0": 10.0, "95.0": 20.0}}}}}
        if body.get("search_after"):
            return {"hits": {"hits": []}}
        if "block_enforced" in json.dumps(body):
            return {"hits": {"hits": [{"_source": {"event_time": "2026-10-09T02:00:05Z",
                                                   "payload": {"processed_at": NOW.replace(hour=2).timestamp()}},
                                       "sort": [1]}]}}
        return {"hits": {"hits": []}}
    t = compliance.response_timings(SINCE, req)
    assert t["deteccion_a_decision_s"]["p95"] == 900.0
    assert t["decision_a_bloqueo_s"]["p50"] == 5.0
    assert t["humano_s"]["n"] == 0 and "sin datos" in t["humano_s"]["detalle"]


# ── e ────────────────────────────────────────────────────────────────────────

class TestResumenYRegimen:
    def test_cobertura_no_cuenta_fuera_del_sistema(self) -> None:
        items = compliance.build_checklist(_ctx())
        s = compliance.coverage_summary(items, NOW.isoformat())
        assert s["obligaciones_del_sistema"] + s["fuera_del_sistema"] == len(items)
        assert "fuera_de_alcance" not in s["por_estado"]


# ── f ────────────────────────────────────────────────────────────────────────

def test_historial_diario_con_regimenes() -> None:
    def req(method, path, body=None):
        day = datetime(2026, 10, 8, 3, 0, tzinfo=timezone.utc)
        return {"aggregations": {"dia": {"buckets": [{
            "key": int(day.timestamp() * 1000), "key_as_string": "2026-10-08T00:00:00.000-03:00",
            "bloqueos": {"ips": {"value": 240}}, "derivadas": {"ips": {"value": 480}},
            "expiradas": {"doc_count": 1300}}]}}}
    h = compliance.daily_history(7, req, now=NOW)
    row = h["dias"][0]
    assert row["razon_bloqueo_sobre_derivacion"] == 0.5 and row["ips_bloqueadas"] == 240
    assert row["regimenes"] == ["R1", "R2", "R3"]


# ── g ────────────────────────────────────────────────────────────────────────

class TestContenidoLegal:
    def test_art_7_son_deberes_generales(self) -> None:
        it = _by_id(_ctx())["acceso"]
        assert it["article"] == "Art. 7" and "Deberes generales" in it["title"]

    def test_filas_fuera_del_sistema_para_8_f_g_h(self) -> None:
        items = _by_id(_ctx())
        for iid, art in (("certificaciones", "Art. 8 f)"), ("afectados", "Art. 8 g)"), ("capacitacion", "Art. 8 h)")):
            assert items[iid]["article"] == art and items[iid]["status"] == "fuera_de_alcance"

    def test_plazos_y_fuentes_del_art_9_y_ds_295(self) -> None:
        items = _by_id(_ctx())
        assert "3 h desde el conocimiento" in items["alerta_temprana"]["title"]
        assert "DS 295 art. 10" in items["segundo_reporte"]["article"]
        assert "desde el envío de la alerta temprana" in items["informe_final"]["title"]
        assert "cada 15 días" in items["informe_final"]["title"] and "13" in items["informe_final"]["article"]
        assert items["plan_accion"]["article"] == "Art. 9, párrafo final; DS 295 art. 11"

    @pytest.mark.parametrize("oiv,frase", [(None, "Aplica solo si"), (True, "se declaró operador"),
                                           (False, "declaró no ser")])
    def test_nota_de_aplicabilidad_oiv(self, oiv, frase) -> None:
        assert frase in _by_id(_ctx(organizacion_es_oiv=oiv))["respuesta"]["evidence"]

    def test_ninguna_fila_promete_cumplimiento_legal(self) -> None:
        text = json.dumps(compliance.build_checklist(_ctx()), ensure_ascii=False).lower()
        assert "cumple la ley" not in text and "cumplimiento legal garantizado" not in text
        assert "evidencia técnica de apoyo" in compliance.SCOPE_NOTE


def test_alcance_explicito_de_la_verificacion_completa() -> None:
    full = {"available": True, "alcance": "completa", "generated_at": "2026-10-09T04:04:48+00:00", "cadenas": {
        "responses": {"pattern": "soc-responses-*", "first_time": "2026-10-02T21:50:46Z", "first_seq": 1,
                      "last_seq": 1699916, "ok": True, "aborted": None},
        "decisions": {"pattern": "soc-decisions-*", "first_time": "2026-10-03T06:16:52Z", "first_seq": 1,
                      "last_seq": 2456573, "ok": True, "aborted": None}}}
    t = compliance.chain_scope_text(full)
    assert "soc-responses-* desde 2026-10-02, chain_seq 1 a 1699916, íntegra" in t
    assert "soc-decisions-* desde 2026-10-03, chain_seq 1 a 2456573, íntegra" in t
    assert "2026-10-09 04:04 UTC" in t and "17,9 M" in t and "no se verificó" in t
    assert "17,9 M" in compliance.chain_scope_text({"available": False})
    ev = _by_id(_ctx(integrity={"completa": full, "huecos_declarados": {"gaps": [{"id": "H54"}]}}))["registro"]["evidence"]
    assert "chain_seq 1 a 1699916" in ev and "H54" in ev
