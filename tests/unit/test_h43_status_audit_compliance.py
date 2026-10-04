"""
H43 — Lógica de las vistas nuevas, sin red:
- system_status: clasificación de pipelines por lag/inactividad, OpenSearch
  por color, Wazuh sin credenciales / con API simulada (httpx.MockTransport).
- audit_view: detecta un documento alterado y un enlace roto, oculta los
  accesos a N2, verifica la cola de una cadena.
- compliance: checklist derivado de los datos, buckets H25 excluidos,
  conteo de fuentes de corroboración con su cobertura real.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")


# ── system_status ────────────────────────────────────────────────────────────

class FakeStreams:
    def __init__(self, groups=None, last_id="0-0", missing=False):
        self.groups, self.last_id, self.missing = groups or [], last_id, missing

    def xinfo_stream(self, stream):
        if self.missing:
            raise redis.ResponseError("ERR no such key")
        return {"length": 10, "last-generated-id": self.last_id}

    def xinfo_groups(self, stream):
        return self.groups


NOW = 1_791_000_000.0


class TestPipelines:
    def _check(self, rdb, stream="soc:response:tasks"):
        import system_status
        return system_status.check_pipeline(rdb, stream, "g", "svc", ".140", "desc", now=NOW)

    def test_al_dia(self) -> None:
        c = self._check(FakeStreams([{"name": "g", "lag": 3, "pending": 1}], f"{int(NOW * 1000)}-0"))
        assert c["status"] == "ok" and c["metrics"]["lag"] == 3

    @pytest.mark.parametrize("lag,status", [(1_000, "degraded"), (50_000, "down")])
    def test_atrasado(self, lag, status) -> None:
        assert self._check(FakeStreams([{"name": "g", "lag": lag, "pending": 0}]))["status"] == status

    def test_sin_consumer_group_es_down(self) -> None:
        c = self._check(FakeStreams([{"name": "otro", "lag": 0}]))
        assert c["status"] == "down" and "No hay consumer group" in c["detail"]

    def test_stream_inexistente_es_down(self) -> None:
        assert self._check(FakeStreams(missing=True))["status"] == "down"

    def test_fast_path_sin_trafico_se_marca(self) -> None:
        """La señal que habría delatado H25: decisiones que dejan de llegar."""
        old = f"{int((NOW - 3600) * 1000)}-0"
        c = self._check(FakeStreams([{"name": "g", "lag": 0, "pending": 0}], old), stream="soc:decisions")
        assert c["status"] == "degraded" and "sin decisiones nuevas hace 60 min" in c["detail"]


class TestOpenSearchYWazuh:
    @pytest.mark.parametrize("color,status", [("green", "ok"), ("yellow", "degraded"), ("red", "down")])
    def test_color_del_cluster(self, color, status) -> None:
        import system_status
        c = system_status.check_opensearch(lambda m, p, b=None: {"status": color, "unassigned_shards": 0})
        assert c["status"] == status

    def test_opensearch_sin_respuesta(self) -> None:
        import system_status
        assert system_status.check_opensearch(lambda *a, **k: None)["status"] == "down"

    def _settings(self, monkeypatch, user="", password="", enforcer_user="", enforcer_password=""):
        import system_status
        from response.config import ResponseSettings
        s = ResponseSettings(wazuh_nodes_user=user, wazuh_nodes_password=password,
                             wazuh_api_user=enforcer_user, wazuh_api_password=enforcer_password)
        monkeypatch.setattr(system_status, "get_settings", lambda: s)
        system_status._wazuh_cache.update(at=0.0, value=None)
        return system_status

    def test_wazuh_sin_credenciales(self, monkeypatch) -> None:
        ss = self._settings(monkeypatch)
        assert ss.fetch_wazuh_agents()["status"] == "not_configured"

    def test_nunca_usa_la_credencial_del_enforcer(self, monkeypatch) -> None:
        """Mínimo privilegio: con solo la credencial del enforcer (administrator
        en Wazuh) configurada, la vista no la usa ni hace ninguna llamada."""
        ss = self._settings(monkeypatch, enforcer_user="wazuh", enforcer_password="x")
        calls = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(req)
            return httpx.Response(200, json={})
        assert ss.fetch_wazuh_agents(transport=httpx.MockTransport(handler))["status"] == "not_configured"
        assert calls == []

    def test_autentica_con_el_usuario_de_solo_lectura(self, monkeypatch) -> None:
        ss = self._settings(monkeypatch, "rsoar-nodes-ro", "clave-ro", enforcer_user="wazuh", enforcer_password="adm")
        seen = []

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/authenticate"):
                seen.append(req.headers["authorization"])
                return httpx.Response(200, json={"data": {"token": "t"}})
            if req.url.path.endswith("/summary/status"):
                return httpx.Response(200, json={"data": {"connection": {"active": 1, "total": 1}}})
            return httpx.Response(200, json={"data": {"affected_items": [{"id": "000", "status": "active"}]}})
        ss.fetch_wazuh_agents(transport=httpx.MockTransport(handler))
        import base64
        assert seen == ["Basic " + base64.b64encode(b"rsoar-nodes-ro:clave-ro").decode()]

    def test_wazuh_agentes_desconectados_degradan(self, monkeypatch) -> None:
        ss = self._settings(monkeypatch, "lector", "x")

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/authenticate"):
                return httpx.Response(200, json={"data": {"token": "t"}})
            if req.url.path.endswith("/summary/status"):
                return httpx.Response(200, json={"data": {"connection": {"active": 2, "disconnected": 1, "total": 3}}})
            return httpx.Response(200, json={"data": {"affected_items": [
                {"id": "000", "name": "manager", "status": "active"},
                {"id": "001", "name": "web", "status": "active"},
                {"id": "002", "name": "ia", "status": "disconnected"}]}})
        c = ss.fetch_wazuh_agents(transport=httpx.MockTransport(handler))
        assert c["status"] == "degraded"
        assert c["metrics"]["active"] == 2 and len(c["metrics"]["agents"]) == 3

    def test_wazuh_caido(self, monkeypatch) -> None:
        ss = self._settings(monkeypatch, "lector", "x")

        def handler(req):
            raise httpx.ConnectError("sin ruta")
        assert ss.fetch_wazuh_agents(transport=httpx.MockTransport(handler))["status"] == "down"


# ── audit_view ───────────────────────────────────────────────────────────────

def _chain(contents: list[dict]) -> list[dict]:
    from response_audit_indexer import GENESIS_HASH, chain_document
    docs, prev = [], GENESIS_HASH
    for i, c in enumerate(contents, start=1):
        d = chain_document(c, i, prev)
        docs.append(d)
        prev = d["hash"]
    return docs


class FakeOS:
    """Responde _search por índice + query (term chain_seq / term trace_id / sort)."""

    def __init__(self, by_pattern: dict[str, list[dict]]):
        self.by_pattern = by_pattern

    def __call__(self, method, path, body=None):
        pattern = path.strip("/").split("/")[0]
        docs = list(self.by_pattern.get(pattern, []))
        q = (body or {}).get("query", {})
        if "term" in q:
            (field, value), = q["term"].items()
            docs = [d for d in docs if d.get(field) == value]
        if "ids" in q:
            docs = [d for d in docs if d.get("trace_id") in q["ids"]["values"]]
        sort = (body or {}).get("sort")
        if sort:
            (field, order), = sort[0].items()
            docs.sort(key=lambda d: d.get(field, 0), reverse=order == "desc")
        docs = docs[: (body or {}).get("size", 10)]
        return {"hits": {"hits": [{"_source": d} for d in docs]}}


class TestAuditView:
    def test_documento_alterado_se_detecta(self) -> None:
        import audit_view
        docs = _chain([{"trace_id": "t-0001-aaaa", "tier": 3}, {"trace_id": "t-0002-bbbb", "tier": 1}])
        docs[0]["tier"] = 0  # alguien "bajó" el tier después de indexar
        os = FakeOS({"soc-decisions-*": docs})
        v = audit_view.verify_document(docs[0], "soc-decisions-*", os)
        assert v["content_ok"] is False and v["next_link_ok"] is True
        assert audit_view.verify_document(docs[1], "soc-decisions-*", os)["prev_link_ok"] is True

    def test_n2_no_ve_eventos_de_acceso(self) -> None:
        import audit_view
        tid = "t-0001-aaaa"
        resp = _chain([
            {"trace_id": tid, "event_type": "response", "accion_recomendada": "bloqueo_ip"},
            {"trace_id": tid, "event_type": "access", "access_event": "approval_denied_role"},
        ])
        os = FakeOS({"soc-decisions-*": _chain([{"trace_id": tid, "tier": 3}]), "soc-responses-*": resp})
        partial = audit_view.search_trace(tid, include_access=False, request=os)
        full = audit_view.search_trace(tid, include_access=True, request=os)
        assert [e["doc"]["event_type"] for e in partial["events"]] == ["response"]
        assert partial["hidden_events"] == 1
        assert len(full["events"]) == 2
        assert all(e["verification"]["content_ok"] for e in full["events"])
        assert full["decisions"][0]["verification"]["content_ok"] is True

    def test_legado_con_formula_vieja(self) -> None:
        import audit_view
        d = {"trace_id": "t-legacy-01", "timestamp": "2026-10-01T00:00:00Z", "tier": 2, "risk_score": 0.5,
             "prev_hash": "abc"}
        d["hash"] = audit_view.legacy_hash("abc", d)
        os = FakeOS({"soc-decisions": [d]})
        out = audit_view.search_trace("t-legacy-01", include_access=False, request=os)
        assert out["decisions"][0]["verification"]["content_ok"] is True
        assert "solo trace_id" in out["decisions"][0]["verification"]["note"]

    def test_cola_integra_y_alterada(self) -> None:
        import audit_view
        docs = _chain([{"n": i, "event_time": f"2026-10-03T00:00:{i:02d}Z"} for i in range(30)])
        ok = audit_view.verify_tail("soc-responses-*", size=10, request=FakeOS({"soc-responses-*": docs}))
        assert ok["ok"] is True and ok["verified"] == 11 and ok["to_seq"] == 30
        docs[25]["n"] = 999
        bad = audit_view.verify_tail("soc-responses-*", size=10, request=FakeOS({"soc-responses-*": docs}))
        assert bad["ok"] is False and any("chain_seq 26" in p for p in bad["problems"])

    def test_opensearch_caido_no_es_cadena_integra(self) -> None:
        import audit_view
        out = audit_view.verify_tail("soc-responses-*", request=lambda *a, **k: None)
        assert out["available"] is False and out["ok"] is None

    @pytest.mark.parametrize("tid,ok", [("9291e87d-a84d-4e61-b429-8f9207fd401b", True),
                                         ("corto", False), ("a" * 65, False), ("x' OR 1=1", False)])
    def test_validacion_trace_id(self, tid, ok) -> None:
        import audit_view
        assert audit_view.valid_trace_id(tid) is ok


# ── compliance ───────────────────────────────────────────────────────────────

def _ctx(**over):
    base = {
        "stats": {"available": True, "total_decisiones": 12_000, "latencia_p95_ms": 61.0},
        "chains": {"responses": {"ok": True}, "decisions": {"ok": True}}, "tail_size": 2000,
        "responses": {"available": True, "acciones": {"ejecutadas_auto": 4}, "accesos": {"login_success": 3}},
        "ism": {"soc-decisions-retention": True, "soc-responses-retention": True},
        "nodes_overall": "ok", "users_by_role": {"N1": 2, "N2": 1, "CISO": 1}, "active_sessions": 2,
        "pending_approvals": 5, "response_mode": "enforce",
    }
    base.update(over)
    return base


class TestChecklist:
    def _by_id(self, ctx):
        import compliance
        return {i["id"]: i for i in compliance.build_checklist(ctx)}

    def test_todo_sano(self) -> None:
        items = self._by_id(_ctx())
        assert items["monitoreo"]["status"] == "cumple" and "12.000 decisiones" in items["monitoreo"]["evidence"]
        assert items["registro"]["status"] == "cumple"
        assert items["acceso"]["status"] == "cumple"
        assert items["respuesta"]["status"] == "cumple"
        # Lo que R-SOAR no hace nunca aparece como cumplido.
        assert items["alerta_temprana"]["status"] == "no_cubierto"
        assert items["informes"]["status"] == "no_cubierto"
        assert items["continuidad"]["status"] == "fuera_de_alcance"

    def test_cadena_rota_no_cumple(self) -> None:
        items = self._by_id(_ctx(chains={"responses": {"ok": False}, "decisions": {"ok": True}}))
        assert items["registro"]["status"] == "no_cubierto"

    def test_dry_run_es_parcial(self) -> None:
        assert self._by_id(_ctx(response_mode="dry_run"))["respuesta"]["status"] == "parcial"

    def test_sin_ism_es_parcial(self) -> None:
        items = self._by_id(_ctx(ism={"soc-decisions-retention": True, "soc-responses-retention": False}))
        assert items["registro"]["status"] == "parcial"


class TestTendencias:
    def test_buckets_h25_excluidos_no_son_cero(self) -> None:
        import compliance
        start = datetime(2026, 8, 25, tzinfo=timezone.utc)
        key = int(start.timestamp() * 1000)
        os = lambda m, p, b=None: {"aggregations": {"t": {"buckets": [
            {"key": key, "tiers": {"buckets": []}},
            {"key": key + 86_400_000 * 20, "tiers": {"buckets": [{"key": 3, "doc_count": 7}]}}]}}}
        out = compliance.tier_trend(start, start, "1d", timedelta(days=1), os)
        assert out["buckets"][0]["excluded"] is True and out["buckets"][0]["counts"] is None
        assert out["buckets"][1]["counts"]["T3"] == 7

    def test_dias_no_permitidos(self) -> None:
        import compliance
        with pytest.raises(ValueError):
            compliance.get_trends(3, rdb=object(), request=lambda *a, **k: None)

    def test_fuentes_de_corroboracion_con_cobertura(self) -> None:
        import compliance
        now = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)

        def rec(minutes_ago, sources, crowdsec=False):
            return ("x", {"data": json.dumps({"processed_at": (now - timedelta(minutes=minutes_ago)).timestamp(),
                                              "enrichment": {"corroborating_sources": sources,
                                                             "crowdsec_observado": crowdsec}})})

        class R:
            def xrevrange(self, stream, count):
                return [rec(1, ["abuseipdb", "otx"]), rec(2, ["abuseipdb"], True),
                        ("y", {"data": json.dumps({"access_event": "login_success"})}),
                        rec(3, []), rec(60 * 30, ["otx"])]  # 30 h atrás: fuera de la ventana, corta el recorrido
        out = compliance.corroboration_sources(now - timedelta(days=1), R())
        assert out["sources"] == [{"source": "abuseipdb", "count": 2}, {"source": "otx", "count": 1}]
        assert (out["evaluated"], out["sin_corroboracion"], out["crowdsec_observado"]) == (3, 1, 1)
        assert out["coverage_from"].startswith("2026-10-03T11:57")
        assert out["truncated"] is False

    def test_redis_caido(self) -> None:
        import compliance

        class R:
            def xrevrange(self, *a, **k):
                raise redis.ConnectionError("caído")
        assert compliance.corroboration_sources(datetime.now(timezone.utc), R())["available"] is False
