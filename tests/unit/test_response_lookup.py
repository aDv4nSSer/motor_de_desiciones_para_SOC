"""
H49 — la vista de alertas resuelve la respuesta R1/R2 por los trace_id de su
página, no por las últimas 200 entradas del stream.

Caso real reproducido (producción, 2026-10-05 ~11:46 -03): con ~8 entradas/s
en soc:response:audit, las últimas 200 cubrían ~25 s. De las 150 decisiones
T2+ más recientes, la ventana resolvía 36/50, 34/50 y 0/50 por página, aunque
150/150 tenían registro (las que faltaban en la página 1 estaban en proceso).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import redis

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")
sys.path.insert(0, MOTOR_PATH)

FRONTIER_MS = 1_791_212_203_926


def _record(trace_id: str, tier: int = 2, **extra) -> dict:
    return {"trace_id": trace_id, "tier": tier, "src_ip": "198.51.100.7",
            "accion_recomendada": "alertar_crear_caso",
            "enrichment": {"corroboration_count": 1}, "processed_at": 1.0, **extra}


class FakeOpenSearch:
    """soc-responses-*: responde la consulta `terms` con los registros persistidos."""

    def __init__(self, persisted: list[dict], down: bool = False) -> None:
        self.persisted = persisted
        self.down = down
        self.bodies: list[dict] = []

    def __call__(self, method: str, path: str, body: dict | None = None) -> dict | None:
        self.bodies.append({"path": path, **(body or {})})
        if self.down:
            return None
        wanted = set(body["query"]["bool"]["filter"][0]["terms"]["trace_id"])
        hits = [{"_source": {"payload": p}} for p in self.persisted if p["trace_id"] in wanted]
        return {"hits": {"hits": hits[: body["size"]]}}


class FakeRedis:
    """soc:response:audit (lista vieja→nueva) + XINFO GROUPS de los dos streams."""

    def __init__(self, audit: list[dict], indexer_lag: int | None = 0, broken: bool = False) -> None:
        self.audit = [(f"{i}-0", {"data": json.dumps(rec)}) for i, rec in enumerate(audit, 1)]
        self.indexer_lag = indexer_lag
        self.broken = broken
        self.scanned: list[int] = []

    def xinfo_groups(self, stream: str) -> list[dict]:
        if self.broken:
            raise redis.ConnectionError("redis caído")
        import dashboard
        s = dashboard.get_settings()
        if stream == dashboard.RESPONSE_AUDIT_STREAM:
            return [{"name": dashboard.RESPONSE_AUDIT_INDEXER_GROUP, "lag": self.indexer_lag, "pending": 0}]
        if stream == s.response_stream:
            return [{"name": s.response_group, "last-delivered-id": f"{FRONTIER_MS}-0"}]
        return []

    def xrevrange(self, stream: str, count: int | None = None) -> list:
        self.scanned.append(count or 0)
        return list(reversed(self.audit))[:count]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")


def _wire(monkeypatch, os_fake: FakeOpenSearch, redis_fake: FakeRedis):
    import dashboard
    monkeypatch.setattr(dashboard, "_os_request", os_fake)
    monkeypatch.setattr(dashboard, "_get_redis", lambda: redis_fake)
    return dashboard


class TestCasoDeProduccion:
    def test_resuelve_las_tres_paginas_completas(self, monkeypatch) -> None:
        # 150 decisiones T2+: 120 ya persistidas en soc-responses-*, las 30 más
        # nuevas solo en el stream (el indexador va 30 atrás). Entre medio, el
        # tráfico T1 que llenaba la ventana de 200 de la UI.
        pagina = [f"trace-{i:04d}" for i in range(150)]
        persisted = [_record(t) for t in pagina[:120]]
        audit: list[dict] = []
        for t in pagina:
            audit.extend(_record(f"t1-{t}-{k}", tier=1) for k in range(4))
            audit.append(_record(t))
        d = _wire(monkeypatch, FakeOpenSearch(persisted), FakeRedis(audit, indexer_lag=30))

        out = d.lookup_responses(pagina[:100]), d.lookup_responses(pagina[100:])
        resueltos = set(out[0]["responses"]) | set(out[1]["responses"])
        assert resueltos == set(pagina)
        assert all(o["complete"] for o in out)

        # La ventana vieja (últimas 200 entradas) no llegaba ni a la mitad.
        ventana = {r["trace_id"] for r in d.get_recent_responses(200)}
        assert len(ventana & set(pagina)) < 50

    def test_informa_la_frontera_del_worker(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([]), FakeRedis([]))
        out = d.lookup_responses(["trace-0001"])
        assert out["worker_frontier"] == "2026-10-05T14:56:43.926000+00:00"


class TestAusenciaSoloSiSePuedeAfirmar:
    def test_sin_registro_con_cobertura_completa(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([]), FakeRedis([_record("otro")], indexer_lag=0))
        out = d.lookup_responses(["trace-perdido"])
        assert out["responses"] == {}
        assert out["complete"] is True

    def test_opensearch_caido_no_afirma_ausencia(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([], down=True), FakeRedis([_record("trace-nuevo")]))
        out = d.lookup_responses(["trace-nuevo", "trace-viejo"])
        assert set(out["responses"]) == {"trace-nuevo"}  # la cola del stream igual resuelve
        assert out["sources"]["opensearch"] is False
        assert out["complete"] is False

    def test_atraso_del_indexador_mayor_que_la_cola(self, monkeypatch) -> None:
        import dashboard
        lag = dashboard.RESPONSE_TAIL_MAX
        d = _wire(monkeypatch, FakeOpenSearch([]), FakeRedis([], indexer_lag=lag))
        out = d.lookup_responses(["trace-x"])
        assert out["complete"] is False

    def test_lag_desconocido_no_afirma_ausencia(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([]), FakeRedis([], indexer_lag=None))
        assert d.lookup_responses(["trace-x"])["complete"] is False

    def test_redis_caido_conserva_lo_de_opensearch(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([_record("trace-a")]), FakeRedis([], broken=True))
        out = d.lookup_responses(["trace-a", "trace-b"])
        assert set(out["responses"]) == {"trace-a"}
        assert out["sources"]["redis"] is False
        assert out["complete"] is False

    def test_todo_resuelto_es_completo_aunque_redis_falle(self, monkeypatch) -> None:
        d = _wire(monkeypatch, FakeOpenSearch([_record("trace-a")]), FakeRedis([], broken=True))
        assert d.lookup_responses(["trace-a"])["complete"] is True


class TestConsultaDirigida:
    def test_terms_por_trace_id_solo_respuestas(self, monkeypatch) -> None:
        os_fake = FakeOpenSearch([])
        d = _wire(monkeypatch, os_fake, FakeRedis([]))
        d.lookup_responses(["trace-a", "trace-b", "trace-a"])
        body = os_fake.bodies[0]
        assert body["path"] == "/soc-responses-*/_search"
        filtros = body["query"]["bool"]["filter"]
        assert filtros[0] == {"terms": {"trace_id": ["trace-a", "trace-b"]}}
        assert filtros[1] == {"term": {"event_type": "response"}}

    def test_cola_revisada_es_atraso_mas_margen(self, monkeypatch) -> None:
        import dashboard
        redis_fake = FakeRedis([], indexer_lag=1_234)
        d = _wire(monkeypatch, FakeOpenSearch([]), redis_fake)
        d.lookup_responses(["trace-x"])
        assert redis_fake.scanned == [1_234 + dashboard.RESPONSE_TAIL_MARGIN]

    def test_no_escanea_el_stream_si_opensearch_resolvio_todo(self, monkeypatch) -> None:
        redis_fake = FakeRedis([])
        d = _wire(monkeypatch, FakeOpenSearch([_record("trace-a")]), redis_fake)
        d.lookup_responses(["trace-a"])
        assert redis_fake.scanned == []

    def test_descarta_accesos_aprobaciones_y_expiraciones(self, monkeypatch) -> None:
        audit = [
            {"access_event": "login_success", "trace_id": "trace-a"},
            {"trace_id": "trace-a", "manual_approval": True, "accion_recomendada": "x"},
            {"trace_id": "trace-a", "approval_expired": True, "enrichment": {}},
        ]
        d = _wire(monkeypatch, FakeOpenSearch([]), FakeRedis(audit))
        assert d.lookup_responses(["trace-a"])["responses"] == {}


@pytest.fixture
def client(monkeypatch):
    sys.path.insert(0, MOTOR_PATH)
    for mod in list(sys.modules):
        if mod in ("main", "redis_client", "response.queue", "response.config"):
            sys.modules.pop(mod)
    from fastapi.testclient import TestClient
    from users import User

    import main

    main.app.dependency_overrides[main.get_current_user] = (
        lambda: User(username="op", role="N1", created_at="", disabled=False)
    )
    monkeypatch.setattr(main, "lookup_responses", lambda ids: {"responses": {}, "ids": ids})
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


class TestEndpoint:
    URL = "/api/v1/dashboard/responses/lookup"

    def test_acepta_trace_ids_validos(self, client) -> None:
        resp = client.post(self.URL, json={"trace_ids": ["4f1c2b3a-aaaa-bbbb-cccc-1234567890ab"]})
        assert resp.status_code == 200
        assert resp.json()["ids"] == ["4f1c2b3a-aaaa-bbbb-cccc-1234567890ab"]
        assert resp.headers.get("X-Trace-Id")

    @pytest.mark.parametrize("ids", [[], ["corto"], ["a b c d e f g h"], ["x" * 65]])
    def test_rechaza_formatos_invalidos(self, client, ids) -> None:
        assert client.post(self.URL, json={"trace_ids": ids}).status_code == 422

    def test_rechaza_mas_del_maximo(self, client) -> None:
        import dashboard
        ids = [f"trace-{i:05d}" for i in range(dashboard.RESPONSE_LOOKUP_MAX_IDS + 1)]
        assert client.post(self.URL, json={"trace_ids": ids}).status_code == 422
