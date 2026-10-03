"""
H39: persistencia de soc:response:audit en soc-responses con hash-chain.

- Cadena: cada documento apunta al hash del anterior; alterar CUALQUIER
  campo (no solo 4, como en el indexador de soc-decisions) se detecta.
- Consumer group: XACK solo después de persistir. Si el proceso cae a mitad
  de lote (o OpenSearch falla), nada se pierde, nada se duplica y la cadena
  no se bifurca al reiniciar.
- Sin contención: el indexador solo toca su stream y su grupo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import response_audit_indexer as rai  # noqa: E402
from response_audit_indexer import (  # noqa: E402
    GENESIS_HASH,
    GROUP,
    STREAM,
    AuditIndexerSettings,
    IndexingError,
    ResponseAuditIndexer,
    build_content,
    chain_document,
    compute_hash,
    index_name_for,
    verify_chain,
)


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeStreamRedis:
    """Streams con consumer groups: entrega con '>' (nuevos) y '0' (pendientes
    propios), XACK. Registra cada comando para el chequeo de contención."""

    def __init__(self):
        self.streams: dict[str, list[tuple[str, dict]]] = {}
        self.groups: dict[tuple[str, str], dict] = {}
        self.calls: list[tuple[str, str]] = []
        self._ms = 1_790_000_000_000

    def xadd(self, stream, fields, **kw):
        self._ms += 1
        msg_id = f"{self._ms}-0"
        self.streams.setdefault(stream, []).append((msg_id, fields))
        return msg_id

    def xgroup_create(self, stream, group, id="$", mkstream=False):
        self.calls.append(("xgroup_create", stream))
        if (stream, group) in self.groups:
            raise redis.ResponseError("BUSYGROUP Consumer Group name already exists")
        self.streams.setdefault(stream, [])
        self.groups[(stream, group)] = {"last": "0-0" if id == "0" else None, "pel": {}}

    def xreadgroup(self, group, consumer, streams, count=None, block=None):
        (stream, start), = streams.items()
        self.calls.append(("xreadgroup", stream))
        g = self.groups[(stream, group)]
        entries = self.streams.get(stream, [])
        if start == "0":
            out = [(m, f) for m, f in entries if g["pel"].get(m) == consumer][:count]
        else:
            last = g["last"]
            out = [(m, f) for m, f in entries if _gt(m, last)][:count]
            for m, _ in out:
                g["pel"][m] = consumer
            if out:
                g["last"] = out[-1][0]
        return [[stream, out]]

    def xack(self, stream, group, *ids):
        self.calls.append(("xack", stream))
        for i in ids:
            self.groups[(stream, group)]["pel"].pop(i, None)
        return len(ids)

    def pending(self, stream=STREAM, group=GROUP) -> int:
        return len(self.groups[(stream, group)]["pel"])


def _gt(a: str, b: str) -> bool:
    return tuple(map(int, a.split("-"))) > tuple(map(int, b.split("-")))


class FakeOpenSearch:
    """_create con 409 si existe; fallos inyectables (antes o después de
    escribir, para simular respuesta perdida)."""

    def __init__(self):
        self.indices: dict[str, dict[str, dict]] = {}
        self.fail_next = 0
        self.lose_response_next = 0  # escribe pero lanza error (timeout de respuesta)

    def create(self, index, doc_id, doc):
        if self.fail_next:
            self.fail_next -= 1
            raise IndexingError("HTTP 503")
        idx = self.indices.setdefault(index, {})
        if doc_id in idx:
            return "exists"
        idx[doc_id] = json.loads(json.dumps(doc))
        if self.lose_response_next:
            self.lose_response_next -= 1
            raise IndexingError("ReadTimeout tras escribir")
        return "created"

    def get_source(self, index, doc_id):
        return self.indices.get(index, {}).get(doc_id)

    def chain_head(self):
        docs = self.all_docs()
        return (docs[-1]["chain_seq"], docs[-1]["hash"]) if docs else (0, GENESIS_HASH)

    def all_docs(self) -> list[dict]:
        return sorted((d for idx in self.indices.values() for d in idx.values()), key=lambda d: d["chain_seq"])


def _settings() -> AuditIndexerSettings:
    return AuditIndexerSettings(batch_size=10, block_ms=1, redis_password="x", os_pass="x")


def _event(i: int) -> dict:
    return {"data": json.dumps({"trace_id": f"t-{i}", "tier": 3, "risk_score": 0.9, "src_ip": "1.2.3.4",
                                "accion_recomendada": "bloqueo_ip",
                                "block": {"action": "block", "reason": "ok", "enforced": True}})}


def _indexer(rdb, os_client) -> ResponseAuditIndexer:
    ix = ResponseAuditIndexer(rdb, os_client, _settings())
    ix.start()
    return ix


def _drain(ix: ResponseAuditIndexer, rounds: int = 20) -> None:
    for _ in range(rounds):
        ix.run_once()


# ── Cadena ────────────────────────────────────────────────────────────────────

class TestHashChain:
    def test_cada_documento_apunta_al_anterior(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(5):
            rdb.xadd(STREAM, _event(i))
        _drain(_indexer(rdb, osc))
        docs = osc.all_docs()
        assert [d["chain_seq"] for d in docs] == [1, 2, 3, 4, 5]
        assert docs[0]["prev_hash"] == GENESIS_HASH
        for prev, cur in zip(docs, docs[1:]):
            assert cur["prev_hash"] == prev["hash"]
        assert verify_chain(docs) == []

    def test_hash_es_sha256_del_contenido_completo_mas_prev(self) -> None:
        content = build_content("1790000000001-0", _event(1))
        doc = chain_document(content, 1, "abc")
        assert doc["hash"] == compute_hash({**content, "chain_seq": 1}, "abc")
        assert doc["hash"] == chain_document(content, 1, "abc")["hash"]  # determinístico

    @pytest.mark.parametrize("campo,valor", [
        ("accion_recomendada", "ninguna"), ("block_reason", "otro motivo"),
        ("src_ip", "9.9.9.9"), ("event_time", "2020-01-01T00:00:00+00:00"),
    ])
    def test_alterar_cualquier_campo_se_detecta(self, campo, valor) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(3):
            rdb.xadd(STREAM, _event(i))
        _drain(_indexer(rdb, osc))
        docs = osc.all_docs()
        docs[1][campo] = valor
        assert any("alterado" in p for p in verify_chain(docs))

    def test_alterar_el_payload_anidado_se_detecta(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        rdb.xadd(STREAM, _event(1))
        _drain(_indexer(rdb, osc))
        docs = osc.all_docs()
        docs[0]["payload"]["block"]["enforced"] = False
        assert verify_chain(docs) != []

    def test_borrar_un_documento_intermedio_se_detecta(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(4):
            rdb.xadd(STREAM, _event(i))
        _drain(_indexer(rdb, osc))
        docs = osc.all_docs()
        del docs[2]
        problems = verify_chain(docs)
        assert any("salto de secuencia" in p for p in problems)
        assert any("prev_hash" in p for p in problems)


# ── Garantías de entrega ──────────────────────────────────────────────────────

class TestEntrega:
    def test_ack_solo_despues_de_persistir(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(3):
            rdb.xadd(STREAM, _event(i))
        osc.fail_next = 1
        ix = _indexer(rdb, osc)
        with pytest.raises(IndexingError):
            ix.run_once()  # pendientes (vacío) -> nuevos: falla el primero
            ix.run_once()
        assert osc.all_docs() == []
        assert rdb.pending() == 3  # entregados pero sin XACK: no se pierden

    def test_caida_a_mitad_de_lote_y_reinicio_sin_perdidas_ni_duplicados(self) -> None:
        """Proceso 1 persiste 2 de 5 y muere (falla el 3.º). Proceso 2 arranca
        de cero: lee la cabeza desde OpenSearch y termina el resto."""
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(5):
            rdb.xadd(STREAM, _event(i))
        ix1 = _indexer(rdb, osc)
        ix1.run_once()  # pendientes: ninguno
        osc.fail_next = 0
        # el 3.º mensaje falla
        original = osc.create
        calls = {"n": 0}

        def flaky(index, doc_id, doc):
            calls["n"] += 1
            if calls["n"] == 3:
                raise IndexingError("proceso muere")
            return original(index, doc_id, doc)
        osc.create = flaky
        with pytest.raises(IndexingError):
            ix1.run_once()
        assert len(osc.all_docs()) == 2
        osc.create = original

        ix2 = _indexer(rdb, osc)  # "reinicio": estado nuevo, cabeza desde OpenSearch
        assert (ix2.seq, ix2.head_hash) == (2, osc.all_docs()[-1]["hash"])
        _drain(ix2)
        docs = osc.all_docs()
        assert [d["payload"]["trace_id"] for d in docs] == [f"t-{i}" for i in range(5)]
        assert verify_chain(docs) == []
        assert rdb.pending() == 0

    def test_respuesta_perdida_tras_escribir_no_duplica_ni_bifurca(self) -> None:
        """OpenSearch escribió pero la respuesta no llegó (timeout): sin XACK.
        Al reprocesar, _create da 409 y se confirma sin reescribir."""
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        for i in range(3):
            rdb.xadd(STREAM, _event(i))
        osc.lose_response_next = 1
        ix = _indexer(rdb, osc)
        with pytest.raises(IndexingError):
            ix.run_once()
            ix.run_once()
        assert rdb.pending() == 3 and len(osc.all_docs()) == 1
        ix2 = _indexer(rdb, osc)
        _drain(ix2)
        docs = osc.all_docs()
        assert [d["chain_seq"] for d in docs] == [1, 2, 3]
        assert len({d["stream_id"] for d in docs}) == 3
        assert verify_chain(docs) == []
        assert rdb.pending() == 0

    def test_eventos_nuevos_despues_de_un_reinicio_continuan_la_cadena(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        rdb.xadd(STREAM, _event(0))
        _drain(_indexer(rdb, osc))
        rdb.xadd(STREAM, _event(1))
        _drain(_indexer(rdb, osc))
        assert verify_chain(osc.all_docs()) == []
        assert osc.all_docs()[-1]["chain_seq"] == 2

    def test_grupo_existente_no_se_recrea(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        _indexer(rdb, osc)
        _indexer(rdb, osc)  # BUSYGROUP tolerado


# ── Contención con el worker ──────────────────────────────────────────────────

class TestSinContencion:
    def test_solo_toca_su_stream_y_su_grupo(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        rdb.xadd("soc:response:tasks", {"data": "{}"})  # stream del worker
        rdb.groups[("soc:response:tasks", "response-workers")] = {"last": "0-0", "pel": {}}
        for i in range(3):
            rdb.xadd(STREAM, _event(i))
        _drain(_indexer(rdb, osc))
        assert {s for _, s in rdb.calls} == {STREAM}
        assert GROUP != "response-workers"
        assert rdb.groups[("soc:response:tasks", "response-workers")] == {"last": "0-0", "pel": {}}


# ── Tipos de evento ───────────────────────────────────────────────────────────

class TestTiposDeEvento:
    def test_response_record(self) -> None:
        payload = {"trace_id": "t", "tier": 3, "risk_score": 0.91, "src_ip": "1.2.3.4",
                   "accion_recomendada": "ninguna", "event_age_seconds": 54000.0,
                   "block": {"action": "block_skipped", "reason": "stale_backlog_event_age>1h", "enforced": False}}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})
        assert d["event_type"] == "response"
        assert d["block_reason"] == "stale_backlog_event_age>1h"
        assert d["block_enforced"] is False and d["tier"] == 3
        assert d["payload"] == payload

    def test_approval_expired(self) -> None:
        payload = {"approval_expired": True, "trace_id": "t", "src_ip": "1.1.1.1", "status": "expired",
                   "resolved_by": "system:expiry", "occurrences": 4}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})
        assert (d["event_type"], d["status"], d["username"]) == ("approval_expired", "expired", "system:expiry")

    def test_aprobacion_manual(self) -> None:
        payload = {"manual_approval": True, "trace_id": "t", "approved_by": "ana", "approver_role": "N2",
                   "src_ip": "1.1.1.1", "enforced": True}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})
        assert (d["event_type"], d["username"], d["approver_role"], d["block_enforced"]) == \
            ("manual_approval", "ana", "N2", True)

    def test_evento_de_acceso(self) -> None:
        payload = {"access_event": "token_rejected_user_state", "username": "ana",
                   "detail": {"reason": "deshabilitado", "token_role": "N1"}}
        d = build_content("1790000000001-0", {"data": json.dumps(payload)})
        assert (d["event_type"], d["access_event"], d["username"]) == ("access", "token_rejected_user_state", "ana")

    def test_json_corrupto_se_persiste_igual(self) -> None:
        rdb, osc = FakeStreamRedis(), FakeOpenSearch()
        rdb.xadd(STREAM, {"data": "{no es json"})
        _drain(_indexer(rdb, osc))
        doc = osc.all_docs()[0]
        assert doc["event_type"] == "unparseable"
        assert doc["payload"]["raw"] == "{no es json"
        assert rdb.pending() == 0

    def test_indice_diario_segun_la_hora_del_mensaje(self) -> None:
        assert index_name_for("1790000000000-0") == "soc-responses-2026.09.21"

    def test_mapping_no_rechaza_campos_nuevos(self) -> None:
        assert rai.INDEX_MAPPINGS["dynamic"] is False
        assert rai.INDEX_MAPPINGS["properties"]["payload"] == {"type": "object", "enabled": False}

    def test_politica_ism_borra_a_los_90_dias(self) -> None:
        p = rai.ism_policy(90)["policy"]
        assert p["states"][0]["transitions"][0]["conditions"] == {"min_index_age": "90d"}
        assert p["ism_template"][0]["index_patterns"] == ["soc-responses-*"]
