"""
Verifica response/approvals.py — la cola de aprobaciones humanas que gatea
las acciones de alto impacto de R2 (accion_recomendada ==
ACCION_ALERTAR_PENDIENTE_APROBACION). Caminos críticos: idempotencia por
trace_id, que una resolución nunca se pise, registros corruptos y
degradación con gracia cuando Redis falla.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
import redis

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from response.approvals import (
    APPROVALS_INDEX_KEY,
    APPROVALS_KEY_PREFIX,
    create_pending_approval,
    get_approval,
    list_pending_approvals,
    pending_approvals_page,
    resolve_approval,
)
from response.schemas import ActionType, BlockResult, ResponseRecord


class FakeRedis:
    """Redis mínimo en memoria — solo lo que approvals.py necesita
    (get/set con nx/sadd/srem/smembers). `fail_on` hace que esos comandos
    lancen RedisError para probar la degradación."""

    def __init__(self, fail_on: set[str] | None = None):
        self._kv: dict[str, str] = {}
        self._sets: dict[str, set[str]] = {}
        self._fail_on = fail_on or set()

    def _maybe_fail(self, op: str) -> None:
        if op in self._fail_on:
            raise redis.ConnectionError(f"redis caído ({op})")

    def set(self, key, value, nx=False):
        self._maybe_fail("set")
        if nx and key in self._kv:
            return None
        self._kv[key] = value
        return True

    def get(self, key):
        self._maybe_fail("get")
        return self._kv.get(key)

    def sadd(self, key, value):
        self._maybe_fail("sadd")
        self._sets.setdefault(key, set()).add(value)

    def srem(self, key, value):
        self._maybe_fail("srem")
        self._sets.get(key, set()).discard(value)

    def smembers(self, key):
        self._maybe_fail("smembers")
        return self._sets.get(key, set())


def _record(trace_id: str = "trace-cuarentena-1", approval_level: str = "N2") -> ResponseRecord:
    return ResponseRecord(
        trace_id=trace_id, tier=3, risk_score=0.93, src_ip="203.0.113.50",
        block=BlockResult(
            src_ip="203.0.113.50", action=ActionType.BLOCK_PENDING_APPROVAL,
            reason="corroboración insuficiente", requires_approval=True,
            approval_level=approval_level,
        ),
    )


class TestCreatePendingApproval:
    def test_registra_pendiente_e_indexa(self) -> None:
        rdb = FakeRedis()
        approval = create_pending_approval(_record(), rdb)
        assert approval["status"] == "pending"
        assert approval["approval_level"] == "N2"
        assert get_approval("trace-cuarentena-1", rdb) == approval
        assert rdb.smembers(APPROVALS_INDEX_KEY) == {"trace-cuarentena-1"}

    def test_idempotente_mismo_trace_id_no_duplica_ni_pisa(self) -> None:
        rdb = FakeRedis()
        first = create_pending_approval(_record(), rdb)
        second = create_pending_approval(_record(), rdb)
        assert second == first  # mismo created_at: no se reescribió
        assert rdb.smembers(APPROVALS_INDEX_KEY) == {"trace-cuarentena-1"}
        assert len(list_pending_approvals(rdb)) == 1

    @pytest.mark.parametrize("decision", ["approved", "rejected"])
    def test_no_reabre_una_aprobacion_ya_resuelta(self, decision) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        resolve_approval("trace-cuarentena-1", "ciso1", decision, rdb)

        again = create_pending_approval(_record(), rdb)

        assert again["status"] == decision
        assert again["resolved_by"] == "ciso1"
        assert get_approval("trace-cuarentena-1", rdb)["status"] == decision
        assert "trace-cuarentena-1" not in rdb.smembers(APPROVALS_INDEX_KEY)
        assert list_pending_approvals(rdb) == []

    def test_repara_indice_si_el_registro_pendiente_quedo_sin_indexar(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        rdb.srem(APPROVALS_INDEX_KEY, "trace-cuarentena-1")  # simula caída entre set y sadd

        create_pending_approval(_record(), rdb)

        assert rdb.smembers(APPROVALS_INDEX_KEY) == {"trace-cuarentena-1"}

    def test_redis_caido_loguea_y_no_rompe_al_caller(self, caplog) -> None:
        rdb = FakeRedis(fail_on={"set"})
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            approval = create_pending_approval(_record(), rdb)
        assert approval["status"] == "pending"
        assert "trace-cuarentena-1" in caplog.text


class TestResolveApproval:
    def test_approved(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        resolved = resolve_approval("trace-cuarentena-1", "n2-ana", "approved", rdb)
        assert resolved["status"] == "approved"
        assert resolved["resolved_by"] == "n2-ana"
        assert resolved["resolved_at"] is not None
        assert get_approval("trace-cuarentena-1", rdb) == resolved
        assert rdb.smembers(APPROVALS_INDEX_KEY) == set()

    def test_rejected(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        resolved = resolve_approval("trace-cuarentena-1", "n2-ana", "rejected", rdb)
        assert resolved["status"] == "rejected"
        assert get_approval("trace-cuarentena-1", rdb)["status"] == "rejected"
        assert rdb.smembers(APPROVALS_INDEX_KEY) == set()

    def test_resolver_dos_veces_no_pisa_la_resolucion_anterior(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        first = resolve_approval("trace-cuarentena-1", "n2-ana", "approved", rdb)

        second = resolve_approval("trace-cuarentena-1", "ciso-luis", "rejected", rdb)

        assert second == first
        stored = get_approval("trace-cuarentena-1", rdb)
        assert stored["status"] == "approved"
        assert stored["resolved_by"] == "n2-ana"
        assert stored["resolved_at"] == first["resolved_at"]

    def test_inexistente_devuelve_none(self) -> None:
        assert resolve_approval("no-existe", "n2-ana", "approved", FakeRedis()) is None

    def test_redis_falla_al_escribir_loguea_y_devuelve_none(self, caplog) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record(), rdb)
        rdb._fail_on = {"set"}
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            assert resolve_approval("trace-cuarentena-1", "n2-ana", "approved", rdb) is None
        assert "trace-cuarentena-1" in caplog.text
        rdb._fail_on = set()
        assert get_approval("trace-cuarentena-1", rdb)["status"] == "pending"

    def test_redis_falla_al_leer_loguea_y_devuelve_none(self, caplog) -> None:
        rdb = FakeRedis(fail_on={"get"})
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            assert resolve_approval("trace-cuarentena-1", "n2-ana", "approved", rdb) is None
        assert "trace-cuarentena-1" in caplog.text


class TestRegistroCorrupto:
    def test_get_approval_json_invalido_loguea_y_devuelve_none(self, caplog) -> None:
        rdb = FakeRedis()
        rdb.set(f"{APPROVALS_KEY_PREFIX}trace-roto", "{no es json")
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            assert get_approval("trace-roto", rdb) is None
        assert "trace-roto" in caplog.text

    def test_list_pending_omite_el_corrupto_y_devuelve_el_resto(self, caplog) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("trace-ok"), rdb)
        rdb.set(f"{APPROVALS_KEY_PREFIX}trace-roto", "{no es json")
        rdb.sadd(APPROVALS_INDEX_KEY, "trace-roto")
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            pending = list_pending_approvals(rdb)
        assert [a["trace_id"] for a in pending] == ["trace-ok"]
        assert "trace-roto" in caplog.text


class TestListPendingApprovals:
    def test_solo_pendientes_mas_recientes_primero_con_limite(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"trace-{i}"), rdb)
            stored = json.loads(rdb.get(f"{APPROVALS_KEY_PREFIX}trace-{i}"))
            stored["created_at"] = f"2026-09-30T10:0{i}:00+00:00"
            rdb.set(f"{APPROVALS_KEY_PREFIX}trace-{i}", json.dumps(stored))
        resolve_approval("trace-1", "n2-ana", "rejected", rdb)

        pending = list_pending_approvals(rdb, limit=1)

        assert [a["trace_id"] for a in pending] == ["trace-2"]
        assert [a["trace_id"] for a in list_pending_approvals(rdb)] == ["trace-2", "trace-0"]

    def test_redis_caido_devuelve_lista_vacia(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            assert list_pending_approvals(FakeRedis(fail_on={"smembers"})) == []
        assert "pendientes" in caplog.text


class TestPendingApprovalsPage:
    """El panel mostraba "100" cuando había 257: la página debe traer el total real."""

    def _con_pendientes(self, n: int) -> FakeRedis:
        rdb = FakeRedis()
        for i in range(n):
            create_pending_approval(_record(f"trace-{i:03d}"), rdb)
        return rdb

    def test_total_real_aunque_la_pagina_sea_menor(self) -> None:
        page = pending_approvals_page(self._con_pendientes(257), limit=100)
        assert page["total"] == 257
        assert len(page["items"]) == 100
        assert page["limit"] == 100
        assert page["available"] is True

    def test_total_excluye_resueltas(self) -> None:
        rdb = self._con_pendientes(5)
        resolve_approval("trace-001", "n2-ana", "rejected", rdb)
        assert pending_approvals_page(rdb, limit=100)["total"] == 4

    def test_redis_caido_no_se_confunde_con_cola_vacia(self, caplog) -> None:
        with caplog.at_level(logging.ERROR, logger="response.approvals"):
            page = pending_approvals_page(FakeRedis(fail_on={"smembers"}), limit=100)
        assert page == {"items": [], "total": 0, "limit": 100, "available": False}
