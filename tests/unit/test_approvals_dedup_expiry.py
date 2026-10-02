"""
H38 (B): cola de aprobaciones con dedup por IP, expiración a las 4 h y sin
aprobaciones para IPs de safelist.

- Una aprobación pendiente por src_ip: eventos nuevos de la misma IP suman
  ocurrencias en vez de crear filas.
- Pendiente con más de approval_ttl_seconds -> "expired" (no "rejected":
  nadie lo decidió), auditado por el worker.
- Las transiciones usan compare-and-set: el barrido no pisa una resolución
  hecha en paralelo por un operador.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from response.approvals import (  # noqa: E402
    APPROVALS_BY_IP_PREFIX,
    APPROVALS_INDEX_KEY,
    APPROVALS_KEY_PREFIX,
    create_pending_approval,
    expire_stale_approvals,
    get_approval,
    is_expired,
    pending_approvals_page,
    resolve_approval,
)
from response.config import ResponseSettings  # noqa: E402
from response.schemas import (  # noqa: E402
    ACCION_NINGUNA,
    ActionType,
    EnrichmentResult,
    ResponseTask,
)
from response.worker import process_task, sweep_expired_approvals  # noqa: E402
from test_approvals import FakeRedis, _record  # noqa: E402

TTL = 4 * 3600


def _age(rdb: FakeRedis, trace_id: str, hours: float) -> None:
    """Retrocede created_at de una aprobación `hours` horas."""
    a = get_approval(trace_id, rdb)
    a["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    rdb._kv[f"{APPROVALS_KEY_PREFIX}{trace_id}"] = json.dumps(a)


class TestDedupPorIP:
    def test_misma_ip_suma_ocurrencias_en_vez_de_crear_filas(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1", src_ip="95.40.160.2"), rdb)
        second = create_pending_approval(_record("t-2", src_ip="95.40.160.2"), rdb)
        third = create_pending_approval(_record("t-3", src_ip="95.40.160.2"), rdb)
        assert second["trace_id"] == third["trace_id"] == "t-1"
        assert third["occurrences"] == 3
        assert third["last_trace_id"] == "t-3"
        page = pending_approvals_page(rdb)
        assert page["total"] == 1
        assert page["items"][0]["occurrences"] == 3
        assert get_approval("t-2", rdb) is None  # no se creó registro aparte

    def test_ips_distintas_son_aprobaciones_distintas(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1", src_ip="1.2.3.4"), rdb)
        create_pending_approval(_record("t-2", src_ip="5.6.7.8"), rdb)
        assert pending_approvals_page(rdb)["total"] == 2

    def test_reentrega_del_mismo_trace_no_suma(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        again = create_pending_approval(_record("t-1"), rdb)
        assert again["occurrences"] == 1

    @pytest.mark.parametrize("decision", ["approved", "rejected"])
    def test_tras_resolver_un_evento_nuevo_abre_otra(self, decision) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        resolve_approval("t-1", "n1-ana", decision, rdb)
        fresh = create_pending_approval(_record("t-9"), rdb)
        assert fresh["trace_id"] == "t-9"
        assert fresh["occurrences"] == 1
        assert get_approval("t-1", rdb)["status"] == decision  # la resuelta no se reabre
        assert rdb.get(f"{APPROVALS_BY_IP_PREFIX}1.2.3.4") == "t-9"

    def test_tras_expirar_un_evento_nuevo_abre_otra(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        _age(rdb, "t-1", 5)
        expire_stale_approvals(rdb, TTL)
        assert create_pending_approval(_record("t-9"), rdb)["trace_id"] == "t-9"

    def test_registro_previo_al_dedup_se_lee_con_una_ocurrencia(self) -> None:
        rdb = FakeRedis()
        legacy = {"trace_id": "old-1", "src_ip": "1.2.3.4", "tier": 3, "risk_score": 0.9,
                  "reason": "x", "approval_level": "N1", "status": "pending",
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "resolved_by": None, "resolved_at": None}
        rdb.set(f"{APPROVALS_KEY_PREFIX}old-1", json.dumps(legacy))
        rdb.sadd(APPROVALS_INDEX_KEY, "old-1")
        item = pending_approvals_page(rdb)["items"][0]
        assert item["occurrences"] == 1
        assert item["last_seen_at"] == legacy["created_at"]

    def test_orden_por_actividad_mas_reciente(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-a", src_ip="1.1.1.1"), rdb)
        create_pending_approval(_record("t-b", src_ip="2.2.2.2"), rdb)
        create_pending_approval(_record("t-a2", src_ip="1.1.1.1"), rdb)  # 1.1.1.1 vuelve a aparecer
        assert [i["src_ip"] for i in pending_approvals_page(rdb)["items"]] == ["1.1.1.1", "2.2.2.2"]


class TestExpiracion:
    def test_solo_expiran_las_de_mas_de_4h(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("vieja", src_ip="1.1.1.1"), rdb)
        create_pending_approval(_record("nueva", src_ip="2.2.2.2"), rdb)
        _age(rdb, "vieja", 4.1)
        _age(rdb, "nueva", 3.9)
        expired = expire_stale_approvals(rdb, TTL)
        assert [a["trace_id"] for a in expired] == ["vieja"]
        v = get_approval("vieja", rdb)
        assert v["status"] == "expired"
        assert v["resolved_by"] == "system:expiry"
        assert "vieja" not in rdb.smembers(APPROVALS_INDEX_KEY)
        assert rdb.get(f"{APPROVALS_BY_IP_PREFIX}1.1.1.1") is None
        assert get_approval("nueva", rdb)["status"] == "pending"

    def test_no_toca_las_ya_resueltas(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        resolve_approval("t-1", "n2-luis", "rejected", rdb)
        _age(rdb, "t-1", 10)
        assert expire_stale_approvals(rdb, TTL) == []
        assert get_approval("t-1", rdb)["status"] == "rejected"

    def test_expirada_conserva_sus_ocurrencias(self) -> None:
        rdb = FakeRedis()
        for i in range(4):
            create_pending_approval(_record(f"t-{i}"), rdb)
        _age(rdb, "t-0", 5)
        assert expire_stale_approvals(rdb, TTL)[0]["occurrences"] == 4

    def test_fecha_ilegible_cuenta_como_vencida(self) -> None:
        assert is_expired({"created_at": "no-es-fecha"}, TTL) is True
        assert is_expired({}, TTL) is True

    def test_listado_oculta_vencidas_sin_escribir(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        _age(rdb, "t-1", 5)
        assert pending_approvals_page(rdb, ttl_seconds=TTL)["total"] == 0
        assert get_approval("t-1", rdb)["status"] == "pending"  # el listado no la expira

    def test_operador_resuelve_mientras_el_barrido_corre_y_gana_el_operador(self) -> None:
        """WATCH/MULTI: entre la lectura del barrido y su escritura, un
        operador rechaza. El barrido detecta el cambio y no lo pisa."""
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)
        _age(rdb, "t-1", 5)
        rdb.on_watch = lambda: resolve_approval("t-1", "n1-ana", "rejected", rdb)
        assert expire_stale_approvals(rdb, TTL) == []
        final = get_approval("t-1", rdb)
        assert final["status"] == "rejected"
        assert final["resolved_by"] == "n1-ana"

    def test_conflictos_persistentes_no_escriben(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-1"), rdb)

        def always_conflict():
            rdb._touch(f"{APPROVALS_KEY_PREFIX}t-1")
            rdb.on_watch = always_conflict
        rdb.on_watch = always_conflict
        assert resolve_approval("t-1", "n1-ana", "approved", rdb) is None
        rdb.on_watch = None
        assert get_approval("t-1", rdb)["status"] == "pending"


def _settings(**over) -> ResponseSettings:
    base = {"r1_min_tier": 1, "r2_min_tier": 3, "min_corroborating_sources_for_autoblock": 2,
            "response_mode": "enforce", "approval_ttl_seconds": TTL}
    base.update(over)
    return ResponseSettings(**base)


class TestWorker:
    def test_ip_de_safelist_no_crea_aprobacion(self, mocker) -> None:
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(src_ip="10.30.30.1", corroboration_count=1))
        create = mocker.patch("response.worker.create_pending_approval")
        task = ResponseTask(trace_id="t-infra", tier=3, risk_score=0.9, src_ip="10.30.30.1", L4_DST_PORT=22)
        record = process_task(task, _settings(), mocker.MagicMock(), mocker.MagicMock())
        create.assert_not_called()
        assert record.block.action == ActionType.BLOCK_SKIPPED
        assert record.block.reason == "safelisted (infra del lab)"
        assert record.accion_recomendada == ACCION_NINGUNA

    def test_ip_de_safelist_extra_tampoco(self, mocker) -> None:
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(src_ip="200.54.12.139", corroboration_count=0))
        create = mocker.patch("response.worker.create_pending_approval")
        task = ResponseTask(trace_id="t-bastion", tier=3, risk_score=0.9, src_ip="200.54.12.139", L4_DST_PORT=22)
        process_task(task, _settings(response_safelist_extra="200.54.12.139"), mocker.MagicMock(), mocker.MagicMock())
        create.assert_not_called()

    def test_barrido_audita_cada_expiracion_como_expired(self) -> None:
        rdb = FakeRedis()
        audited: list[dict] = []
        rdb.xadd = lambda stream, fields, **kw: audited.append(json.loads(fields["data"]))
        create_pending_approval(_record("t-1", src_ip="1.1.1.1"), rdb)
        create_pending_approval(_record("t-1b", src_ip="1.1.1.1"), rdb)
        create_pending_approval(_record("t-2", src_ip="2.2.2.2"), rdb)
        _age(rdb, "t-1", 6)
        assert sweep_expired_approvals(_settings(), rdb) == 1
        assert audited == [{
            "approval_expired": True, "trace_id": "t-1", "src_ip": "1.1.1.1", "status": "expired",
            "resolved_by": "system:expiry", "created_at": audited[0]["created_at"],
            "expired_at": audited[0]["expired_at"], "occurrences": 2, "ttl_seconds": TTL,
        }]
