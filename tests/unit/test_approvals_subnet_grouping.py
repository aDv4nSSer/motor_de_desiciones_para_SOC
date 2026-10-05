"""
Agrupación por subred de la cola de aprobaciones N1 — medición 5-oct-2026
(ver BITACORA_TECNICA): 78% de la cola es un solo /24 (91.92.42.0/24,
reputación a nivel de red vía Spamhaus DROP) pedido IP por IP. Esto agrupa
la REVISIÓN de un bloque entero en un solo ítem -- no cambia la clave de
dedup de create_pending_approval (sigue siendo por IP exacta, H38) ni el
gate de corroboración de R2.

Casos cubiertos:
- Agrupa solo con >= GROUP_MIN_SIZE IPs en la misma red /prefix_len.
- No agrupa niveles de aprobación distintos aunque compartan red.
- IP no parseable pasa sin agrupar en vez de romper.
- occurrences suma, tier/risk_score toman el máximo del grupo.
- resolver un grupo resuelve cada trace_id individualmente (mismo CAS/
  idempotencia que resolve_approval) y no se cae si uno ya fue resuelto.
- pending_approvals_page(group=True): total sigue siendo la cuenta real de
  IPs, no la de ítems en pantalla.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from response.approvals import (  # noqa: E402
    create_pending_approval,
    group_by_subnet,
    pending_approvals_page,
    resolve_approval_group,
)
from test_approvals import FakeRedis, _record  # noqa: E402

RED_RUIDOSA = "91.92.42"  # /24 de la medición real


def _ip(i: int) -> str:
    return f"{RED_RUIDOSA}.{i}"


class TestGroupBySubnet:
    def test_agrupa_desde_el_minimo_de_tamano(self) -> None:
        rdb = FakeRedis()
        for i in range(5):
            create_pending_approval(_record(f"t-{i}", approval_level="N1", src_ip=_ip(i)), rdb)
        items = pending_approvals_page(rdb, group=False)["items"]

        grouped = group_by_subnet(items, prefix_len=24, min_group_size=3)

        assert len(grouped) == 1
        group = grouped[0]
        assert group["is_group"] is True
        assert group["network"] == "91.92.42.0/24"
        assert group["member_count"] == 5
        assert set(group["member_trace_ids"]) == {f"t-{i}" for i in range(5)}

    def test_bajo_el_minimo_no_agrupa(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-0", approval_level="N1", src_ip=_ip(0)), rdb)
        create_pending_approval(_record("t-1", approval_level="N1", src_ip=_ip(1)), rdb)
        items = pending_approvals_page(rdb, group=False)["items"]

        result = group_by_subnet(items, prefix_len=24, min_group_size=3)

        assert all(not r.get("is_group") for r in result)
        assert len(result) == 2

    def test_no_mezcla_niveles_de_aprobacion_distintos(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"n1-{i}", approval_level="N1", src_ip=_ip(i)), rdb)
        for i in range(3, 6):
            create_pending_approval(_record(f"n2-{i}", approval_level="N2", src_ip=_ip(i)), rdb)
        items = pending_approvals_page(rdb, group=False)["items"]

        grouped = [r for r in group_by_subnet(items, 24, 3) if r.get("is_group")]

        assert len(grouped) == 2
        levels = {g["approval_level"] for g in grouped}
        assert levels == {"N1", "N2"}
        for g in grouped:
            assert g["member_count"] == 3

    def test_redes_distintas_no_se_mezclan(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"a-{i}", approval_level="N1", src_ip=_ip(i)), rdb)
        for i in range(3):
            create_pending_approval(
                _record(f"b-{i}", approval_level="N1", src_ip=f"100.29.192.{i}"), rdb,
            )
        items = pending_approvals_page(rdb, group=False)["items"]

        grouped = [r for r in group_by_subnet(items, 24, 3) if r.get("is_group")]

        assert len(grouped) == 2
        assert {g["network"] for g in grouped} == {"91.92.42.0/24", "100.29.192.0/24"}

    def test_ip_no_parseable_pasa_sin_agrupar(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"t-{i}", approval_level="N1", src_ip=_ip(i)), rdb)
        create_pending_approval(_record("t-raro", approval_level="N1", src_ip="no-es-una-ip"), rdb)
        items = pending_approvals_page(rdb, group=False)["items"]

        result = group_by_subnet(items, 24, 3)

        raro = [r for r in result if r.get("trace_id") == "t-raro"]
        assert len(raro) == 1
        assert raro[0]["is_group"] is False

    def test_occurrences_suma_tier_y_riesgo_toman_el_maximo(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"t-{i}", approval_level="N1", src_ip=_ip(i)), rdb)
        # repite t-0 para que sume ocurrencias antes de agrupar
        create_pending_approval(_record("t-0-bis", approval_level="N1", src_ip=_ip(0)), rdb)
        items = pending_approvals_page(rdb, group=False)["items"]

        grouped = group_by_subnet(items, 24, 3)

        assert len(grouped) == 1
        assert grouped[0]["occurrences"] == 4  # 2 (t-0 dedup por IP) + 1 + 1
        assert grouped[0]["tier"] == 3
        assert grouped[0]["risk_score"] == 0.93


class TestResolveApprovalGroup:
    def test_resuelve_cada_miembro_individualmente(self) -> None:
        rdb = FakeRedis()
        for i in range(3):
            create_pending_approval(_record(f"t-{i}", approval_level="N1", src_ip=_ip(i)), rdb)

        out = resolve_approval_group(["t-0", "t-1", "t-2"], "n1-op", "rejected", rdb)

        assert out["resolved"] == ["t-0", "t-1", "t-2"]
        assert out["already_resolved"] == []
        assert out["missing"] == []
        items = pending_approvals_page(rdb, group=False)["items"]
        assert items == []

    def test_no_se_cae_si_uno_ya_fue_resuelto_o_no_existe(self) -> None:
        rdb = FakeRedis()
        create_pending_approval(_record("t-0", approval_level="N1", src_ip=_ip(0)), rdb)
        create_pending_approval(_record("t-1", approval_level="N1", src_ip=_ip(1)), rdb)
        resolve_approval_group(["t-0"], "n1-op", "approved", rdb)  # ya resuelto antes

        out = resolve_approval_group(["t-0", "t-1", "t-no-existe"], "n1-op", "rejected", rdb)

        assert out["resolved"] == ["t-1"]
        assert out["already_resolved"] == ["t-0"]
        assert out["missing"] == ["t-no-existe"]


class TestPendingApprovalsPageConGrupo:
    def test_total_sigue_siendo_la_cuenta_real_no_la_de_items_agrupados(self) -> None:
        rdb = FakeRedis()
        for i in range(5):
            create_pending_approval(_record(f"t-{i}", approval_level="N1", src_ip=_ip(i)), rdb)

        page = pending_approvals_page(rdb, group=True, group_min_size=3)

        assert page["total"] == 5          # IPs reales
        assert len(page["items"]) == 1     # un solo ítem de grupo en pantalla
        assert page["items"][0]["is_group"] is True
