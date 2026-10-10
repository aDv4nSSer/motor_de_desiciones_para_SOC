"""H59: tabla ATT&CK por SID y extracción de métricas (lógica pura, sin OpenSearch)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "motor"))


def _load(rel: str):
    spec = importlib.util.spec_from_file_location(Path(rel).stem, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


attack = _load("scripts/attack/tabla_attack_por_sid.py")
metricas = _load("scripts/metrics/extraer_metricas.py")


def _bucket(sid, n, category, signature="ET X"):
    return {"key": sid, "doc_count": n, "ej": {"hits": {"hits": [{"_source": {"signature": signature, "category": category, "severity": 2}}]}},
            "desde": {"value_as_string": "2026-10-01T00:00:00Z"}, "hasta": {"value_as_string": "2026-10-09T00:00:00Z"}}


class TestTablaAttack:
    def test_mapea_por_classtype_y_ordena(self) -> None:
        rows = attack.build_rows([_bucket(1, 5, "Detection of a Network Scan"), _bucket(2, 50, "Attempted Administrator Privilege Gain")])
        assert [r["sid"] for r in rows] == [2, 1]
        assert all(r["tecnica_id"] for r in rows) and rows[0]["fuente_mapeo"].startswith("classtype_attack.yaml")

    def test_classtype_desconocido_o_ausente_se_declara(self) -> None:
        rows = attack.build_rows([_bucket(3, 1, "no existe"), _bucket(4, 1, None)])
        assert {r["fuente_mapeo"] for r in rows} == {"classtype fuera del YAML", "sin classtype"}
        assert all(r["tecnica_id"] is None for r in rows)

    def test_resumen_de_cobertura(self) -> None:
        rows = attack.build_rows([_bucket(1, 3, "Detection of a Network Scan"), _bucket(4, 1, None)])
        assert "con técnica: 1" in attack.summary(rows) and "(75.0%)" in attack.summary(rows)

    def test_agregacion_acotada(self) -> None:
        body = attack.aggregation(30, 500)
        assert body["size"] == 0 and body["aggs"]["sid"]["terms"]["size"] == 500


class TestMetricas:
    def test_tiers_por_hora(self) -> None:
        rows = metricas.tiers_por_hora([{"key_as_string": "2026-10-09T14:00:00.000Z", "doc_count": 7,
                                         "tier": {"buckets": [{"key": 3, "doc_count": 5}, {"key": 0, "doc_count": 2}]}}])
        assert rows == [{"hora_utc": "2026-10-09T14:00:00.000Z", "t0": 2, "t1": 0, "t2": 0, "t3": 5, "total": 7}]

    def test_latencia_por_dia(self) -> None:
        rows = metricas.latencia_por_dia([{"key_as_string": "2026-10-09T00:00:00.000Z", "doc_count": 3,
                                           "lat": {"values": {"50.0": 10.123, "95.0": 47.0, "99.0": None}}}])
        assert rows == [{"dia_utc": "2026-10-09", "n": 3, "p50": 10.12, "p95": 47.0, "p99": None}]

    def test_consultas_solo_agregan(self) -> None:
        for _, body in metricas.queries("2026-10-03").values():
            assert body["size"] == 0 and "h" in body["aggs"]
