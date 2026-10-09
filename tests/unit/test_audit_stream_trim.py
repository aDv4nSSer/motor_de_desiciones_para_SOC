"""
H57 (ítem 1.3): el indexador recorta del stream soc:response:audit solo lo que
el grupo ya confirmó (XTRIM MINID). Antes el único recorte era el maxlen del
XADD del worker, que descarta lo más viejo aunque no esté indexado.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import pytest
from response_audit_indexer import GROUP, STREAM, IndexingError, ResponseAuditIndexer

from tests.unit.test_response_audit_indexer import (
    FakeOpenSearch,
    FakeStreamRedis,
    _event,
    _settings,
)


def _ix(rdb, osc, interval=0.0, min_age=0.0):
    s = _settings()
    s.trim_interval_seconds = interval
    s.trim_min_age_seconds = min_age
    ix = ResponseAuditIndexer(rdb, osc, s)
    ix.start()
    return ix


def test_recorta_lo_confirmado_y_conserva_lo_no_entregado() -> None:
    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    for i in range(10):
        rdb.xadd(STREAM, _event(i))
    ix = _ix(rdb, osc)
    for _ in range(5):
        ix.run_once()
    assert len(rdb.streams[STREAM]) == 1  # solo el último confirmado (MINID lo conserva)
    for i in range(10, 13):
        rdb.xadd(STREAM, _event(i))  # llegan después: no entregados todavía
    ix.trim_acked(now=10**9)
    assert len(rdb.streams[STREAM]) == 4
    assert sum(len(d) for d in osc.indices.values()) == 10


def test_nunca_pasa_el_pendiente_mas_viejo_del_grupo() -> None:
    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    for i in range(6):
        rdb.xadd(STREAM, _event(i))
    ix = _ix(rdb, osc)
    osc.fail_next = 1
    ix._pending_first = False
    with pytest.raises(IndexingError):
        ix.run_once()  # el primero falla: queda pendiente, el lote se corta
    pend = rdb.xpending(STREAM, GROUP)
    assert pend["pending"] >= 1
    ix._last_acked = rdb.streams[STREAM][-1][0]  # aunque haya un acked más nuevo
    ix.trim_acked(now=10**9)
    kept = {m for m, _ in rdb.streams[STREAM]}
    assert pend["min"] in kept  # el pendiente sigue en el stream


def test_respeta_el_intervalo() -> None:
    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    for i in range(3):
        rdb.xadd(STREAM, _event(i))
    ix = _ix(rdb, osc, interval=30.0)
    ix.run_once()
    ix.run_once()
    assert ix.trim_acked(now=ix._last_trim + 5) is None
    assert ix.trim_acked(now=ix._last_trim + 31) is not None


def test_sin_nada_confirmado_no_recorta() -> None:
    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    rdb.xadd(STREAM, _event(0))
    ix = _ix(rdb, osc)
    assert ix.trim_acked(now=10**9) is None
    assert len(rdb.streams[STREAM]) == 1


def test_el_colchon_minimo_nunca_se_recorta(monkeypatch) -> None:
    """Con 48 h de colchón y entradas de la última hora, no se recorta nada;
    49 h después, sí (hasta lo confirmado)."""
    import response_audit_indexer as rai

    rdb, osc = FakeStreamRedis(), FakeOpenSearch()
    for i in range(10):
        rdb.xadd(STREAM, _event(i))  # ids en ms ~1.790.000.000.000
    newest_s = int(rdb.streams[STREAM][-1][0].split("-")[0]) / 1000
    monkeypatch.setattr(rai.time, "time", lambda: newest_s + 3600)
    ix = _ix(rdb, osc, min_age=48 * 3600)
    for _ in range(5):
        ix.run_once()
    assert len(rdb.streams[STREAM]) == 10  # todo dentro del colchón
    ix._last_trim = 0
    ix.trim_acked(now=newest_s + 49 * 3600)
    assert len(rdb.streams[STREAM]) == 1
