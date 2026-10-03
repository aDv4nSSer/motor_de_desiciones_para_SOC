"""
H42 (corrige H40): indexador de soc-decisions con el patrón de soc-responses.

Cubre los defectos de la versión anterior y el corte de cadena:
- Contenido alterado rompe la cadena (antes solo 4 campos estaban cubiertos).
- Un fallo de indexación no hace XACK (antes sí: la decisión se perdía).
- Un reproceso da 409 y no sobrescribe (antes POST _doc aceptaba "updated").
- La cabeza viene de OpenSearch: un reinicio no bifurca la cadena.
- Corte: la cadena nueva se ancla al último hash de la cadena vieja y lo
  deja escrito, dentro del hash, en el primer documento.
- Pendientes heredados: los ya recortados del stream se confirman y cuentan;
  los vivos que ya están en el índice legado no se duplican.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import opensearch_indexer as osi
from opensearch_indexer import (
    GROUP,
    INDEX_PATTERN,
    LEGACY_INDEX,
    STREAM,
    DecisionsIndexer,
    DecisionsIndexerSettings,
    DecisionsOpenSearchClient,
    find_legacy_head,
    index_name_for,
    parse_decision,
    read_legacy_state,
)
from response_audit_indexer import (
    GENESIS_HASH,
    IndexingError,
    bootstrap_until_ready,
    verify_chain,
)
from test_response_audit_indexer import FakeStreamRedis


def legacy_hash(prev_hash: str, doc: dict) -> str:
    """Fórmula de la versión anterior (H40), copiada tal cual para comparar:
    solo trace_id + timestamp + tier + risk_score."""
    raw = prev_hash + doc.get("trace_id", "") + doc.get("timestamp", "") + str(doc.get("tier", "")) + str(doc.get("risk_score", ""))
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Fakes ─────────────────────────────────────────────────────────────────────

class TrimmingStreamRedis(FakeStreamRedis):
    """Como Redis real: un pendiente cuyo mensaje se recortó del stream (maxlen)
    sigue en la PEL y XREADGROUP con '0' lo devuelve con campos None."""

    def trim(self, stream: str, keep_last: int) -> None:
        self.streams[stream] = self.streams[stream][-keep_last:] if keep_last else []

    def xreadgroup(self, group, consumer, streams, count=None, block=None):
        (stream, start), = streams.items()
        if start != "0":
            return super().xreadgroup(group, consumer, streams, count, block)
        self.calls.append(("xreadgroup", stream))
        pel = self.groups[(stream, group)]["pel"]
        alive = dict(self.streams.get(stream, []))
        ids = sorted((m for m, c in pel.items() if c == consumer), key=lambda m: tuple(map(int, m.split("-"))))
        return [[stream, [(m, alive.get(m)) for m in ids[:count]]]]


def _xpending(self, stream, group):
    pel = self.groups.get((stream, group), {}).get("pel", {})
    ids = sorted(pel, key=lambda m: tuple(map(int, m.split("-"))))
    return {"pending": len(ids), "min": ids[0] if ids else None, "max": ids[-1] if ids else None}


def _xrange(self, stream, count=None):
    return self.streams.get(stream, [])[:count]


TrimmingStreamRedis.xpending = _xpending
TrimmingStreamRedis.xrange = _xrange


class FakeDecisionsOS:
    def __init__(self, legacy: list[dict] | None = None):
        self.daily: dict[str, dict[str, dict]] = {}
        self.legacy: list[dict] = legacy or []
        self.fail_next = 0
        self.writes: list[tuple[str, str]] = []

    # cadena nueva
    def create(self, index, doc_id, doc):
        if self.fail_next:
            self.fail_next -= 1
            raise IndexingError("HTTP 503")
        self.writes.append((index, doc_id))
        idx = self.daily.setdefault(index, {})
        if doc_id in idx:
            return "exists"
        idx[doc_id] = json.loads(json.dumps(doc))
        return "created"

    def get_source(self, index, doc_id):
        return self.daily.get(index, {}).get(doc_id)

    def chain_head(self):
        docs = self.docs()
        return (docs[-1]["chain_seq"], docs[-1]["hash"]) if docs else (0, GENESIS_HASH)

    def docs(self) -> list[dict]:
        return sorted((d for i in self.daily.values() for d in i.values()), key=lambda d: d["chain_seq"])

    # índice legado (solo lectura)
    def legacy_exists(self, trace_id):
        return any(d["trace_id"] == trace_id for d in self.legacy)

    def legacy_count(self):
        return len(self.legacy)

    def legacy_search(self, query, size=10, sort=None):
        if "term" in query:
            (field, value), = query["term"].items()
            hits = [d for d in self.legacy if d.get(field) == value]
        else:
            hits = list(self.legacy)
        if sort:
            hits.sort(key=lambda d: d["timestamp"], reverse=True)
        return hits[:size]


def build_legacy_chain(n: int, start_hash: str = "genesis") -> list[dict]:
    docs, prev = [], start_hash
    for i in range(n):
        d = {"trace_id": f"old-{i}", "timestamp": f"2026-10-03T05:00:{i:02d}+00:00", "tier": 1, "risk_score": 0.2}
        h = legacy_hash(prev, d)
        docs.append({**d, "prev_hash": prev, "hash": h})
        prev = h
    return docs


def _settings(tmp_path: Path, state_hash: str | None = None) -> DecisionsIndexerSettings:
    state = tmp_path / "state.json"
    if state_hash is not None:
        state.write_text(json.dumps({"last_hash": state_hash}))
    return DecisionsIndexerSettings(batch_size=10, block_ms=1, redis_password="x", os_pass="x",
                                    legacy_state_file=str(state))


def _decision(i: int) -> dict:
    return {"trace_id": f"t-{i}", "timestamp": f"2026-10-03T06:00:{i:02d}+00:00", "tier": "3", "risk_score": "0.91",
            "ml_score": "0.88", "anomaly_score": "0.4", "decision": "BLOCK", "L4_DST_PORT": "22",
            "OUT_PKTS": "3", "DURATION_MS": "12", "SERVER_FLAGS": "18", "model_version": "golden4_v7_1",
            "latency_ms": "4.2"}


def _indexer(rdb, osc, settings) -> DecisionsIndexer:
    ix = DecisionsIndexer(rdb, osc, settings)
    ix.start()
    return ix


def _drain(ix: DecisionsIndexer, rounds: int = 30) -> None:
    for _ in range(rounds):
        ix.run_once()


# ── 1. Contenido completo en el hash ──────────────────────────────────────────

class TestHashSobreContenidoCompleto:
    @pytest.mark.parametrize("campo,valor", [("decision", "ALLOW"), ("ml_score", 0.01),
                                              ("L4_DST_PORT", 443), ("model_version", "otro")])
    def test_alterar_un_campo_fuera_de_los_4_rompe_la_cadena_nueva_y_no_la_vieja(self, tmp_path, campo, valor) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        for i in range(3):
            rdb.xadd(STREAM, _decision(i))
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        docs = osc.docs()
        before_old = legacy_hash(docs[1]["prev_hash"], docs[1])
        docs[1][campo] = valor
        assert legacy_hash(docs[1]["prev_hash"], docs[1]) == before_old  # la fórmula vieja no lo ve
        assert any("alterado" in p for p in verify_chain(docs))      # la nueva sí

    def test_cadena_nueva_continua(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        for i in range(5):
            rdb.xadd(STREAM, _decision(i))
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        docs = osc.docs()
        assert [d["chain_seq"] for d in docs] == [1, 2, 3, 4, 5]
        assert verify_chain(docs) == []


# ── 2. Sin XACK si no persistió ───────────────────────────────────────────────

class TestXackSoloTrasPersistir:
    def test_fallo_de_indexacion_no_hace_xack(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        for i in range(3):
            rdb.xadd(STREAM, _decision(i))
        ix = _indexer(rdb, osc, _settings(tmp_path))
        ix.run_once()  # pendientes heredados: ninguno
        osc.fail_next = 1
        with pytest.raises(IndexingError):
            ix.run_once()
        assert osc.docs() == []
        assert rdb.pending(STREAM, GROUP) == 3

    def test_despues_del_fallo_se_reintenta_en_orden(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        for i in range(3):
            rdb.xadd(STREAM, _decision(i))
        ix = _indexer(rdb, osc, _settings(tmp_path))
        ix.run_once()
        osc.fail_next = 1
        with pytest.raises(IndexingError):
            ix.run_once()
        _drain(ix)
        assert [d["trace_id"] for d in osc.docs()] == ["t-0", "t-1", "t-2"]
        assert rdb.pending(STREAM, GROUP) == 0


# ── 3. Append-only: 409 sin sobrescribir ──────────────────────────────────────

class TestAppendOnly:
    def test_reproceso_da_409_y_no_sobrescribe(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        msg_id = rdb.xadd(STREAM, _decision(0))
        ix = _indexer(rdb, osc, _settings(tmp_path))
        _drain(ix)
        original = json.dumps(osc.docs()[0], sort_keys=True)
        altered = {**_decision(0), "decision": "ALLOW"}  # mismo mensaje, contenido distinto
        assert ix.process(msg_id, altered) == "exists"
        assert json.dumps(osc.docs()[0], sort_keys=True) == original
        assert len(osc.docs()) == 1 and ix.seq == 1

    def test_escribe_con_create_por_id_de_mensaje(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        msg_id = rdb.xadd(STREAM, _decision(0))
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        assert osc.writes == [(index_name_for(msg_id), msg_id)]


# ── 4. Reinicio sin bifurcación ───────────────────────────────────────────────

class TestReinicio:
    def test_cabeza_desde_opensearch_no_desde_archivo(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        for i in range(4):
            rdb.xadd(STREAM, _decision(i))
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        for i in range(4, 7):
            rdb.xadd(STREAM, _decision(i))
        # "reinicio" con un archivo de estado viejo y equivocado: se ignora
        ix2 = _indexer(rdb, osc, _settings(tmp_path, state_hash="hash-viejo-que-no-importa"))
        assert ix2.seq == 4
        _drain(ix2)
        docs = osc.docs()
        assert [d["chain_seq"] for d in docs] == list(range(1, 8))
        assert len({d["prev_hash"] for d in docs}) == 7  # ningún prev_hash repetido = sin bifurcación
        assert verify_chain(docs) == []

    def test_fallo_antes_del_primer_documento_conserva_el_ancla(self, tmp_path) -> None:
        legacy = build_legacy_chain(3)
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        rdb.xadd(STREAM, _decision(0))
        ix = _indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[-1]["hash"]))
        ix.resync_head()  # como tras un error de red antes de escribir nada
        assert ix.head_hash == legacy[-1]["hash"]


# ── 5. Corte de la cadena vieja a la nueva ────────────────────────────────────

class TestCorteDeCadena:
    def test_primer_documento_se_ancla_a_la_cabeza_real_de_la_vieja(self, tmp_path) -> None:
        legacy = build_legacy_chain(10)
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        for i in range(2):
            rdb.xadd(STREAM, _decision(i))
        # el archivo de estado quedó 3 documentos atrás (se guardaba cada 100)
        ix = _indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[6]["hash"]))
        _drain(ix)
        first = osc.docs()[0]
        assert first["chain_seq"] == 1
        assert first["prev_hash"] == legacy[-1]["hash"]
        c = first["chain_cutover"]
        assert c["legacy_head_hash"] == legacy[-1]["hash"] and c["legacy_head_trace_id"] == "old-9"
        assert c["legacy_state_file_hash"] == legacy[6]["hash"]
        assert (c["walk_steps"], c["forks_seen"], c["legacy_doc_count"]) == (3, 0, 10)
        assert c["method"] == "forward_walk_from_state_file"
        assert "chain_cutover" not in osc.docs()[1]
        assert verify_chain(osc.docs()) == []

    def test_el_corte_queda_dentro_del_hash(self, tmp_path) -> None:
        legacy = build_legacy_chain(3)
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        rdb.xadd(STREAM, _decision(0))
        _drain(_indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[-1]["hash"])))
        docs = osc.docs()
        docs[0]["chain_cutover"]["legacy_head_hash"] = "otro"
        assert verify_chain(docs) != []

    def test_bifurcacion_en_la_vieja_se_cuenta_y_sigue_la_rama_mas_reciente(self, tmp_path) -> None:
        legacy = build_legacy_chain(4)
        fork = {"trace_id": "fork", "timestamp": "2026-10-03T04:59:59+00:00", "tier": 1, "risk_score": 0.1,
                "prev_hash": legacy[1]["hash"], "hash": "hash-de-la-rama-vieja"}
        osc = FakeDecisionsOS(legacy + [fork])
        anchor = find_legacy_head(osc, legacy[1]["hash"])
        assert anchor["forks_seen"] == 1
        assert anchor["legacy_head_hash"] == legacy[-1]["hash"]

    def test_sin_archivo_de_estado_usa_el_timestamp_mas_reciente(self, tmp_path) -> None:
        legacy = build_legacy_chain(5)
        anchor = find_legacy_head(FakeDecisionsOS(legacy), None)
        assert anchor["method"] == "latest_timestamp_fallback"
        assert anchor["legacy_head_hash"] == legacy[-1]["hash"]

    def test_sin_cadena_vieja_parte_de_genesis(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS([])
        rdb.xadd(STREAM, _decision(0))
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        assert osc.docs()[0]["prev_hash"] == GENESIS_HASH

    def test_el_corte_solo_ocurre_con_la_cadena_nueva_vacia(self, tmp_path) -> None:
        legacy = build_legacy_chain(3)
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        rdb.xadd(STREAM, _decision(0))
        _drain(_indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[-1]["hash"])))
        rdb.xadd(STREAM, _decision(1))
        ix2 = _indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[-1]["hash"]))
        assert ix2.cutover is None
        _drain(ix2)
        assert sum(1 for d in osc.docs() if "chain_cutover" in d) == 1


# ── 6. Pendientes heredados de la versión anterior ────────────────────────────

class TestPendientesHeredados:
    def test_el_corte_registra_los_pendientes_heredados(self, tmp_path) -> None:
        legacy = build_legacy_chain(2)
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        rdb.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        for i in range(4):
            rdb.xadd(STREAM, _decision(i))
        rdb.xreadgroup(GROUP, "worker-1", {STREAM: ">"}, count=3)  # 3 entregados sin XACK
        rdb.trim(STREAM, keep_last=2)                               # 2 de ellos ya recortados
        ix = _indexer(rdb, osc, _settings(tmp_path, state_hash=legacy[-1]["hash"]))
        inh = ix.cutover["inherited_pending"]
        assert inh["count"] == 3 and inh["oldest_alive_stream_id"] == rdb.streams[STREAM][0][0]
        _drain(ix)
        assert osc.docs()[0]["chain_cutover"]["inherited_pending"]["count"] == 3
        assert ix.stats["trimmed"] == 2

    def test_recortados_del_stream_se_confirman_y_cuentan(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        rdb.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        for i in range(5):
            rdb.xadd(STREAM, _decision(i))
        rdb.xreadgroup(GROUP, "worker-1", {STREAM: ">"}, count=5)  # la versión vieja los recibió
        rdb.trim(STREAM, keep_last=0)                               # y el stream los recortó
        ix = _indexer(rdb, osc, _settings(tmp_path))
        _drain(ix)
        assert ix.stats["trimmed"] == 5
        assert osc.docs() == []
        assert rdb.pending(STREAM, GROUP) == 0

    def test_vivo_ya_indexado_en_el_legado_no_se_duplica(self, tmp_path) -> None:
        legacy = build_legacy_chain(2)
        legacy.append({"trace_id": "t-0", "timestamp": "x", "tier": 3, "risk_score": 0.9,
                       "prev_hash": legacy[-1]["hash"], "hash": "h-t0"})
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS(legacy)
        rdb.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        rdb.xadd(STREAM, _decision(0))
        rdb.xadd(STREAM, _decision(1))
        rdb.xreadgroup(GROUP, "worker-1", {STREAM: ">"}, count=2)  # entregados, sin XACK
        ix = _indexer(rdb, osc, _settings(tmp_path, state_hash="h-t0"))
        _drain(ix)
        assert ix.stats["already_in_legacy"] == 1
        assert [d["trace_id"] for d in osc.docs()] == ["t-1"]
        assert rdb.pending(STREAM, GROUP) == 0


# ── 7. Estado legado sin `except: pass` ───────────────────────────────────────

class TestEstadoLegado:
    def test_archivo_inexistente_se_loguea(self, tmp_path, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="opensearch_indexer"):
            assert read_legacy_state(str(tmp_path / "no.json")) is None
        assert "no encontrado" in caplog.text

    def test_json_corrupto_se_loguea_con_su_causa(self, tmp_path, caplog) -> None:
        p = tmp_path / "s.json"
        p.write_text("{roto")
        with caplog.at_level(logging.WARNING, logger="opensearch_indexer"):
            assert read_legacy_state(str(p)) is None
        assert "JSONDecodeError" in caplog.text

    def test_valor_valido(self, tmp_path) -> None:
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"last_hash": "abc"}))
        assert read_legacy_state(str(p)) == "abc"


# ── 8. Documento, índice y retención ──────────────────────────────────────────

class TestDocumentoEIndice:
    def test_valores_no_convertibles_se_persisten_como_unparseable(self, tmp_path) -> None:
        rdb, osc = TrimmingStreamRedis(), FakeDecisionsOS()
        rdb.xadd(STREAM, {**_decision(0), "tier": "nan?"})
        _drain(_indexer(rdb, osc, _settings(tmp_path)))
        doc = osc.docs()[0]
        assert doc["doc_type"] == "unparseable" and doc["raw"]["tier"] == "nan?"
        assert rdb.pending(STREAM, GROUP) == 0

    def test_timestamp_por_defecto_es_deterministico(self) -> None:
        d = {k: v for k, v in _decision(0).items() if k != "timestamp"}
        assert parse_decision("1790000000000-0", d)["timestamp"] == parse_decision("1790000000000-0", d)["timestamp"]

    def test_el_patron_ism_no_alcanza_al_indice_legado(self) -> None:
        assert not fnmatch.fnmatch(LEGACY_INDEX, INDEX_PATTERN)
        assert fnmatch.fnmatch(index_name_for("1790000000000-0"), INDEX_PATTERN)
        assert osi.ism_policy(90)["policy"]["ism_template"][0]["index_patterns"] == [INDEX_PATTERN]

    def test_mapping_con_los_mismos_tipos_que_el_legado(self) -> None:
        legacy_types = {"DURATION_MS": "long", "L4_DST_PORT": "integer", "OUT_PKTS": "integer",
                        "SERVER_FLAGS": "integer", "anomaly_score": "float", "decision": "keyword",
                        "hash": "keyword", "latency_ms": "float", "ml_score": "float",
                        "model_version": "keyword", "prev_hash": "keyword", "risk_score": "float",
                        "tier": "integer", "tier_name": "keyword", "timestamp": "date", "trace_id": "keyword"}
        props = osi.INDEX_MAPPINGS["properties"]
        assert {k: props[k]["type"] for k in legacy_types} == legacy_types

    def test_dashboard_lee_legado_y_cadena_nueva(self) -> None:
        source = (Path(osi.__file__).parent / "dashboard.py").read_text()
        assert 'OS_INDEX = "soc-decisions,soc-decisions-*"' in source


# ── 9. Bootstrap idempotente con reintentos (patrón H41) ──────────────────────

class TestBootstrap:
    def test_put_de_politica_con_timeout_se_recupera(self, tmp_path) -> None:
        state = {"policy": False}

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/_index_template/soc-decisions":
                return httpx.Response(200, json={})
            if req.url.path == "/_plugins/_ism/policies/soc-decisions-retention":
                if req.method == "GET":
                    return httpx.Response(200 if state["policy"] else 404, json={})
                state["policy"] = True
                raise httpx.ReadTimeout("timeout", request=req)
            return httpx.Response(500, json={})

        client = DecisionsOpenSearchClient(_settings(tmp_path), transport=httpx.MockTransport(handler))
        sleeps: list[float] = []

        class NoStart:
            def start(self):
                pass
        assert bootstrap_until_ready(client, NoStart(), _settings(tmp_path), sleep=sleeps.append, max_rounds=1)
        assert state["policy"] is True and sleeps == [1.0]


# ── 10. Verificador de la cadena vieja (streaming, memoria acotada) ──────────

class TestVerificadorLegado:
    def _stats(self, docs, window=1000):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
        import verify_decisions_legacy_chain as v
        st = v.ChainStats(window)
        for d in docs:
            st.add(d)
        return st

    def test_cadena_sana(self) -> None:
        st = self._stats(build_legacy_chain(50))
        assert (len(st.bad), st.gaps, len(st.forks)) == (0, 0, 0)

    def test_detecta_alteracion_hueco_y_bifurcacion(self) -> None:
        docs = build_legacy_chain(10)
        docs[3]["tier"] = 3                       # contenido alterado
        del docs[6]                               # documento perdido -> hueco
        fork = {"trace_id": "fork", "timestamp": "2026-10-03T05:00:08.5+00:00", "tier": 1, "risk_score": 0.2,
                "prev_hash": docs[7]["prev_hash"]}
        fork["hash"] = legacy_hash(fork["prev_hash"], fork)
        docs.insert(8, fork)                      # segundo hijo del mismo padre
        st = self._stats(docs)
        assert len(st.bad) == 1 and st.bad[0]["trace_id"] == "old-3"
        assert st.gaps == 1
        assert len(st.forks) == 1 and st.forks[0]["child_trace_id"] == "fork"

    def test_memoria_acotada_a_la_ventana(self) -> None:
        st = self._stats(build_legacy_chain(500), window=50)
        assert len(st.recent) == 50 and len(st.children) <= 51
