"""
opensearch_indexer.py — Indexador con hash-chain de soc:decisions (H42, corrige H40).

Consume las decisiones del Fast Path desde el stream Redis `soc:decisions`
(consumer group "opensearch-indexer") y las persiste en índices diarios
`soc-decisions-YYYY.MM.DD`, append-only y encadenados con el mismo patrón
que soc-responses (H39/H41):

    hash = sha256(canonical_json(contenido completo + chain_seq) + prev_hash)

Corrige los defectos de la versión anterior (H40):
1. El hash cubría solo trace_id/timestamp/tier/risk_score: ahora cubre el
   contenido completo.
2. Hacía XACK aunque la indexación fallara: ahora XACK solo tras confirmar
   la creación del documento.
3. La cabeza de la cadena venía de un archivo local guardado cada 100
   documentos (un reinicio bifurcaba la cadena): ahora se lee de OpenSearch.
4. POST _doc/{trace_id} aceptaba "updated" (sobrescritura): ahora _create,
   y un reproceso recibe 409 sin reescribir (append-only, prohibición #6).
5. `except: pass` desnudo al leer el estado: ya no hay archivo de estado en
   el camino normal; la lectura del estado viejo (solo para el corte) loguea
   cada error concreto.
Además: bootstrap idempotente con reintentos (template, política ISM de 90
días, consumer group + cabeza de la cadena) y pendientes reprocesados al
arrancar.

Corte de cadena (H42): el índice legado `soc-decisions` (cadena vieja, hash
de 4 campos) NO se toca ni se recalcula. La primera decisión de la cadena
nueva lleva `prev_hash` = último hash de la cadena vieja y un objeto
`chain_cutover` (dentro del hash) con los datos del corte. Ese índice legado
tampoco recibe la política ISM: tiene más de 90 días y ISM lo borraría entero.

Ejecutar (unit opensearch-indexer.service, sin cambios):
    python3 opensearch_indexer.py
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import redis
from attck_mapping import ATTACK_FIELDS
from response_audit_indexer import (
    BOOTSTRAP_RETRYABLE,
    GENESIS_HASH,
    AuditIndexerSettings,
    IndexingError,
    OpenSearchClient,
    bootstrap_until_ready,
    chain_document,
    stream_id_time,
)

log = logging.getLogger("opensearch_indexer")

STREAM = "soc:decisions"
GROUP = "opensearch-indexer"       # mismo grupo que la versión anterior: retoma donde quedó
CONSUMER = "worker-1"              # mismo consumidor: hereda sus pendientes
INDEX_PREFIX = "soc-decisions-"
INDEX_PATTERN = "soc-decisions-*"  # no incluye el índice legado "soc-decisions" (sin guion final)
LEGACY_INDEX = "soc-decisions"
TEMPLATE_NAME = "soc-decisions"
ISM_POLICY_ID = "soc-decisions-retention"
LEGACY_STATE_FILE = "/home/aiayala/tesis/motor/logs/opensearch_indexer_state.json"
LEGACY_WALK_MAX_STEPS = 5000

TIER_NAMES = {0: "T0_BENIGNO", 1: "T1_BAJO", 2: "T2_MEDIO", 3: "T3_CRITICO"}


class DecisionsIndexerSettings(AuditIndexerSettings):
    legacy_state_file: str = LEGACY_STATE_FILE


# ── Documento ─────────────────────────────────────────────────────────────────

def index_name_for(msg_id: str) -> str:
    return f"{INDEX_PREFIX}{stream_id_time(msg_id):%Y.%m.%d}"


def parse_decision(msg_id: str, msg_data: dict) -> dict:
    """Mensaje de soc:decisions -> documento (mismos campos y tipos que el
    índice legado, más stream_id). El timestamp por defecto sale del ID del
    mensaje, no del reloj: el contenido es determinístico ante un reproceso.
    Un mensaje con valores no convertibles se persiste igual como
    "unparseable" (nunca se descarta ni queda trabado en pendientes)."""
    try:
        tier = int(msg_data.get("tier", 0))
        return {
            "stream_id": msg_id,
            "doc_type": "decision",
            "trace_id": msg_data.get("trace_id", ""),
            "timestamp": msg_data.get("timestamp") or stream_id_time(msg_id).isoformat(),
            "tier": tier,
            "tier_name": TIER_NAMES.get(tier, "UNKNOWN"),
            "risk_score": float(msg_data.get("risk_score", 0)),
            "ml_score": float(msg_data.get("ml_score", 0)),
            "anomaly_score": float(msg_data.get("anomaly_score", 0)),
            "decision": msg_data.get("decision", ""),
            "L4_DST_PORT": int(msg_data.get("L4_DST_PORT", 0)),
            "OUT_PKTS": int(msg_data.get("OUT_PKTS", 0)),
            "DURATION_MS": int(msg_data.get("DURATION_MS", 0)),
            "SERVER_FLAGS": int(msg_data.get("SERVER_FLAGS", 0)),
            "model_version": msg_data.get("model_version", ""),
            "latency_ms": float(msg_data.get("latency_ms", 0)),
            # H50: "" en el stream (o clave ausente, productor anterior) ->
            # null en el documento: un keyword vacío "" sería un término
            # buscable sin significado; null queda fuera de exists/terms.
            "classtype": msg_data.get("classtype") or None,
            **{f: msg_data.get(f) or None for f in ATTACK_FIELDS},
        }
    except (TypeError, ValueError):
        return {"stream_id": msg_id, "doc_type": "unparseable",
                "timestamp": stream_id_time(msg_id).isoformat(),
                "trace_id": str(msg_data.get("trace_id", "")), "raw": dict(msg_data)}


# Mismos tipos que el mapping del índice legado (lecturas con
# "soc-decisions,soc-decisions-*" ordenan y agregan sin conflictos).
INDEX_MAPPINGS = {
    "dynamic": False,
    "properties": {
        "stream_id": {"type": "keyword"},
        "doc_type": {"type": "keyword"},
        "trace_id": {"type": "keyword"},
        "timestamp": {"type": "date"},
        "tier": {"type": "integer"},
        "tier_name": {"type": "keyword"},
        "risk_score": {"type": "float"},
        "ml_score": {"type": "float"},
        "anomaly_score": {"type": "float"},
        "decision": {"type": "keyword"},
        "L4_DST_PORT": {"type": "integer"},
        "OUT_PKTS": {"type": "integer"},
        "DURATION_MS": {"type": "long"},
        "SERVER_FLAGS": {"type": "integer"},
        "model_version": {"type": "keyword"},
        "latency_ms": {"type": "float"},
        # H50: IDs/categorías, no texto libre -> keyword. Con "dynamic": False
        # un campo nuevo solo es consultable en índices creados con este
        # template; el índice diario ya abierto se actualiza con un PUT
        # _mapping aditivo (ver H50 en BITACORA), sin tocar documentos.
        "classtype": {"type": "keyword"},
        **{f: {"type": "keyword"} for f in ATTACK_FIELDS},
        "chain_seq": {"type": "long"},
        "prev_hash": {"type": "keyword"},
        "hash": {"type": "keyword"},
        "raw": {"type": "object", "enabled": False},
        "chain_cutover": {"type": "object", "enabled": False},
    },
}


def ism_policy(retention_days: int) -> dict:
    return {"policy": {
        "description": f"soc-decisions: borrar índices diarios con más de {retention_days} días (H42)",
        "default_state": "hot",
        "states": [
            {"name": "hot", "actions": [],
             "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{retention_days}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
        ],
        # Solo índices diarios nuevos: el patrón no matchea el legado "soc-decisions".
        "ism_template": [{"index_patterns": [INDEX_PATTERN], "priority": 100}],
    }}


# ── OpenSearch ────────────────────────────────────────────────────────────────

class DecisionsOpenSearchClient(OpenSearchClient):
    """Mismo cliente que soc-responses (timeout explícito, ver H41), con
    template/política/cabeza propios de soc-decisions."""

    def ensure_template(self) -> None:
        tpl = {"index_patterns": [INDEX_PATTERN], "priority": 100, "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0, "codec": "best_compression"},
            "mappings": INDEX_MAPPINGS}}
        r = self.request("PUT", f"/_index_template/{TEMPLATE_NAME}", tpl)
        if r.status_code >= 300:
            raise IndexingError(f"template {TEMPLATE_NAME}: HTTP {r.status_code} {r.text[:200]}")

    def ensure_policy(self, retention_days: int) -> str:
        r = self.request("GET", f"/_plugins/_ism/policies/{ISM_POLICY_ID}")
        if r.status_code == 200:
            return "exists"
        if r.status_code != 404:
            raise IndexingError(f"política ISM (GET): HTTP {r.status_code} {r.text[:200]}")
        r = self.request("PUT", f"/_plugins/_ism/policies/{ISM_POLICY_ID}", ism_policy(retention_days))
        if r.status_code == 409:
            return "exists"
        if r.status_code >= 300:
            raise IndexingError(f"política ISM (PUT): HTTP {r.status_code} {r.text[:200]}")
        log.info(f"política ISM {ISM_POLICY_ID} creada ({retention_days} días)")
        return "created"

    def chain_head(self) -> tuple[int, str]:
        r = self.request("POST", f"/{INDEX_PATTERN}/_search", {
            "size": 1, "sort": [{"chain_seq": "desc"}], "_source": ["chain_seq", "hash"]})
        if r.status_code == 404:
            return 0, GENESIS_HASH
        if r.status_code >= 300:
            raise IndexingError(f"no se pudo leer la cabeza de la cadena: HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return 0, GENESIS_HASH
        return int(hits[0]["_source"]["chain_seq"]), hits[0]["_source"]["hash"]

    def legacy_exists(self, trace_id: str) -> bool:
        r = self.request("GET", f"/{LEGACY_INDEX}/_doc/{trace_id}")
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        raise IndexingError(f"{LEGACY_INDEX}/{trace_id}: HTTP {r.status_code}")

    def legacy_search(self, query: dict, size: int = 10, sort: list | None = None) -> list[dict]:
        body: dict[str, Any] = {"size": size, "query": query,
                                "_source": ["trace_id", "timestamp", "prev_hash", "hash"]}
        if sort:
            body["sort"] = sort
        r = self.request("POST", f"/{LEGACY_INDEX}/_search", body)
        if r.status_code >= 300:
            raise IndexingError(f"{LEGACY_INDEX}/_search: HTTP {r.status_code}")
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]

    def legacy_count(self) -> int:
        r = self.request("GET", f"/{LEGACY_INDEX}/_count")
        if r.status_code >= 300:
            raise IndexingError(f"{LEGACY_INDEX}/_count: HTTP {r.status_code}")
        return int(r.json()["count"])


# ── Corte de la cadena vieja a la nueva ───────────────────────────────────────

def read_legacy_state(path: str) -> str | None:
    """last_hash del archivo de estado de la versión anterior, o None. Cada
    error se loguea por su causa concreta (reemplaza el `except: pass`)."""
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f).get("last_hash")
    except FileNotFoundError:
        log.warning(f"estado de la cadena vieja no encontrado: {path}")
        return None
    except (OSError, json.JSONDecodeError, AttributeError) as e:
        log.warning(f"estado de la cadena vieja ilegible ({path}): {type(e).__name__}: {e}")
        return None
    return value if isinstance(value, str) and value else None


def find_legacy_head(client: DecisionsOpenSearchClient, state_hash: str | None,
                     max_steps: int = LEGACY_WALK_MAX_STEPS) -> dict:
    """Cabeza real de la cadena vieja. El archivo de estado se guardaba cada
    100 documentos, así que desde ese hash se camina hacia adelante (docs con
    prev_hash = hash actual) hasta el último. Si hay bifurcaciones (defecto 3)
    se sigue la rama con el documento más reciente y se cuentan. Sin archivo
    de estado, cae al documento con timestamp más reciente."""
    anchor: dict[str, Any] = {
        "reason": "H40/H42: cadena vieja con hash de 4 campos; no se recalcula, se corta y se ancla",
        "legacy_index": LEGACY_INDEX,
        "legacy_doc_count": client.legacy_count(),
        "legacy_state_file_hash": state_hash,
        "walk_steps": 0,
        "forks_seen": 0,
        "cutover_at": datetime.now(timezone.utc).isoformat(),
    }
    head: dict | None = None
    if state_hash:
        found = client.legacy_search({"term": {"hash": state_hash}}, size=1)
        if found:
            head = found[0]
            anchor["method"] = "forward_walk_from_state_file"
            for _ in range(max_steps):
                successors = client.legacy_search({"term": {"prev_hash": head["hash"]}}, size=10,
                                                  sort=[{"timestamp": "desc"}])
                if not successors:
                    break
                if len(successors) > 1:
                    anchor["forks_seen"] += 1
                head = successors[0]
                anchor["walk_steps"] += 1
            else:
                anchor["walk_truncated"] = True
    if head is None:
        latest = client.legacy_search({"match_all": {}}, size=1, sort=[{"timestamp": "desc"}])
        head = latest[0] if latest else None
        anchor["method"] = "latest_timestamp_fallback"
    if head:
        anchor.update(legacy_head_hash=head["hash"], legacy_head_trace_id=head.get("trace_id"),
                      legacy_head_timestamp=head.get("timestamp"))
    return anchor


# ── Consumidor ────────────────────────────────────────────────────────────────

class DecisionsIndexer:
    def __init__(self, rdb: redis.Redis, os_client: Any, settings: DecisionsIndexerSettings):
        self.rdb, self.os, self.s = rdb, os_client, settings
        self.seq, self.head_hash = 0, GENESIS_HASH
        self.cutover: dict | None = None
        self._pending_first = True
        self.stats = {"created": 0, "exists": 0, "trimmed": 0, "already_in_legacy": 0}

    def start(self) -> None:
        try:
            self.rdb.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
            log.info(f"consumer group {GROUP} creado sobre {STREAM}")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        self.seq, self.head_hash = self.os.chain_head()
        if self.seq == 0:
            # Cadena nueva vacía: se ancla a la cabeza de la cadena vieja.
            self.cutover = find_legacy_head(self.os, read_legacy_state(self.s.legacy_state_file))
            self.cutover["inherited_pending"] = self._inherited_pending()
            self.head_hash = self.cutover.get("legacy_head_hash") or GENESIS_HASH
            log.info("corte de cadena preparado: " + json.dumps(self.cutover, ensure_ascii=False))
        log.info(f"cabeza de la cadena: chain_seq={self.seq} hash={self.head_hash[:16]}")

    def _inherited_pending(self) -> dict:
        """Pendientes que deja la versión anterior (entregados, nunca
        confirmados). Los que el stream ya recortó son pérdidas irrecuperables:
        quedan registradas en el corte, dentro del hash."""
        summary = self.rdb.xpending(STREAM, GROUP)
        count = int(summary.get("pending", 0)) if summary else 0
        if not count:
            return {"count": 0}
        first = self.rdb.xrange(STREAM, count=1)
        oldest_alive = first[0][0] if first else None
        return {"count": count, "oldest_id": summary.get("min"), "newest_id": summary.get("max"),
                "oldest_alive_stream_id": oldest_alive}

    def process(self, msg_id: str, fields: dict | None) -> str:
        """Persiste un mensaje y recién entonces hace XACK."""
        if not fields:
            # Entrada pendiente que el stream ya recortó (maxlen ~10k): no hay
            # contenido que persistir. Se confirma y se cuenta.
            self.rdb.xack(STREAM, GROUP, msg_id)
            self.stats["trimmed"] += 1
            return "trimmed"
        if self._pending_first and fields.get("trace_id") and self.os.legacy_exists(fields["trace_id"]):
            # Pendiente heredado de la versión anterior que sí llegó al índice
            # legado (cayó antes del XACK): ya está en la cadena vieja.
            self.rdb.xack(STREAM, GROUP, msg_id)
            self.stats["already_in_legacy"] += 1
            return "already_in_legacy"
        content = parse_decision(msg_id, fields)
        if self.seq == 0 and self.cutover is not None:
            content["chain_cutover"] = self.cutover
        doc = chain_document(content, self.seq + 1, self.head_hash)
        outcome = self.os.create(index_name_for(msg_id), msg_id, doc)
        if outcome == "created":
            self.seq, self.head_hash = doc["chain_seq"], doc["hash"]
            if doc["chain_seq"] == 1:
                log.info(f"cadena nueva iniciada en {index_name_for(msg_id)}: chain_seq=1 "
                         f"prev_hash={doc['prev_hash'][:16]} hash={doc['hash'][:16]}")
            self.cutover = None
        else:
            existing = self.os.get_source(index_name_for(msg_id), msg_id) or {}
            if int(existing.get("chain_seq", 0)) > self.seq:
                self.seq, self.head_hash = int(existing["chain_seq"]), existing["hash"]
        self.rdb.xack(STREAM, GROUP, msg_id)
        self.stats[outcome] += 1
        return outcome

    def run_once(self) -> int:
        start_id = "0" if self._pending_first else ">"
        resp = self.rdb.xreadgroup(GROUP, CONSUMER, {STREAM: start_id}, count=self.s.batch_size,
                                   block=None if self._pending_first else self.s.block_ms)
        entries = resp[0][1] if resp else []
        if self._pending_first and not entries:
            self._pending_first = False
            log.info(f"pendientes heredados procesados: {self.stats}")
            return 0
        done = 0
        for msg_id, fields in entries:
            try:
                self.process(msg_id, fields)
                done += 1
            except Exception:
                self._pending_first = True
                raise
        return done

    def run(self) -> None:
        """Loop principal. Requiere start() previo (bootstrap_until_ready)."""
        total = 0
        while True:
            try:
                n = self.run_once()
                total += n
                if n and total % 1000 < n:
                    log.info(f"procesados {total} | chain_seq={self.seq} | {self.stats}")
            except BOOTSTRAP_RETRYABLE as e:
                log.error(f"no se pudo persistir, reintento en {self.s.error_backoff_seconds}s: "
                          f"{type(e).__name__}: {e}")
                time.sleep(self.s.error_backoff_seconds)
                try:
                    self.resync_head()
                except BOOTSTRAP_RETRYABLE as e2:
                    log.error(f"cabeza de la cadena no disponible: {e2}")

    def resync_head(self) -> None:
        """Relee la cabeza desde OpenSearch (fuente de verdad). Si la cadena
        nueva sigue vacía, la cabeza es el ancla a la cadena vieja, no genesis."""
        self.seq, self.head_hash = self.os.chain_head()
        if self.seq == 0 and self.cutover is not None:
            self.head_hash = self.cutover.get("legacy_head_hash") or GENESIS_HASH


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [opensearch_indexer] %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = DecisionsIndexerSettings()
    os_client = DecisionsOpenSearchClient(s)
    rdb = redis.Redis(host=s.redis_host, port=s.redis_port, password=s.redis_password,
                      decode_responses=True, socket_timeout=(s.block_ms / 1000) + 5)
    indexer = DecisionsIndexer(rdb, os_client, s)
    bootstrap_until_ready(os_client, indexer, s)
    indexer.run()


if __name__ == "__main__":
    main()
