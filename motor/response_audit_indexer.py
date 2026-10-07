"""
response_audit_indexer.py — Persistencia con hash-chain de soc:response:audit (H39).

Proceso SEPARADO del response-worker y del opensearch_indexer de
soc-decisions. Lee el stream Redis `soc:response:audit` con su propio
consumer group y persiste cada evento en índices diarios
`soc-responses-YYYY.MM.DD` de OpenSearch, append-only y encadenados:

    hash = sha256(canonical_json(contenido + chain_seq) + prev_hash)

Cubre todo lo que hoy solo vivía unas horas en Redis (stream capado en 100k):
ResponseRecord de R1/R2 (enriquecimiento, accion_recomendada, bloqueo u
omisión), approval_expired, aprobaciones manuales y eventos de acceso.

Garantías:
- XACK solo después de que OpenSearch confirma la creación del documento:
  si el proceso cae a mitad de lote, el mensaje queda pendiente y se
  reprocesa al reiniciar (primero los pendientes propios, después los nuevos).
- Append-only: cada documento se crea con `_create` y _id = ID del mensaje
  del stream. Un reproceso recibe 409 y se confirma sin reescribir nada.
- La cabeza de la cadena (último chain_seq + hash) se lee de OpenSearch, no
  de un archivo local: un reinicio no puede bifurcar la cadena.
- No comparte stream ni grupo con el worker (que consume soc:response:tasks):
  no hay contención con el loop de respuesta optimizado en H38.

Ejecutar como servicio systemd propio (infra/systemd/response-audit-indexer.service):
    python3 -m response_audit_indexer
"""
from __future__ import annotations

import hashlib
import json
import logging
import ssl
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx
import redis
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("response_audit_indexer")

STREAM = "soc:response:audit"
GROUP = "response-audit-indexer"
CONSUMER = "indexer-1"
INDEX_PREFIX = "soc-responses-"
INDEX_PATTERN = "soc-responses-*"
TEMPLATE_NAME = "soc-responses"
ISM_POLICY_ID = "soc-responses-retention"
GENESIS_HASH = "genesis"

# Bootstrap (template, política ISM, consumer group + cabeza de la cadena):
# 1 intento + 3 reintentos con backoff 1s/2s/4s por operación. Si una ronda
# completa falla, el proceso NO muere: espera BOOTSTRAP_ROUND_BACKOFF_SECONDS y
# repite (los mensajes esperan en el stream; no hay nada que perder).
BOOTSTRAP_BACKOFF_SECONDS = (1.0, 2.0, 4.0)
BOOTSTRAP_ROUND_BACKOFF_SECONDS = 30.0

#: Campos del contenido que se encadenan, además del payload completo.
CHAIN_FIELDS = ("chain_seq", "prev_hash", "hash")


class AuditIndexerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    os_host: str = "https://localhost:9201"
    os_user: str = "admin"
    os_pass: str = ""
    # OpenSearch en .140 usa un certificado autofirmado (mismo criterio que
    # opensearch_indexer.py y dashboard.py). Configurable para cuando haya CA.
    os_verify_tls: bool = False
    retention_days: int = 90
    batch_size: int = 100
    block_ms: int = 5000
    error_backoff_seconds: float = 5.0


class IndexingError(Exception):
    """OpenSearch no confirmó la creación: no se hace XACK."""


# ── Documento y cadena (funciones puras) ─────────────────────────────────────

def canonical_json(obj: dict) -> str:
    """Serialización determinística: misma entrada, mismos bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_hash(content: dict, prev_hash: str) -> str:
    """sha256(contenido canónico + prev_hash). `content` incluye chain_seq y
    excluye prev_hash/hash."""
    return hashlib.sha256((canonical_json(content) + prev_hash).encode("utf-8")).hexdigest()


def stream_id_time(msg_id: str) -> datetime:
    return datetime.fromtimestamp(int(msg_id.split("-")[0]) / 1000, tz=timezone.utc)


def index_name_for(msg_id: str) -> str:
    """Índice diario según la hora del mensaje (determinístico: un reproceso
    cae en el mismo índice y el _create detecta el duplicado)."""
    return f"{INDEX_PREFIX}{stream_id_time(msg_id):%Y.%m.%d}"


def build_content(msg_id: str, fields: dict[str, Any]) -> dict:
    """Documento sin los campos de cadena. Campos consultables extraídos y el
    evento completo en `payload` (guardado, no indexado: los `detail` de
    acceso son libres y romperían el mapping)."""
    raw = fields.get("data", "")
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise TypeError("payload no es un objeto")
    except (TypeError, ValueError):
        # Nunca se descarta un evento: se persiste crudo, marcado.
        return {"stream_id": msg_id, "event_time": stream_id_time(msg_id).isoformat(),
                "event_type": "unparseable", "payload": {"raw": str(raw)}}

    doc: dict[str, Any] = {"stream_id": msg_id, "event_time": stream_id_time(msg_id).isoformat()}
    if "access_event" in payload:
        doc.update(event_type="access", username=payload.get("username"),
                   access_event=payload.get("access_event"))
        detail = payload.get("detail") or {}
        if isinstance(detail, dict):
            doc["trace_id"] = detail.get("trace_id")
            doc["src_ip"] = detail.get("src_ip")
    elif payload.get("approval_expired"):
        doc.update(event_type="approval_expired", trace_id=payload.get("trace_id"),
                   src_ip=payload.get("src_ip"), status=payload.get("status"),
                   username=payload.get("resolved_by"))
    elif payload.get("manual_approval"):
        doc.update(event_type="manual_approval", trace_id=payload.get("trace_id"),
                   src_ip=payload.get("src_ip"), username=payload.get("approved_by"),
                   approver_role=payload.get("approver_role"),
                   block_enforced=payload.get("enforced"))
    elif any(k in payload for k in ("accion_recomendada", "enrichment", "block")):
        block = payload.get("block") or {}
        doc.update(event_type="response", trace_id=payload.get("trace_id"),
                   src_ip=payload.get("src_ip"), tier=payload.get("tier"),
                   risk_score=payload.get("risk_score"),
                   accion_recomendada=payload.get("accion_recomendada"),
                   block_action=block.get("action"), block_reason=block.get("reason"),
                   block_enforced=block.get("enforced"),
                   event_age_seconds=payload.get("event_age_seconds"),
                   case_id=payload.get("case_id"))
        # H52: corroboración ponderada en modo sombra + el conteo del gate
        # real, top-level para compararlos con una sola query. Solo si el
        # score se calculó (band no vacío): un 0.0 por default (tier < 2 o
        # cálculo fallido) no es un score real. Payloads anteriores no los
        # traen y quedan fuera (None se descarta abajo).
        # corroboration_groups queda solo en payload (lista con texto libre).
        if payload.get("corroboration_band"):
            doc.update(corroboration_score=payload.get("corroboration_score"),
                       corroboration_band=payload.get("corroboration_band"),
                       corroboration_ambiguous=payload.get("corroboration_ambiguous"))
        enrichment = payload.get("enrichment")
        if isinstance(enrichment, dict):
            doc["corroboration_count"] = enrichment.get("corroboration_count")
        # H53: insumos de los grupos signature/context y qué grupos estuvieron
        # disponibles, para medir su cobertura con una query. Payloads
        # anteriores no los traen (None se descarta abajo).
        groups = payload.get("corroboration_groups")
        if isinstance(groups, list) and groups:
            doc["corroboration_groups_available"] = [
                g.get("name") for g in groups if isinstance(g, dict) and g.get("available")]
        alert = payload.get("correlated_alert")
        if isinstance(alert, dict):
            doc.update(correlated_classtype=alert.get("classtype"),
                       correlated_attack_technique_id=alert.get("attack_technique_id"))
        doc.update(alert_lookup=payload.get("alert_lookup") or None,
                   recidivism_count=payload.get("recidivism_count"))
    else:
        doc["event_type"] = "other"
    doc["payload"] = payload
    return {k: v for k, v in doc.items() if v is not None}


def chain_document(content: dict, seq: int, prev_hash: str) -> dict:
    hashed = {**content, "chain_seq": seq}
    return {**hashed, "prev_hash": prev_hash, "hash": compute_hash(hashed, prev_hash)}


def verify_chain(docs: list[dict]) -> list[str]:
    """Recorre documentos ordenados por chain_seq y devuelve los problemas
    encontrados (vacío = cadena íntegra). El primero puede no partir de
    genesis si los índices más viejos ya se borraron por retención."""
    problems: list[str] = []
    prev: dict | None = None
    for d in docs:
        hashed = {k: v for k, v in d.items() if k not in ("prev_hash", "hash")}
        if compute_hash(hashed, d.get("prev_hash", "")) != d.get("hash"):
            problems.append(f"chain_seq {d.get('chain_seq')}: el hash no corresponde al contenido (alterado)")
        if prev is not None:
            if d.get("chain_seq") != prev.get("chain_seq", 0) + 1:
                problems.append(f"chain_seq {d.get('chain_seq')}: salto de secuencia desde {prev.get('chain_seq')}")
            if d.get("prev_hash") != prev.get("hash"):
                problems.append(f"chain_seq {d.get('chain_seq')}: prev_hash no apunta al documento anterior")
        prev = d
    return problems


# ── OpenSearch ────────────────────────────────────────────────────────────────

INDEX_MAPPINGS = {
    "dynamic": False,  # campos nuevos quedan en _source sin indexar: nunca un 400 por mapping
    "properties": {
        "stream_id": {"type": "keyword"},
        "event_time": {"type": "date"},
        "event_type": {"type": "keyword"},
        "trace_id": {"type": "keyword"},
        "src_ip": {"type": "keyword"},
        "username": {"type": "keyword"},
        "access_event": {"type": "keyword"},
        "approver_role": {"type": "keyword"},
        "status": {"type": "keyword"},
        "tier": {"type": "integer"},
        "risk_score": {"type": "float"},
        "accion_recomendada": {"type": "keyword"},
        "block_action": {"type": "keyword"},
        "block_reason": {"type": "keyword"},
        "block_enforced": {"type": "boolean"},
        "event_age_seconds": {"type": "float"},
        "case_id": {"type": "keyword"},
        # H52: corroboración ponderada (modo sombra) vs. gate real
        "corroboration_score": {"type": "float"},
        "corroboration_band": {"type": "keyword"},
        "corroboration_ambiguous": {"type": "boolean"},
        "corroboration_count": {"type": "integer"},
        # H53: grupos signature/context (modo sombra)
        "corroboration_groups_available": {"type": "keyword"},
        "correlated_classtype": {"type": "keyword"},
        "correlated_attack_technique_id": {"type": "keyword"},
        "alert_lookup": {"type": "keyword"},
        "recidivism_count": {"type": "integer"},
        "chain_seq": {"type": "long"},
        "prev_hash": {"type": "keyword"},
        "hash": {"type": "keyword"},
        "payload": {"type": "object", "enabled": False},
    },
}


def ism_policy(retention_days: int) -> dict:
    return {"policy": {
        "description": f"soc-responses: borrar índices diarios con más de {retention_days} días (H39)",
        "default_state": "hot",
        "states": [
            {"name": "hot", "actions": [],
             "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{retention_days}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": [INDEX_PATTERN], "priority": 100}],
    }}


class OpenSearchClient:
    def __init__(self, settings: AuditIndexerSettings, transport: httpx.BaseTransport | None = None):
        verify: bool | ssl.SSLContext = True
        if not settings.os_verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            verify = ctx
        # httpx.Client sync: proceso sin event loop (bootstrap + loop bloqueante
        # sobre XREADGROUP) — excepción consciente a "siempre httpx.AsyncClient"
        # de CLAUDE.md, ver docs/BITACORA_TECNICA.md H41. Timeout explícito igual
        # al estándar: connect 2 s, read 5 s.
        self._http = httpx.Client(
            base_url=settings.os_host, auth=(settings.os_user, settings.os_pass), verify=verify,
            timeout=httpx.Timeout(5.0, connect=2.0), transport=transport,
        )

    def request(self, method: str, path: str, body: dict | None = None) -> httpx.Response:
        return self._http.request(method, path, json=body)

    def ensure_template(self) -> None:
        """PUT del index template (idempotente: reescribirlo no cambia nada)."""
        tpl = {"index_patterns": [INDEX_PATTERN], "priority": 100, "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0, "codec": "best_compression"},
            "mappings": INDEX_MAPPINGS}}
        r = self.request("PUT", f"/_index_template/{TEMPLATE_NAME}", tpl)
        if r.status_code >= 300:
            raise IndexingError(f"template {TEMPLATE_NAME}: HTTP {r.status_code} {r.text[:200]}")

    def ensure_policy(self, retention_days: int) -> str:
        """Crea la política ISM si no existe. Idempotente ante reintentos: si
        un intento anterior la creó pero su respuesta no llegó (timeout), el
        GET siguiente la encuentra, y un PUT concurrente da 409 = ya existe.

        Returns:
            "exists" o "created".
        """
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
        """(último chain_seq, su hash) o (0, genesis) si no hay documentos."""
        r = self.request("POST", f"/{INDEX_PATTERN}/_search", {
            "size": 1, "sort": [{"chain_seq": "desc"}], "_source": ["chain_seq", "hash"]})
        if r.status_code == 404:
            return 0, GENESIS_HASH
        if r.status_code >= 300:
            raise IndexingError(f"no se pudo leer la cabeza de la cadena: HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return 0, GENESIS_HASH
        src = hits[0]["_source"]
        return int(src["chain_seq"]), src["hash"]

    def create(self, index: str, doc_id: str, doc: dict) -> str:
        """'created' | 'exists'. Lanza IndexingError en cualquier otro caso."""
        r = self.request("PUT", f"/{index}/_create/{doc_id}", doc)
        if r.status_code in (200, 201):
            return "created"
        if r.status_code == 409:
            return "exists"
        raise IndexingError(f"{index}/{doc_id}: HTTP {r.status_code} {r.text[:200]}")

    def get_source(self, index: str, doc_id: str) -> dict | None:
        r = self.request("GET", f"/{index}/_doc/{doc_id}")
        return r.json().get("_source") if r.status_code == 200 else None


# ── Consumidor ────────────────────────────────────────────────────────────────

class ResponseAuditIndexer:
    def __init__(self, rdb: redis.Redis, os_client: Any, settings: AuditIndexerSettings):
        self.rdb, self.os, self.s = rdb, os_client, settings
        self.seq, self.head_hash = 0, GENESIS_HASH
        self._pending_first = True  # al arrancar (y tras un error): primero los pendientes propios

    def start(self) -> None:
        try:
            self.rdb.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
            log.info(f"consumer group {GROUP} creado sobre {STREAM} desde el inicio del stream")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        self.seq, self.head_hash = self.os.chain_head()
        log.info(f"cabeza de la cadena: chain_seq={self.seq} hash={self.head_hash[:16]}")

    def process(self, msg_id: str, fields: dict) -> str:
        """Persiste un mensaje y recién entonces hace XACK. Lanza
        IndexingError sin hacer XACK si OpenSearch no lo confirma."""
        content = build_content(msg_id, fields)
        doc = chain_document(content, self.seq + 1, self.head_hash)
        outcome = self.os.create(index_name_for(msg_id), msg_id, doc)
        if outcome == "created":
            self.seq, self.head_hash = doc["chain_seq"], doc["hash"]
        else:
            # Ya persistido en una corrida anterior (cayó antes del XACK). La
            # cabeza viene de OpenSearch, que ya lo incluye: no se mueve hacia
            # atrás ni se reescribe nada.
            existing = self.os.get_source(index_name_for(msg_id), msg_id) or {}
            if int(existing.get("chain_seq", 0)) > self.seq:
                self.seq, self.head_hash = int(existing["chain_seq"]), existing["hash"]
        self.rdb.xack(STREAM, GROUP, msg_id)
        return outcome

    def run_once(self) -> int:
        """Una lectura del stream. Devuelve cuántos mensajes persistió."""
        start_id = "0" if self._pending_first else ">"
        resp = self.rdb.xreadgroup(GROUP, CONSUMER, {STREAM: start_id},
                                   count=self.s.batch_size,
                                   block=None if self._pending_first else self.s.block_ms)
        entries = resp[0][1] if resp else []
        if self._pending_first and not entries:
            self._pending_first = False
            return 0
        done = 0
        for msg_id, fields in entries:
            try:
                self.process(msg_id, fields)
                done += 1
            except Exception:
                # Orden y cadena: no se sigue con el resto del lote; todo lo no
                # confirmado queda pendiente y se relee primero.
                self._pending_first = True
                raise
        return done

    def run(self) -> None:
        """Loop principal. Requiere start() previo (lo hace bootstrap_until_ready)."""
        total = 0
        while True:
            try:
                total += self.run_once()
                if total and total % 1000 == 0:
                    log.info(f"persistidos {total} eventos | chain_seq={self.seq}")
            except (IndexingError, httpx.HTTPError, redis.RedisError) as e:
                log.error(f"no se pudo persistir, reintento en {self.s.error_backoff_seconds}s: {e}")
                time.sleep(self.s.error_backoff_seconds)
                try:
                    # Re-sincroniza la cabeza: OpenSearch es la fuente de verdad.
                    self.seq, self.head_hash = self.os.chain_head()
                except (IndexingError, httpx.HTTPError) as e2:
                    log.error(f"cabeza de la cadena no disponible: {e2}")


# Errores transitorios de setup: red/timeout de httpx, respuesta no OK de
# OpenSearch (IndexingError) o Redis no disponible.
BOOTSTRAP_RETRYABLE = (httpx.HTTPError, IndexingError, redis.RedisError)


def with_retry(op: str, fn: Callable[[], Any], sleep: Callable[[float], None] = time.sleep) -> Any:
    """Ejecuta fn con 1 intento + len(BOOTSTRAP_BACKOFF_SECONDS) reintentos.
    Loguea cada reintento (operación, intento, causa, espera) y relanza el
    último error si se agotan."""
    attempts = len(BOOTSTRAP_BACKOFF_SECONDS) + 1
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except BOOTSTRAP_RETRYABLE as e:
            if attempt == attempts:
                raise
            wait = BOOTSTRAP_BACKOFF_SECONDS[attempt - 1]
            log.warning("bootstrap_retry op=%s intento=%d/%d causa=%s:%s espera_s=%.0f",
                        op, attempt, attempts, type(e).__name__, str(e)[:200], wait)
            sleep(wait)
    raise AssertionError("inalcanzable")


def bootstrap_until_ready(os_client: OpenSearchClient, indexer: ResponseAuditIndexer,
                          settings: AuditIndexerSettings,
                          sleep: Callable[[float], None] = time.sleep,
                          max_rounds: int | None = None) -> bool:
    """Template, política ISM y consumer group + cabeza de la cadena, cada uno
    con reintentos. Si una ronda falla entera, espera y repite en vez de
    terminar el proceso. Devuelve True cuando quedó listo; False solo si se
    agotó max_rounds (usado en tests)."""
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        rounds += 1
        try:
            with_retry("index_template", os_client.ensure_template, sleep)
            with_retry("ism_policy", lambda: os_client.ensure_policy(settings.retention_days), sleep)
            with_retry("consumer_group_y_cabeza", indexer.start, sleep)
            return True
        except BOOTSTRAP_RETRYABLE as e:
            log.error("bootstrap_failed ronda=%d causa=%s:%s reintento_ronda_s=%.0f",
                      rounds, type(e).__name__, str(e)[:200], BOOTSTRAP_ROUND_BACKOFF_SECONDS)
            sleep(BOOTSTRAP_ROUND_BACKOFF_SECONDS)
    return False


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [response_audit_indexer] %(levelname)s %(message)s")
    # httpx loguea cada request en INFO: con un _create por evento eso es una
    # línea de journal por documento. Solo advertencias/errores.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = AuditIndexerSettings()
    os_client = OpenSearchClient(s)
    rdb = redis.Redis(host=s.redis_host, port=s.redis_port, password=s.redis_password,
                      decode_responses=True, socket_timeout=(s.block_ms / 1000) + 5)
    indexer = ResponseAuditIndexer(rdb, os_client, s)
    bootstrap_until_ready(os_client, indexer, s)
    indexer.run()


if __name__ == "__main__":
    main()
