#!/usr/bin/env python3
"""
opensearch_indexer.py — Worker de auditoría con hash-chain
Tesis UBO — Motor de Decisiones SOC

Consume decisiones desde Redis Streams (soc:decisions) y las indexa
en OpenSearch con hash-chain para tamper-evidence (no repudio).

Hash-chain: cada decisión incluye:
  - prev_hash: hash SHA-256 del documento anterior
  - hash:      SHA-256(prev_hash + trace_id + timestamp + tier + risk_score)

Si alguien modifica un documento, la cadena se rompe y es detectable.
"""
import redis, hashlib, json, os, time, logging, urllib.request, urllib.parse, ssl
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [opensearch_indexer] %(levelname)s %(message)s"
)
log = logging.getLogger("opensearch_indexer")

# ── Configuración ─────────────────────────────────────────────────────────────
REDIS_HOST   = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT   = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASS   = os.environ.get("REDIS_PASSWORD", "")
REDIS_STREAM = "soc:decisions"
CONSUMER_GRP = "opensearch-indexer"
CONSUMER_ID  = "worker-1"

OS_HOST      = os.environ.get("OS_HOST", "https://localhost:9201")
OS_USER      = os.environ.get("OS_USER", "admin")
OS_PASS      = os.environ.get("OS_PASS", "")
OS_INDEX     = "soc-decisions"

STATE_FILE   = "/home/aiayala/tesis/motor/logs/opensearch_indexer_state.json"

# ── Cliente OpenSearch (simple HTTP sin SDK) ──────────────────────────────────
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def os_request(method, path, body=None):
    url = f"{OS_HOST}{path}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + __import__("base64").b64encode(
            f"{OS_USER}:{OS_PASS}".encode()).decode()
    }
    data = json.dumps(body).encode() if body else None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Esquema de URL no permitido: {parsed.scheme!r}")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as r:  # nosec B310 - esquema validado arriba (solo http/https)
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())
    except Exception as e:
        log.error(f"OpenSearch error: {e}")
        return None

# ── Hash-chain ────────────────────────────────────────────────────────────────
def compute_hash(prev_hash: str, data: dict) -> str:
    raw = (prev_hash
           + data.get("trace_id", "")
           + data.get("timestamp", "")
           + str(data.get("tier", ""))
           + str(data.get("risk_score", "")))
    return hashlib.sha256(raw.encode()).hexdigest()

def load_state() -> str:
    """Carga el último hash de la cadena."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f).get("last_hash", "genesis")
        except:
            pass
    return "genesis"

def save_state(last_hash: str):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"last_hash": last_hash,
                   "updated": datetime.now(timezone.utc).isoformat()}, f)

# ── Redis Streams ─────────────────────────────────────────────────────────────
def get_redis():
    return redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS,
        decode_responses=True, socket_timeout=5
    )

def ensure_consumer_group(r):
    try:
        r.xgroup_create(REDIS_STREAM, CONSUMER_GRP, id="0", mkstream=True)
        log.info(f"Consumer group '{CONSUMER_GRP}' creado")
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            log.info(f"Consumer group '{CONSUMER_GRP}' ya existe")
        else:
            raise

def parse_decision(msg_data: dict) -> dict:
    """Convierte el mensaje de Redis al documento OpenSearch."""
    return {
        "trace_id":      msg_data.get("trace_id", ""),
        "timestamp":     msg_data.get("timestamp",
                         datetime.now(timezone.utc).isoformat()),
        "tier":          int(msg_data.get("tier", 0)),
        "tier_name":     {0:"T0_BENIGNO", 1:"T1_BAJO",
                          2:"T2_MEDIO", 3:"T3_CRITICO"}.get(
                              int(msg_data.get("tier", 0)), "UNKNOWN"),
        "risk_score":    float(msg_data.get("risk_score", 0)),
        "ml_score":      float(msg_data.get("ml_score", 0)),
        "anomaly_score": float(msg_data.get("anomaly_score", 0)),
        "decision":      msg_data.get("decision", ""),
        "L4_DST_PORT":   int(msg_data.get("L4_DST_PORT", 0)),
        "OUT_PKTS":      int(msg_data.get("OUT_PKTS", 0)),
        "DURATION_MS":   int(msg_data.get("DURATION_MS", 0)),
        "SERVER_FLAGS":  int(msg_data.get("SERVER_FLAGS", 0)),
        "model_version": msg_data.get("model_version", ""),
        "latency_ms":    float(msg_data.get("latency_ms", 0)),
    }

def index_decision(doc: dict, prev_hash: str) -> str:
    """Indexa un documento en OpenSearch con hash-chain. Retorna el nuevo hash."""
    new_hash = compute_hash(prev_hash, doc)
    doc["prev_hash"] = prev_hash
    doc["hash"]      = new_hash

    result = os_request("POST", f"/{OS_INDEX}/_doc/{doc['trace_id']}", doc)
    if result and result.get("result") in ("created", "updated"):
        return new_hash
    else:
        log.error(f"Error indexando {doc['trace_id']}: {result}")
        return prev_hash  # No avanzar la cadena si falló

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    log.info("="*55)
    log.info("OpenSearch Indexer con hash-chain — Tesis UBO")
    log.info("="*55)

    # Verificar conectividad OpenSearch
    health = os_request("GET", "/_cluster/health")
    if not health:
        log.error("No se puede conectar a OpenSearch. Abortando.")
        return
    log.info(f"OpenSearch: cluster='{health.get('cluster_name')}' "
             f"status={health.get('status')}")

    r = get_redis()
    ensure_consumer_group(r)

    last_hash = load_state()
    log.info(f"Último hash de la cadena: {last_hash[:16]}...")

    processed = 0
    errors    = 0

    log.info("Esperando decisiones de Redis Streams...")

    while True:
        try:
            messages = r.xreadgroup(
                CONSUMER_GRP, CONSUMER_ID, {REDIS_STREAM: ">"},
                count=10, block=5000
            )

            if not messages:
                continue

            for stream_name, msg_list in messages:
                for msg_id, msg_data in msg_list:
                    try:
                        doc = parse_decision(msg_data)
                        last_hash = index_decision(doc, last_hash)
                        r.xack(REDIS_STREAM, CONSUMER_GRP, msg_id)
                        processed += 1

                        if processed % 100 == 0:
                            save_state(last_hash)
                            log.info(f"Indexados: {processed} | "
                                     f"Errores: {errors} | "
                                     f"Hash: {last_hash[:16]}...")

                    except Exception as e:
                        log.error(f"Error procesando {msg_id}: {e}")
                        errors += 1

        except redis.exceptions.ConnectionError:
            log.error("Redis desconectado. Reintentando en 5s...")
            time.sleep(5)
            r = get_redis()

        except KeyboardInterrupt:
            save_state(last_hash)
            log.info(f"Detenido. Total indexados: {processed}")
            break

        except Exception as e:
            log.error(f"Error inesperado: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
