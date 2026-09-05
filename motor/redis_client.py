"""
redis_client.py — Publicación a Redis Streams del motor SOC
Streams: soc:flows (Fast Path) y soc:decisions (decisiones finales)
"""
import redis, json, logging, os
from datetime import datetime, timezone

from dotenv import load_dotenv
from redis.backoff import NoBackoff
from redis.retry import Retry

# Mismo patrón que opensearch_indexer.py/dashboard.py desde H27: REDIS_PASSWORD
# vive en .env (WorkingDirectory), no en el unit file de systemd.
load_dotenv()

log = logging.getLogger("motor.redis")

REDIS_HOST = os.environ.get("REDIS_HOST", "200.54.12.140")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASS = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASS:
    raise RuntimeError(
        "REDIS_PASSWORD no está configurada en el entorno — sin default a "
        "propósito, un fallback adivinable es peor que fallar al arrancar."
    )
MAXLEN     = 10000

_client = None

def get_redis():
    global _client
    if _client is None:
        try:
            _client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASS,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
                # Continuación de H30: redis-py 8.x trae un Retry por defecto
                # con hasta 10 reintentos sobre TimeoutError/ConnectionError,
                # incluso con retry_on_timeout=False (validado con CLIENT
                # PAUSE contra un Redis de prueba: sin esto, 1 intento
                # "fallido" tardaba ~5s en vez de los ~1s configurados).
                # NoBackoff()+0 fuerza un único intento real. retry_on_timeout
                # está deprecado en redis-py 8.x (TimeoutError ya se incluye
                # por defecto en el Retry) — pasar retry= explícito alcanza.
                retry=Retry(NoBackoff(), 0),
            )
            _client.ping()
            log.info(f"Redis conectado: {REDIS_HOST}:{REDIS_PORT}")
        except Exception as e:
            log.error(f"Redis no disponible: {e}")
            _client = None
    return _client

def publish_decision(trace_id: str, features: dict, decision: dict):
    """Publica la decisión final al stream soc:decisions"""
    r = get_redis()
    if r is None:
        return False
    try:
        payload = {
            "trace_id":      trace_id,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "tier":          str(decision["tier"]),
            "risk_score":    str(decision["risk_score"]),
            "ml_score":      str(decision["ml_score"]),
            "anomaly_score": str(decision["anomaly_score"]),
            "L4_DST_PORT":   str(features.get("L4_DST_PORT", 0)),
            "OUT_PKTS":      str(features.get("OUT_PKTS", 0)),
            "DURATION_MS":   str(features.get("FLOW_DURATION_MILLISECONDS", 0)),
            "SERVER_FLAGS":  str(features.get("SERVER_TCP_FLAGS", 0)),
            "decision":      decision["decision"],
            "latency_ms":    str(decision.get("latency_ms", 0)),
        }
        r.xadd("soc:decisions", payload, maxlen=MAXLEN, approximate=True)
        return True
    except Exception as e:
        log.warning(f"Error publicando a Redis: {e}")
        return False

def publish_flow(trace_id: str, features: dict):
    """Publica el flow al stream soc:flows (para workers de enriquecimiento)"""
    r = get_redis()
    if r is None:
        return False
    try:
        payload = {"trace_id": trace_id, **{k: str(v) for k,v in features.items()}}
        r.xadd("soc:flows", payload, maxlen=MAXLEN, approximate=True)
        return True
    except Exception as e:
        log.warning(f"Error publicando flow: {e}")
        return False
