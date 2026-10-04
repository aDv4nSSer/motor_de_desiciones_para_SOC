# Observabilidad — Logging Estructurado, Tracing y Health

## Logging estructurado con structlog

Todo servicio usa structlog con output JSON en producción. Configurar una sola vez al iniciar:

```python
import structlog, logging

def configure_logging(service_name: str, version: str) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_logger_name,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
    )
    structlog.contextvars.bind_contextvars(service=service_name, version=version)

logger = structlog.get_logger()
```

**Campos obligatorios en eventos del pipeline:**
`trace_id`, `service`, `level`, `timestamp`, `event`

**Campos adicionales según contexto:**
`entity_id`, `entity_type`, `tier`, `duration_ms`, `cache_level`, `provider`, `verdict`

## Middleware de tracing — trace_id en toda respuesta

Implementación de referencia en producción: `motor/trace_middleware.py` (copia en
`api/middleware/trace.py`), commit `cf3219b`, H45. **Middleware ASGI puro, no
`@app.middleware("http")`:** con `call_next`, una excepción no controlada sale como
500 armado por `ServerErrorMiddleware` por fuera del middleware, **sin** `X-Trace-Id`.
El ASGI puro intercepta ese caso, responde el 500 con header y error uniforme, y
re-lanza la excepción para que uvicorn la siga registrando.

```python
import re, time, uuid
from starlette.types import ASGIApp, Message, Receive, Scope, Send

TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")  # input externo: validar

def resolve_trace_id(incoming: str | None) -> str:
    if incoming and TRACE_ID_PATTERN.fullmatch(incoming):
        return incoming
    return str(uuid.uuid4())        # nunca reflejar un valor arbitrario

class TraceIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw = next((v.decode("latin-1") for k, v in scope.get("headers", [])
                    if k == b"x-trace-id"), None)
        trace_id = resolve_trace_id(raw)
        scope.setdefault("state", {})["trace_id"] = trace_id   # request.state.trace_id
        t0, status, started = time.monotonic(), 500, False

        async def send_with_trace(message: Message) -> None:
            nonlocal status, started
            if message["type"] == "http.response.start":
                started, status = True, message["status"]
                ms = round((time.monotonic() - t0) * 1000, 2)
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"x-trace-id", b"x-duration-ms")]
                headers += [(b"X-Trace-Id", trace_id.encode()),
                            (b"X-Duration-Ms", str(ms).encode())]
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_trace)
        except Exception:
            if not started:             # 500 con header + error uniforme de CLAUDE.md
                ...                     # ver motor/trace_middleware.py
            raise                       # uvicorn sigue logueando el traceback
        finally:
            logger.info("request_completed", trace_id=trace_id, method=scope.get("method"),
                        path=scope.get("path"), status=status,
                        duration_ms=round((time.monotonic() - t0) * 1000, 2))
```

Registrar con `app.add_middleware(TraceIdMiddleware)` en todos los servicios FastAPI.
(En producción el log usa `logging` de la stdlib: structlog aún no está instalado, H41.)

## Propagación del trace_id en el pipeline

```
Fast Path genera trace_id
    → Redis Stream: campo "trace_id" en cada mensaje
    → Llamadas a historical-context-svc: header "X-Trace-Id"
    → Llamadas a threat-intel-svc: header "X-Trace-Id"
    → Documento en soc-decisions: campo "trace_id"
    → Alerta en Wazuh: campo "trace_id" en el contexto
    → Toda línea de log: via structlog contextvars (automático)
```

Para auditar una decisión completa: una sola query OpenSearch por `trace_id`.
```json
{ "query": { "term": { "trace_id.keyword": "uuid-aqui" } } }
```

## Health Check estándar — implementar en todos los servicios

```python
from pydantic import BaseModel
from typing import Literal
import time, asyncio

class DependencyStatus(BaseModel):
    name: str
    status: Literal["ok", "degraded", "error"]
    latency_ms: float | None = None
    error: str | None = None

class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    version: str
    dependencies: list[DependencyStatus]

@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    deps = []

    # Redis
    t0 = time.monotonic()
    try:
        await redis_client.ping()
        deps.append(DependencyStatus(name="redis", status="ok",
            latency_ms=round((time.monotonic() - t0) * 1000, 2)))
    except Exception as e:
        deps.append(DependencyStatus(name="redis", status="error", error=str(e)))

    # OpenSearch — mismo patrón con client.info()
    # API externa (TI) — mismo patrón, con timeout corto 1s

    overall = "ok" if all(d.status == "ok" for d in deps) else \
              "degraded" if any(d.status == "ok" for d in deps) else "error"
    return HealthResponse(status=overall, version=VERSION, dependencies=deps)
```

Docker Compose: `healthcheck: {test: ["CMD", "curl", "-f", "http://localhost:PORT/health"],
interval: 30s, timeout: 5s, retries: 3, start_period: 10s}`.

## Performance budgets

| Operación | Target p99 | Acción si excede |
|---|---|---|
| Fast Path completo | < 100ms | Log WARNING + investigar |
| historical-context-svc Redis hit | < 10ms | Log WARNING |
| historical-context-svc OpenSearch fallback | < 500ms | Servir dato cacheado más reciente |
| threat-intel-svc caché L1 hit | < 5ms | Log WARNING |
| threat-intel-svc API externa | timeout 5s | Circuit breaker activa |
| SHAP por evento | < 200ms | Solo calcular si score > SHAP_THRESHOLD |
| Enrichment Path completo | < 10s | Log ERROR si excede consistentemente |

## Métricas Prometheus (GET /metrics)

```python
from prometheus_client import Counter, Histogram, generate_latest

REQUESTS = Counter("soc_requests_total", "Total requests",
                   ["service", "endpoint", "status"])
LATENCY  = Histogram("soc_request_duration_seconds", "Request latency",
                     ["service", "endpoint"])
CACHE    = Counter("soc_cache_hits_total", "Cache hits",
                   ["service", "cache_level"])
DECISIONS = Counter("soc_decisions_total", "Decisions by tier",
                    ["tier"])              # solo decision-engine
ML_SCORE  = Histogram("soc_ml_score", "ML score distribution",
                      buckets=[.1,.2,.3,.4,.5,.6,.7,.8,.9,1.0])  # solo decision-engine
```

Si Prometheus no está desplegado aún: log estructurado de métricas agregadas cada 5 minutos
como alternativa temporal hasta que se configure el stack de monitoreo.
