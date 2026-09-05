"""
main.py — Motor de Decisiones SOC v2
FastAPI: recibe flows de Vector (single o batch), clasifica con ML, publica a Redis.
Tesis UBO — Motor de decisión basado en riesgo para SOAR en SOC
"""
import asyncio, uuid, logging, time
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from contextlib import asynccontextmanager

from schemas import FlowFeatures, DecisionResponse, RiskTier
from model import get_model
from redis_client import publish_decision, publish_flow
from response.queue import enqueue_response_task
from dashboard import (
    get_stats, get_recent_decisions, get_active_blocks, get_recent_responses,
    get_port_stats, list_cases, update_case_state,
    get_precision_stats, get_watcher_heartbeat, get_experimental_detections,
)
from auth import verify_credentials

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)
log = logging.getLogger("motor")

T3_CLASSTYPES = {
    "trojan-activity", "shellcode-detect", "web-application-attack",
    "attempted-admin", "attempted-user", "successful-admin", "policy-violation",
}

TIER_NAMES = {0: "T0_BENIGNO", 1: "T1_BAJO", 2: "T2_MEDIO", 3: "T3_CRITICO"}
DECISIONS  = {0: "ALLOW", 1: "LOG", 2: "ALERT", 3: "BLOCK"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Motor SOC iniciando...")
    model = get_model()
    log.info(f"Modelo cargado: {model.model_version}")
    yield
    log.info("Motor SOC detenido.")

app = FastAPI(
    title="Motor de Decisiones SOC",
    description="Motor de riesgo calibrado con ML para SOAR en SOC — Tesis UBO",
    version="0.2.0",
    lifespan=lifespan,
)

def process_event(event_data: dict, trace_id: str, classtype: str) -> dict:
    """Procesa un evento y retorna la decisión."""
    t_start = time.perf_counter()
    model   = get_model()

    try:
        flow     = FlowFeatures(**event_data)
        features = flow.model_dump()
    except Exception as e:
        log.error(f"Validación fallida: {e} | body: {str(event_data)[:200]}")
        return {"trace_id": trace_id, "error": str(e), "tier": 0, "decision": "ALLOW"}

    classtype_override = classtype.lower() in T3_CLASSTYPES
    scores = model.predict(features)
    tier   = 3 if classtype_override else model.tier(scores["risk_score"])

    response = {
        "trace_id":           trace_id,
        "tier":               tier,
        "tier_name":          TIER_NAMES[tier],
        "risk_score":         scores["risk_score"],
        "anomaly_score":      scores["anomaly_score"],
        "ml_score":           scores["ml_score"],
        "decision":           DECISIONS[tier],
        "classtype_override": classtype_override,
        "model_version":      model.model_version,
        "features_used": {
            "SERVER_TCP_FLAGS":           features["SERVER_TCP_FLAGS"],
            "OUT_PKTS":                   features["OUT_PKTS"],
            "FLOW_DURATION_MILLISECONDS": features["FLOW_DURATION_MILLISECONDS"],
            "L4_DST_PORT":               features["L4_DST_PORT"],
        }
    }

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    response["latency_ms"] = round(elapsed_ms, 2)

    publish_flow(trace_id, features)
    publish_decision(trace_id, features, response)
    enqueue_response_task(
        trace_id=trace_id,
        tier=tier,
        risk_score=scores["risk_score"],
        src_ip=event_data.get("IPV4_SRC_ADDR") or event_data.get("src_ip"),
        dst_ip=event_data.get("IPV4_DST_ADDR") or event_data.get("dst_ip"),
        dst_port=features["L4_DST_PORT"],
        classtype=classtype,
        classtype_override=classtype_override,
    )

    if elapsed_ms > 100:
        log.warning(f"Fast Path lento: {elapsed_ms:.1f}ms [trace={trace_id}]")

    log.info(
        f"[{trace_id[:8]}] tier={tier} score={scores['risk_score']:.3f} "
        f"port={features['L4_DST_PORT']} elapsed={elapsed_ms:.1f}ms"
    )
    return response

# ── Endpoint principal ─────────────────────────────────────────────────────────
@app.post("/decide")
async def decide(request: Request):
    """
    Fast Path (<100ms): acepta un evento único o array de eventos de Vector.
    """
    try:
        body = await request.json()
    except Exception as e:
        log.error(f"JSON inválido: {e}")
        return JSONResponse(status_code=400, content={"error": "invalid json"})

    classtype = request.headers.get("X-Suricata-Classtype", "")
    trace_id  = request.headers.get("X-Trace-Id", str(uuid.uuid4()))

    # Vector puede enviar un objeto único o un array de objetos (batch)
    events = body if isinstance(body, list) else [body]

    # Continuación de H30: process_event() es síncrono (inferencia CPU-bound +
    # publish a Redis) — llamarlo inline bloquea el único event loop de
    # uvicorn para TODAS las requests concurrentes. run_in_executor lo corre
    # en el threadpool default de asyncio, liberando el loop para seguir
    # aceptando conexiones mientras corre. Seguro para concurrencia: el
    # modelo (LightGBM/IsolationForest) es de solo-lectura durante inferencia
    # y los clientes Redis usan connection pool (ambos ya son thread-safe sin
    # cambios adicionales).
    loop = asyncio.get_running_loop()
    results = await asyncio.gather(*[
        loop.run_in_executor(None, process_event, ev, str(uuid.uuid4()), classtype)
        for ev in events
    ])

    # Si Vector envió un solo evento, retornar un objeto; si batch, retornar lista
    return results[0] if len(results) == 1 else results

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    model = get_model()
    return {
        "status":        "ok",
        "model_version": model.model_version,
        "model_real":    model.lgbm is not None,
        "iforest_real":  model.iforest is not None,
    }

@app.get("/")
async def root():
    return {
        "service": "Motor de Decisiones SOC",
        "version": "0.2.0",
        "endpoints": {"POST /decide": "Clasificar flow", "GET /health": "Estado"}
    }

# ── Dashboard: endpoints de solo lectura ────────────────────────────────────
@app.get("/api/dashboard/stats")
async def dashboard_stats(window_minutes: int = 60, user: str = Depends(verify_credentials)):
    return get_stats(window_minutes)

@app.get("/api/dashboard/decisions")
async def dashboard_decisions(limit: int = 50, user: str = Depends(verify_credentials)):
    return get_recent_decisions(min(limit, 200))

@app.get("/api/dashboard/blocks/active")
async def dashboard_blocks_active(user: str = Depends(verify_credentials)):
    return get_active_blocks()

@app.get("/api/dashboard/blocks/recent")
async def dashboard_blocks_recent(limit: int = 50, user: str = Depends(verify_credentials)):
    return get_recent_responses(min(limit, 200))

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(user: str = Depends(verify_credentials)):
    with open("dashboard.html", encoding="utf-8") as f:
        return f.read()

@app.get("/api/dashboard/ports")
async def dashboard_ports(window_minutes: int = 60, top_n: int = 15, user: str = Depends(verify_credentials)):
    return get_port_stats(window_minutes, top_n)

@app.get("/api/dashboard/precision")
async def dashboard_precision(window_minutes: int = 60, user: str = Depends(verify_credentials)):
    return get_precision_stats(window_minutes)

@app.get("/api/dashboard/watcher-heartbeat")
async def dashboard_watcher_heartbeat(user: str = Depends(verify_credentials)):
    return get_watcher_heartbeat()

@app.get("/api/dashboard/experimental")
async def dashboard_experimental(limit: int = 20, user: str = Depends(verify_credentials)):
    return get_experimental_detections(limit)


# ── Casos (requieren autenticacion) ──────────────────────────────────────
@app.get("/api/dashboard/cases")
async def dashboard_cases(only_open: bool = False, limit: int = 50, user: str = Depends(verify_credentials)):
    return list_cases(only_open=only_open, limit=limit)


@app.post("/api/dashboard/cases/{case_id}/state")
async def dashboard_update_case(
    case_id: str,
    payload: dict,
    user: str = Depends(verify_credentials),
):
    new_state = payload.get("state", "")
    note = payload.get("note", "")
    try:
        case = update_case_state(case_id, new_state, note, actor=user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    return case
