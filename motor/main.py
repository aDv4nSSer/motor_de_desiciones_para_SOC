"""
main.py — Motor de Decisiones SOC v2
FastAPI: recibe flows de Vector (single o batch), clasifica con ML, publica a Redis.
Tesis UBO — Motor de decisión basado en riesgo para SOAR en SOC
"""
import asyncio
import json
import logging
import multiprocessing
import time
import uuid
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from auth import get_current_user, log_access_event, require_ciso
from auth import login as auth_login
from dashboard import (
    _get_redis as get_dashboard_redis,
)
from dashboard import (
    DECISIONS_MAX_LIMIT,
    get_active_blocks,
    get_experimental_detections,
    get_port_stats,
    get_precision_stats,
    get_recent_decisions,
    get_recent_responses,
    get_stats,
    get_watcher_heartbeat,
    list_cases,
    update_case_state,
)
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# H36: "from model import get_model" NO va a nivel de módulo a propósito —
# ver _init_score_worker() más abajo para el porqué (contención de joblib/
# sklearn con nuestro propio ProcessPoolExecutor, encontrada en FASE 2).
from redis_client import publish_decision, publish_flow
from response.approvals import (
    APPROVALS_MAX_LIMIT,
    get_approval,
    pending_approvals_page,
    resolve_approval,
)
from response.config import get_settings as get_response_settings
from response.enforcer import build_enforcer, is_safelisted
from response.queue import enqueue_response_task
from schemas import FlowFeatures
from users import ROLE_LEVEL, User, get_user_record

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

# H36 (2026-09-08): ProcessPoolExecutor para el scoring CPU-bound, reemplaza
# el ThreadPoolExecutor de H30 (confirmado GIL-bound en H35 — duplicar
# threads no subía el %CPU proporcionalmente). contexto "spawn" a propósito:
# evita heredar conexiones Redis/sockets/event loop del proceso padre vía
# fork, que podrían quedar en estado corrupto o compartido entre procesos.
# 8→10 workers (2026-09-08, mismo día): 8 workers desplegado y validado
# (CPU repartido, Vector timeouts en 0, Fast Path 44-91ms vs 2000-2500ms
# antes) — subido a 10 tras confirmar margen de memoria (6.3GB disponibles,
# costo incremental ~664MB) porque el lag de soc:response:tasks, aunque
# mucho más lento que antes, seguía subiendo en vez de estabilizarse.
_PROCESS_POOL_WORKERS = 10

def _init_score_worker():
    """Corre UNA VEZ por proceso worker al arrancar — carga el modelo como
    global de ESE proceso (spawn no comparte memoria con el padre).

    FASE 2 (H36): encontrado con evidencia — al importar `model.py` (que
    importa sklearn/joblib) desde CADA uno de los 8 workers, joblib crea su
    propio pool interno ("loky", confirmado por los nombres de semáforos
    filtrados al apagar: /loky-<pid>-... en vez de /mp-<pid>-...) DENTRO de
    cada worker ya paralelo nuestro — pools anidados, con contención real
    que en el caso completo (main.py real vía uvicorn, no este repro
    aislado) colgaba el calentamiento del proceso padre indefinidamente.
    Fix: fijar estas env vars ANTES de que sklearn/joblib se importen por
    primera vez en este proceso — por eso el import de `model` es local
    acá, no a nivel de módulo (si fuera top-level, el reimport de main.py
    que cada hijo hace para resolver la referencia picklable ya habría
    importado sklearn antes de llegar a esta función, demasiado tarde).
    """
    import os
    os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")
    os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
    from model import get_model
    get_model()

# Guard obligatorio bajo spawn: cada worker hijo, para resolver la
# referencia picklable main.score_event, reimporta este mismo módulo — sin
# este guard, ese reimport volvería a ejecutar esta línea DENTRO de cada
# hijo, creando un ProcessPoolExecutor anidado por cada uno (encontrado en
# FASE 2: colgaba el warmup del proceso padre indefinidamente, aunque los
# workers cargaban el modelo bien — el problema era el pool anidado, no el
# modelo). multiprocessing.parent_process() es None solo en el proceso
# original que nunca fue spawneado por otro contexto de multiprocessing.
_score_pool = None
if multiprocessing.parent_process() is None:
    _score_pool = ProcessPoolExecutor(
        max_workers=_PROCESS_POOL_WORKERS,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=_init_score_worker,
    )


def score_event(features: dict, classtype: str) -> dict:
    """Función PURA y picklable: recibe SOLO datos simples (features ya
    validados) y devuelve SOLO datos simples (score/tier/decisión). Sin
    Redis, sin request, sin logging de publish — eso queda en
    process_event(), en el proceso padre. Corre en _score_pool.
    """
    from model import get_model  # ver _init_score_worker() — import local a propósito
    model = get_model()
    classtype_override = classtype.lower() in T3_CLASSTYPES
    scores = model.predict(features)
    tier   = 3 if classtype_override else model.tier(scores["risk_score"])
    return {
        "tier":               tier,
        "tier_name":          TIER_NAMES[tier],
        "risk_score":         scores["risk_score"],
        "anomaly_score":      scores["anomaly_score"],
        "ml_score":           scores["ml_score"],
        "decision":           DECISIONS[tier],
        "classtype_override": classtype_override,
        "model_version":      model.model_version,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Motor SOC iniciando...")
    from model import get_model  # ver _init_score_worker() — import local a propósito
    model = get_model()
    log.info(f"Modelo cargado: {model.model_version}")
    # H36: calentar el pool de procesos ahora, no en la primera request real
    # — fuerza a spawnear los N workers y cargar el modelo en cada uno.
    log.info(f"Calentando {_PROCESS_POOL_WORKERS} workers del ProcessPoolExecutor...")
    warmup_futures = [_score_pool.submit(_init_score_worker) for _ in range(_PROCESS_POOL_WORKERS)]
    for f in warmup_futures:
        f.result()
    log.info("ProcessPoolExecutor listo.")
    yield
    log.info("Motor SOC deteniendo...")
    _score_pool.shutdown(wait=True)
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

    try:
        flow     = FlowFeatures(**event_data)
        features = flow.model_dump()
    except Exception as e:
        log.error(f"Validación fallida: {e} | body: {str(event_data)[:200]}")
        return {"trace_id": trace_id, "error": str(e), "tier": 0, "decision": "ALLOW"}

    # H36: el scoring CPU-bound corre en _score_pool (procesos, no threads).
    # .result() bloquea el thread actual (del ThreadPoolExecutor de siempre)
    # hasta que el worker responde — no bloquea el event loop de asyncio,
    # porque process_event ya corre fuera de él (run_in_executor en decide()).
    scored = _score_pool.submit(score_event, features, classtype).result()

    tier                = scored["tier"]
    classtype_override  = scored["classtype_override"]

    response = {
        "trace_id":           trace_id,
        "tier":               tier,
        "tier_name":          scored["tier_name"],
        "risk_score":         scored["risk_score"],
        "anomaly_score":      scored["anomaly_score"],
        "ml_score":           scored["ml_score"],
        "decision":           scored["decision"],
        "classtype_override": classtype_override,
        "model_version":      scored["model_version"],
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
        risk_score=scored["risk_score"],
        src_ip=event_data.get("IPV4_SRC_ADDR") or event_data.get("src_ip"),
        dst_ip=event_data.get("IPV4_DST_ADDR") or event_data.get("dst_ip"),
        dst_port=features["L4_DST_PORT"],
        classtype=classtype,
        classtype_override=classtype_override,
    )

    if elapsed_ms > 100:
        log.warning(f"Fast Path lento: {elapsed_ms:.1f}ms [trace={trace_id}]")

    log.info(
        f"[{trace_id[:8]}] tier={tier} score={scored['risk_score']:.3f} "
        f"port={features['L4_DST_PORT']} elapsed={elapsed_ms:.1f}ms"
    )
    return response

# ── Endpoint principal ─────────────────────────────────────────────────────────
@app.post("/api/v1/decide")
# Alias sin versionar: Vector en .139 todavía postea a /decide. Se mantiene
# hasta redesplegar Vector con la URL nueva; retirar después.
@app.post("/decide", include_in_schema=False, deprecated=True)
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
    from model import get_model  # ver _init_score_worker() — import local a propósito
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
        "endpoints": {"POST /api/v1/decide": "Clasificar flow", "GET /health": "Estado"}
    }

# ── Dashboard: endpoints de solo lectura ────────────────────────────────────
# Todos los endpoints de dashboard/auth son `def`, no `async def`, a
# propósito: hacen IO síncrono (OpenSearch vía urllib con timeout 5s, Redis
# síncrono, bcrypt). Dentro de `async def` ese IO bloquearía el único event
# loop de uvicorn — el mismo que atiende /decide (Fast Path <100ms). Como
# `def`, FastAPI los corre en su threadpool. Lo verifica
# tests/unit/test_dashboard_endpoints.py.
@app.get("/api/v1/dashboard/stats")
def dashboard_stats(window_minutes: int = 60, user: User = Depends(get_current_user)):
    return get_stats(window_minutes)

@app.get("/api/v1/dashboard/decisions")
def dashboard_decisions(
    limit: int = Query(50, ge=1, le=DECISIONS_MAX_LIMIT),
    tier_min: int = Query(0, ge=0, le=3),
    before: datetime | None = Query(None, description="Cursor: timestamp del último ítem de la página previa"),
    user: User = Depends(get_current_user),
):
    return get_recent_decisions(limit, tier_min=tier_min, before=before)

@app.get("/api/v1/dashboard/blocks/active")
def dashboard_blocks_active(user: User = Depends(get_current_user)):
    return get_active_blocks()

@app.get("/api/v1/dashboard/blocks/recent")
def dashboard_blocks_recent(limit: int = 50, user: User = Depends(get_current_user)):
    return get_recent_responses(min(limit, 200))

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(user: User = Depends(get_current_user)):
    with open("dashboard.html", encoding="utf-8") as f:
        return f.read()

@app.get("/api/v1/dashboard/ports")
def dashboard_ports(window_minutes: int = 60, top_n: int = 15, user: User = Depends(get_current_user)):
    return get_port_stats(window_minutes, top_n)

@app.get("/api/v1/dashboard/precision")
def dashboard_precision(window_minutes: int = 60, user: User = Depends(get_current_user)):
    return get_precision_stats(window_minutes)

@app.get("/api/v1/dashboard/watcher-heartbeat")
def dashboard_watcher_heartbeat(user: User = Depends(get_current_user)):
    return get_watcher_heartbeat()

@app.get("/api/v1/dashboard/experimental")
def dashboard_experimental(limit: int = 20, user: User = Depends(get_current_user)):
    return get_experimental_detections(limit)


# ── Casos (requieren autenticacion) ──────────────────────────────────────
@app.get("/api/v1/dashboard/cases")
def dashboard_cases(only_open: bool = False, limit: int = 50, user: User = Depends(get_current_user)):
    return list_cases(only_open=only_open, limit=limit)


@app.post("/api/v1/dashboard/cases/{case_id}/state")
def dashboard_update_case(
    case_id: str,
    payload: dict,
    user: User = Depends(get_current_user),
):
    new_state = payload.get("state", "")
    note = payload.get("note", "")
    try:
        case = update_case_state(case_id, new_state, note, actor=user.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if case is None:
        raise HTTPException(status_code=404, detail="Caso no encontrado")
    return case


# ── Auth ──────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def auth_login_endpoint(payload: LoginRequest):
    """Login del dashboard. Devuelve un JWT con el rol embebido (N1/N2/CISO).

    No hay endpoint de registro a propósito — los usuarios se crean con
    scripts/manage_users.py, corrido directamente en `.140`.
    """
    token = auth_login(payload.username, payload.password)
    # auth_login ya audita login_success/login_failed y lanza 401 si falla.
    record = get_user_record(payload.username)
    return LoginResponse(access_token=token, role=record.role if record else "N1")


@app.get("/api/v1/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


# ── Aprobaciones humanas (accion_recomendada con requires_approval=True) ──
# Panel de aprobación del dashboard Operativo (pendiente #9 de la
# especificación). Cualquier operador autenticado (N1+) puede VER la cola;
# resolver una aprobación puntual exige el approval_level que trae el
# propio registro (hoy siempre "N1" — bloqueos de red con corroboración
# insuficiente; cuarentena de host quedará en "N2"/"CISO" cuando el
# pendiente #3 de Wazuh esté integrado).
@app.get("/api/v1/dashboard/approvals")
def dashboard_approvals(
    limit: int = Query(100, ge=1, le=APPROVALS_MAX_LIMIT),
    user: User = Depends(get_current_user),
):
    # Devuelve {items, total, limit, available}: el total real de la cola,
    # no solo la página (antes el panel mostraba 100 de 257 como si fueran todas).
    rdb = get_dashboard_redis()
    page = pending_approvals_page(rdb, limit)
    # Marca las IPs de safelist (infra propia): el panel no ofrece aprobarlas
    # y el endpoint de resolución lo rechaza igual (ver más abajo).
    settings = get_response_settings()
    for item in page["items"]:
        item["safelisted"] = is_safelisted(item.get("src_ip") or "", settings)
    return page


class ApprovalDecision(BaseModel):
    decision: str  # "approved" | "rejected"
    note: str = ""


@app.post("/api/v1/dashboard/approvals/{trace_id}/resolve")
def dashboard_resolve_approval(
    trace_id: str, payload: ApprovalDecision, user: User = Depends(get_current_user),
):
    rdb = get_dashboard_redis()
    approval = get_approval(trace_id, rdb)
    if approval is None:
        raise HTTPException(status_code=404, detail="Aprobación no encontrada")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"Ya resuelta ({approval['status']})")

    # Fail closed: un approval_level vacío, ausente o desconocido (ej.
    # BlockResult.approval_level default "", o un typo "n2") exige CISO —
    # nunca se degrada a N1. Si no, cualquier productor que olvide setear el
    # nivel dejaría a un N1 aprobar una acción de alto impacto.
    required_level = approval.get("approval_level")
    if required_level not in ROLE_LEVEL:
        required_level = "CISO"
    if ROLE_LEVEL.get(user.role, 0) < ROLE_LEVEL[required_level]:
        log_access_event(user.username, "approval_denied_role",
                          {"trace_id": trace_id, "required": required_level, "actual": user.role})
        raise HTTPException(
            status_code=403,
            detail=f"Esta aprobación requiere rol {required_level} o superior",
        )

    if payload.decision not in ("approved", "rejected"):
        raise HTTPException(status_code=400, detail="decision debe ser 'approved' o 'rejected'")

    # Safelist ANTES de resolver: la aprobación manual llama al enforcer
    # directo (no pasa por respond_block, que es donde vive el chequeo), así
    # que sin esto un "Aprobar" sobre la IP del bastion o de un gateway
    # dispararía firewall-drop sobre la propia infraestructura. Rechazar
    # sigue permitido; la aprobación queda pendiente si se intenta aprobar.
    if payload.decision == "approved" and is_safelisted(approval.get("src_ip") or "", get_response_settings()):
        log_access_event(user.username, "approval_denied_safelist",
                          {"trace_id": trace_id, "src_ip": approval.get("src_ip")})
        raise HTTPException(
            status_code=422,
            detail="La IP es infraestructura propia (safelist): no se puede bloquear. Rechaza la aprobación.",
        )

    resolved = resolve_approval(trace_id, user.username, payload.decision, rdb)
    if resolved is None:
        raise HTTPException(status_code=500, detail="No se pudo resolver la aprobación")

    if payload.decision == "approved":
        # Ejecuta AHORA el bloqueo que R2 había dejado pendiente. Se emite un
        # registro de auditoría NUEVO (no se edita el original en
        # soc:response:audit -- ese stream es solo de escritura) para que
        # quede trazado quién aprobó y con qué rol.
        settings = get_response_settings()
        enforcer = build_enforcer(settings)
        enforced, error = enforcer.block(approval["src_ip"], settings.block_ttl_seconds)
        try:
            audit_payload = {
                "trace_id": trace_id,
                "manual_approval": True,
                "approved_by": user.username,
                "approver_role": user.role,
                "src_ip": approval["src_ip"],
                "enforced": enforced,
                "error": error,
                "at": datetime.now(timezone.utc).isoformat(),
            }
            rdb.xadd("soc:response:audit", {"data": json.dumps(audit_payload)},
                     maxlen=100_000, approximate=True)
        except Exception as e:  # noqa: BLE001 — auditar nunca debe tumbar la respuesta al operador
            log.error(f"no se pudo auditar aprobacion manual de {trace_id}: {e}")
        log_access_event(user.username, "approval_granted",
                          {"trace_id": trace_id, "src_ip": approval["src_ip"], "enforced": enforced})
        resolved["enforced"] = enforced
    else:
        log_access_event(user.username, "approval_rejected", {"trace_id": trace_id})

    return resolved


# ── Cumplimiento / CISO (pendiente #10 — backend inicial, dashboard visual pendiente) ──
@app.get("/api/v1/dashboard/compliance")
def dashboard_compliance(window_minutes: int = 1440, user: User = Depends(require_ciso)):
    """Métricas de valor para CISO (sección 7 de la especificación, Fase 1:
    fatiga de alertas + MTTD/MTTR). Reutiliza get_stats/get_precision_stats
    ya existentes -- no se inventa ninguna cifra nueva."""
    stats = get_stats(window_minutes)
    precision = get_precision_stats(window_minutes)
    total = stats.get("total_decisiones") or 0
    por_decision = stats.get("por_decision", {})
    auto_resuelto = sum(v for k, v in por_decision.items() if k in ("ALLOW", "LOG"))
    fatiga_pct = round(100 * auto_resuelto / total, 1) if total else None
    return {
        "window_minutes": window_minutes,
        "fatiga_alertas_pct": fatiga_pct,
        "latencia_avg_ms": stats.get("latencia_avg_ms"),
        "latencia_p95_ms": stats.get("latencia_p95_ms"),
        "precision_bloqueos": precision,
    }


# ── Dashboard Operativo (React/Vite, frontend/operativo) ────────────────────
# Bundle estático compilado en el Mac y copiado a motor/static/operativo con
# scripts/deploy_operativo.sh (no se versiona). Mismo origen que la API: sin
# CORS, JWT solo en memoria del navegador. Sin auth en los estáticos (no
# contienen datos ni secretos); cada llamada a /api/v1/* sí exige el token.
OPERATIVO_DIR = Path(__file__).resolve().parent / "static" / "operativo"


def mount_operativo(target: FastAPI, directory: Path) -> bool:
    """Monta el bundle en /operativo si existe.

    Args:
        target: app donde montar.
        directory: carpeta con index.html + assets/.

    Returns:
        True si se montó; False (y log de aviso) si el bundle no está
        desplegado: el motor arranca igual, /operativo responde 404.
    """
    if not (directory / "index.html").is_file():
        log.warning(f"dashboard operativo no desplegado en {directory}; /operativo no se monta")
        return False

    # Redirect relativo explícito: detrás del proxy de .139, el redirect
    # automático de Starlette armaría una URL absoluta http:// (uvicorn no
    # confía en X-Forwarded-Proto de una IP externa) y el navegador saltaría
    # de https a http.
    @target.get("/operativo", include_in_schema=False)
    def operativo_slash() -> RedirectResponse:
        return RedirectResponse("/operativo/", status_code=307)

    target.mount("/operativo", StaticFiles(directory=directory, html=True), name="operativo")
    return True


mount_operativo(app, OPERATIVO_DIR)
