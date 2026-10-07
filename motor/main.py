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
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import audit_view
import compliance
import redis
import user_admin
from attck_mapping import attack_fields, get_mapping
from auth import (
    get_current_session,
    get_current_user,
    log_access_event,
    require_ciso,
    require_role,
    require_role_session,
)
from auth import login as auth_login
from constants import T3_CLASSTYPES
from dashboard import (
    DECISIONS_MAX_LIMIT,
    RESPONSE_LOOKUP_MAX_IDS,
    get_active_blocks,
    get_experimental_detections,
    get_port_stats,
    get_precision_stats,
    get_recent_decisions,
    get_recent_responses,
    get_stats,
    get_watcher_heartbeat,
    list_cases,
    lookup_responses,
    update_case_state,
)
from dashboard import (
    _get_redis as get_dashboard_redis,
)
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

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
from response.approvals import is_expired as is_approval_expired
from response.config import get_settings as get_response_settings
from response.enforcer import ar_context, build_enforcer, is_safelisted
from response.queue import enqueue_response_task
from schemas import FlowFeatures
from sessions import revoke_session
from system_status import get_node_status
from trace_middleware import TRACE_ID_PATTERN, TraceIdMiddleware
from users import ROLE_LEVEL, Role, User, get_user_record

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)
log = logging.getLogger("motor")


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
    # Mapeo classtype -> ATT&CK: se carga acá para que un YAML roto impida
    # arrancar (AttckMappingLoadError) en vez de dejar decisiones sin ATT&CK
    # en silencio. Después process_event solo hace un dict.get en memoria.
    attck, _ = get_mapping()
    log.info(f"Mapeo ATT&CK cargado: v{attck.version}, {len(attck.mappings)} classtypes")
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
# X-Trace-Id + X-Duration-Ms en toda respuesta, también en 401/403/422/500 (H45).
app.add_middleware(TraceIdMiddleware)

# Dependencias de rol creadas una sola vez a nivel de módulo, no dentro del
# default de cada endpoint (ruff B008, H45). Mismo comportamiento.
REQUIRE_N2 = require_role("N2")
REQUIRE_N2_SESSION = require_role_session("N2")

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

    # ATT&CK acá y no en score_event(): score_event corre en el
    # ProcessPoolExecutor y se mantiene puro (H36). Esto es un dict.get en
    # memoria; sin match o sin classtype -> campos en None (H50: hoy Vector
    # no manda classtype, así que en tráfico real siempre es el caso).
    response = {
        "trace_id":           trace_id,
        "tier":               tier,
        "tier_name":          scored["tier_name"],
        "risk_score":         scored["risk_score"],
        "anomaly_score":      scored["anomaly_score"],
        "ml_score":           scored["ml_score"],
        "decision":           scored["decision"],
        "classtype":          classtype or None,
        "classtype_override": classtype_override,
        **attack_fields(classtype),
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


class ResponseLookupRequest(BaseModel):
    """trace_id de una página de la vista de alertas (input externo: se valida)."""
    trace_ids: list[str] = Field(..., min_length=1, max_length=RESPONSE_LOOKUP_MAX_IDS)

    @field_validator("trace_ids")
    @classmethod
    def _formato(cls, v: list[str]) -> list[str]:
        malos = [t for t in v if not TRACE_ID_PATTERN.fullmatch(t)]
        if malos:
            raise ValueError(f"{len(malos)} trace_id con formato inválido")
        return v


@app.post("/api/v1/dashboard/responses/lookup")
def dashboard_responses_lookup(payload: ResponseLookupRequest, user: User = Depends(get_current_user)):
    """Respuestas R1/R2 de trace_id concretos (H49). Ver dashboard.lookup_responses."""
    return lookup_responses(payload.trace_ids)

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
def auth_login_endpoint(payload: LoginRequest, request: Request):
    """Login del dashboard. Devuelve un JWT con el rol embebido (N1/N2/CISO).

    Desde H43 las cuentas también se gestionan desde el dashboard (N2+/CISO,
    ver user_admin.py); scripts/manage_users.py sigue siendo la vía para el
    primer CISO y para cambiar la propia contraseña. Cada login registra una
    sesión revocable (sessions.py) con el User-Agent y la IP que informa el
    proxy de .139 (X-Real-IP), solo como dato para "sesiones activas".
    """
    token = auth_login(
        payload.username, payload.password,
        user_agent=request.headers.get("user-agent", ""),
        client_ip=request.headers.get("x-real-ip", ""),
    )
    # auth_login ya audita login_success/login_failed y lanza 401 si falla.
    record = get_user_record(payload.username)
    return LoginResponse(access_token=token, role=record.role if record else "N1")


@app.get("/api/v1/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@app.post("/api/v1/auth/logout")
def auth_logout(current: tuple[User, str] = Depends(get_current_session)):
    """Cierra la sesión del lado del servidor: el token deja de servir aunque
    alguien lo haya copiado (antes de H43 solo se borraba en el navegador)."""
    user, jti = current
    try:
        revoke_session(user.username, jti)
    except redis.RedisError as e:
        log.error(f"no se pudo revocar la sesión al cerrar sesión de {user.username!r}: {e}")
        raise HTTPException(status_code=503, detail="No se pudo cerrar la sesión en el servidor, reintente")
    log_access_event(user.username, "logout", {"jti": jti})
    return {"status": "ok"}


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
    group: bool = Query(
        False,
        description="Agrupa IPs de la misma red /24 (mismo approval_level) en un "
                     "solo ítem de revisión -- ver response/approvals.py:group_by_subnet. "
                     "Solo cambia la vista; cada aprobación individual sigue viva y se "
                     "resuelve por su propio trace_id (ver member_trace_ids del grupo).",
    ),
    user: User = Depends(get_current_user),
):
    # Devuelve {items, total, limit, available}: el total real de la cola,
    # no solo la página (antes el panel mostraba 100 de 257 como si fueran todas).
    rdb = get_dashboard_redis()
    settings = get_response_settings()
    # ttl: oculta las vencidas aunque el barrido del worker no haya corrido
    # todavía (p. ej. con el worker caído). Solo lectura.
    page = pending_approvals_page(rdb, limit, ttl_seconds=settings.approval_ttl_seconds, group=group)
    # Marca las IPs de safelist (infra propia): el panel no ofrece aprobarlas
    # y el endpoint de resolución lo rechaza igual (ver más abajo). Para un
    # ítem de grupo, marca el grupo si CUALQUIER miembro es safelist -- el
    # panel debe forzar a desarmar el grupo y resolver esa IP aparte, no
    # ocultar que ahí hay infra propia mezclada con IPs de verdad hostiles.
    for item in page["items"]:
        if item.get("is_group"):
            for member in item.get("members", []):
                member["safelisted"] = is_safelisted(member.get("src_ip") or "", settings)
            item["safelisted"] = any(m["safelisted"] for m in item["members"])
        else:
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
    if approval["status"] == "expired" or (
        approval["status"] == "pending"
        and is_approval_expired(approval, get_response_settings().approval_ttl_seconds)
    ):
        # Vencida: nadie la decidió a tiempo. La transición a "expired" y su
        # auditoría las hace el barrido del worker; acá solo no se actúa.
        raise HTTPException(
            status_code=409,
            detail="La aprobación expiró (más de 4 h sin resolver). Si la amenaza sigue, un evento nuevo abrirá otra.",
        )
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
        # Mismo contexto que el bloqueo automático (H50): trace_id + tier
        # llegan a la alerta 651 de Wazuh. El registro de aprobación no
        # guarda classtype, así que acá no viaja ATT&CK.
        enforced, error = enforcer.block(approval["src_ip"], settings.block_ttl_seconds,
                                         ar_context(trace_id, approval.get("tier")))
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


# ── Estado de nodos (H43, N1+) ───────────────────────────────────────────────
@app.get("/api/v1/dashboard/nodes")
def dashboard_nodes(user: User = Depends(get_current_user)):
    """Salud de motor, Redis, OpenSearch, pipelines, vigilante y agentes Wazuh
    (system_status.py). Cada chequeo degrada por separado."""
    return get_node_status()


# ── Historial / auditoría (H43): N2 parcial, CISO completo ─────────────────────
@app.get("/api/v1/dashboard/audit/trace/{trace_id}")
def dashboard_audit_trace(
    trace_id: str = PathParam(..., max_length=64),
    user: User = Depends(REQUIRE_N2),
):
    """Todo lo registrado para un trace_id, con el hash de cada documento
    verificado. N2 no ve los eventos de acceso (vista parcial); CISO sí."""
    if not audit_view.valid_trace_id(trace_id):
        raise HTTPException(status_code=422, detail="trace_id inválido")
    is_ciso = user.role == "CISO"
    log_access_event(user.username, "audit_trace_viewed", {"trace_id": trace_id})
    return {**audit_view.search_trace(trace_id, include_access=is_ciso), "scope": "full" if is_ciso else "partial"}


@app.get("/api/v1/dashboard/audit/chain")
def dashboard_audit_chain(user: User = Depends(REQUIRE_N2)):
    """Verificación en vivo de la cola de las cadenas soc-responses-* y
    soc-decisions-* (audit_view.chain_status, cache 60 s)."""
    return audit_view.chain_status()


@app.get("/api/v1/dashboard/audit/access")
def dashboard_audit_access(
    limit: int = Query(100, ge=1, le=audit_view.ACCESS_EVENTS_MAX),
    username: str | None = Query(None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$"),
    user: User = Depends(require_ciso),
):
    """Eventos de acceso persistidos con hash-chain (solo CISO)."""
    return audit_view.access_events(limit, username)


# ── Gestión de usuarios y sesiones (H43, N2+; reglas en user_admin.py) ─────────
class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)
    role: Role


class UpdateUserRequest(BaseModel):
    role: Role | None = None
    disabled: bool | None = None


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


def _admin_call(fn, *args):
    """Traduce AdminError a su HTTP y Redis caído a 503 (nunca a 200 vacío)."""
    try:
        return fn(*args)
    except user_admin.AdminError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    except redis.RedisError as e:
        log.error(f"gestión de usuarios sin Redis: {e}")
        raise HTTPException(status_code=503, detail="No se pudo leer o escribir la tabla de usuarios, reintente")


@app.get("/api/v1/dashboard/users")
def dashboard_users(user: User = Depends(REQUIRE_N2)):
    return {"items": _admin_call(user_admin.list_accounts, user),
            "assignable_roles": user_admin.assignable_roles(user)}


@app.post("/api/v1/dashboard/users", status_code=201)
def dashboard_create_user(payload: CreateUserRequest, user: User = Depends(REQUIRE_N2)):
    created = _admin_call(user_admin.create_account, user, payload.username, payload.password, payload.role)
    return created.model_dump()


@app.patch("/api/v1/dashboard/users/{username}")
def dashboard_update_user(
    payload: UpdateUserRequest,
    username: str = PathParam(..., max_length=64),
    user: User = Depends(REQUIRE_N2),
):
    return _admin_call(user_admin.update_account, user, username, payload.role, payload.disabled)


@app.post("/api/v1/dashboard/users/{username}/password")
def dashboard_reset_password(
    payload: PasswordRequest,
    username: str = PathParam(..., max_length=64),
    user: User = Depends(REQUIRE_N2),
):
    return _admin_call(user_admin.reset_password, user, username, payload.password)


@app.get("/api/v1/dashboard/sessions")
def dashboard_sessions(current: tuple[User, str] = Depends(REQUIRE_N2_SESSION)):
    user, jti = current
    items = _admin_call(user_admin.visible_sessions, user)
    for item in items:
        item["is_current"] = item["is_self"] and item["jti"] == jti
    return {"items": items}


@app.delete("/api/v1/dashboard/sessions/{username}/{jti}")
def dashboard_revoke_session(
    username: str = PathParam(..., max_length=64),
    jti: str = PathParam(..., max_length=64, pattern=r"^[a-f0-9]+$"),
    current: tuple[User, str] = Depends(REQUIRE_N2_SESSION),
):
    user, current_jti = current
    return _admin_call(user_admin.revoke, user, username, jti, current_jti)


@app.delete("/api/v1/dashboard/users/{username}/sessions")
def dashboard_revoke_all_sessions(
    username: str = PathParam(..., max_length=64),
    current: tuple[User, str] = Depends(REQUIRE_N2_SESSION),
):
    user, current_jti = current
    return _admin_call(user_admin.revoke, user, username, None, current_jti)


# ── Cumplimiento y tendencias (pendiente #10, H43 — solo CISO) ───────────────
@app.get("/api/v1/dashboard/compliance")
def dashboard_compliance(
    window_minutes: int = Query(1440, ge=60, le=43_200),
    user: User = Depends(require_ciso),
):
    """Métricas de valor (sección 7, Fase 1) + checklist Ley 21.663 con la
    evidencia real de cada obligación (compliance.py). Conserva los campos
    del stub original (fatiga, latencias, precisión)."""
    nodes = get_node_status()
    return compliance.compliance_report(window_minutes, nodes["overall"])


@app.get("/api/v1/dashboard/trends")
def dashboard_trends(days: int = Query(7), user: User = Depends(require_ciso)):
    """Tiers en el tiempo, acciones ejecutadas vs. pendientes y fuentes de
    corroboración (compliance.get_trends). days: 1, 7 o 30."""
    try:
        return compliance.get_trends(days)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


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
