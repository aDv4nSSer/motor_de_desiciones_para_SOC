"""
response/schemas.py — Contratos de datos de la capa de respuesta SOAR.

Define las estructuras que viajan por la cola de respuesta y los resultados
que producen R1 (enriquecimiento pasivo) y R2 (acción activa).
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ResponseMode(str, Enum):
    """Modo de operación de la capa de respuesta activa (R2)."""
    DRY_RUN = "dry_run"   # registra lo que haría, NO bloquea (default seguro)
    ENFORCE = "enforce"   # ejecuta bloqueos reales


class ActionType(str, Enum):
    ENRICH = "enrich"          # R1
    BLOCK = "block"            # R2
    BLOCK_SKIPPED = "block_skipped"  # R2 omitido (safelist / dry_run / ya bloqueado)
    BLOCK_PENDING_APPROVAL = "block_pending_approval"  # corroboración insuficiente
    NOOP = "noop"


class ResponseTask(BaseModel):
    """
    Tarea encolada por el Fast Path para procesamiento asíncrono.
    Se serializa a la stream Redis `soc:response:tasks`.
    """
    trace_id: str
    tier: int
    risk_score: float
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int = Field(default=0, alias="L4_DST_PORT")
    classtype: str = ""
    classtype_override: bool = False
    ts: float = 0.0

    model_config = {"populate_by_name": True}


class EnrichmentResult(BaseModel):
    """Resultado de R1 — enriquecimiento pasivo de un evento."""
    src_ip: str | None = None
    reverse_dns: str | None = None
    abuseipdb_score: int | None = None        # 0-100, confidence of abuse
    abuseipdb_total_reports: int | None = None
    abuseipdb_country: str | None = None
    abuseipdb_available: bool = True             # False si la API falló / no configurada
    otx_pulse_count: int | None = None        # reportes de amenaza comunitarios (OTX pulses)
    otx_available: bool = True                   # False si la API falló / no configurada
    cached: bool = False
    notes: list[str] = Field(default_factory=list)
    # Corroboración multi-fuente (gate real de R2 — ver enrichment.py). Una
    # fuente no disponible no cuenta ni a favor ni en contra del conteo.
    corroborating_sources: list[str] = Field(default_factory=list)
    corroboration_count: int = 0
    # ── H37 Fase 3: CrowdSec, señal SOLO OBSERVACIONAL ──────────────────
    # Deliberadamente fuera de corroborating_sources/corroboration_count —
    # no hay evidencia todavía de cuánta señal nueva aporta en este entorno
    # (0 alertas agregadas en la ventana de Fase 1). Visible/auditable en
    # soc-decisions para acumular evidencia; revisar en ~5-7 días (ver
    # PLAN_SPRINTS.md) si se integra de lleno al gate, y con qué peso.
    crowdsec_observado: bool = False
    crowdsec_scenario: str | None = None
    crowdsec_duration: str | None = None


class CrowdSecDecision(BaseModel):
    """
    Una decisión individual leída del stream de CrowdSec (H37) — bouncer de
    SOLO LECTURA (r-soar-reader). No implica ninguna acción de bloqueo
    propia: es una señal más de corroboración local, del mismo tipo que
    AbuseIPDB/OTX (ver crowdsec_adapter.py). El único punto de bloqueo real
    del sistema sigue siendo R2 (Wazuh Active Response).
    """
    ip: str
    scenario: str = ""
    duration: str = ""
    decision_type: str = ""   # "ban", "captcha", etc. (campo "type" de CrowdSec)
    origin: str | None = None


class AlertMatch(BaseModel):
    """Alerta de Suricata correlacionada con un evento del worker (H53), leída
    de suricata-alerts-* (la indexa Vector; `category` trae la DESCRIPCIÓN de
    classification.config, `classtype` es el nombre corto resuelto con
    classtype_attack.yaml)."""
    category: str
    classtype: str                     # nombre corto si el mapeo lo conoce; si no, category en minúscula
    classtype_override: bool = False   # classtype en constants.T3_CLASSTYPES
    attack_mapped: bool = False        # técnica ATT&CK no nula en classtype_attack.yaml
    attack_technique_id: str | None = None
    signature: str | None = None
    signature_id: int | None = None
    severity: int | None = None
    alert_timestamp: str | None = None


class AlertLookupResult(BaseModel):
    """Resultado del lookup de correlación: `status` distingue "no hubo
    alerta" de "no se pudo consultar" para la auditoría."""
    status: str                        # "match" | "no_match" | "unavailable" | "skipped"
    match: AlertMatch | None = None


class BlockResult(BaseModel):
    """Resultado de R2 — intento de bloqueo de una IP."""
    src_ip: str | None = None
    action: ActionType = ActionType.NOOP
    enforced: bool = False        # True solo si efectivamente se bloqueó
    ttl_seconds: int = 0
    reason: str = ""              # por qué se bloqueó o por qué se omitió
    enforcer: str = ""            # qué backend ejecutó (wazuh_api / dry_run)
    error: str | None = None
    # Poblado solo cuando action == BLOCK_PENDING_APPROVAL (tabla sección 4
    # de la especificación: score alto con corroboración insuficiente).
    requires_approval: bool = False
    approval_level: str = ""      # "N1" | "N2" | "CISO" — nivel mínimo requerido


#: `accion_recomendada` — strings exactos que usa el dashboard/reporting,
#: mapeados 1:1 a los renglones de ORIGEN RED de la tabla en la sección 4 de
#: docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md. Los renglones de origen
#: HOST (FIM crítico, escalamiento de privilegios -> cuarentena) NO están
#: representados acá todavía: ResponseTask no lleva ningún campo de origen
#: porque el pendiente #3 (consulta a eventos de Wazuh por host) no está
#: integrado — no hay ningún evento real que hoy llegue por esa vía. Agregar
#: ese renglón sin la señal real detrás sería fabricar una acción sobre datos
#: que no existen. Mismo criterio para "rate_limiting": la tabla lo reserva
#: para "ataque volumétrico sostenido", y hoy no se calcula ninguna señal de
#: sostenido en el tiempo (todo el scoring es por-flujo) — se deja fuera
#: deliberadamente hasta diseñar esa señal con evidencia, no a las apuradas.
ACCION_NINGUNA = "ninguna"
#: T2 cuyo origen es infraestructura propia del SOC (config.OWN_INFRA, H54):
#: se registra y se explica, pero no abre caso. Distinto de ACCION_NINGUNA
#: para poder medir en el dashboard cuánto ruido interno se descarta.
ACCION_NINGUNA_INFRA_PROPIA = "ninguna_infra_propia"
ACCION_ALERTAR_CREAR_CASO = "alertar_crear_caso"
ACCION_BLOQUEO_IP = "bloqueo_ip"
ACCION_ALERTAR_PENDIENTE_APROBACION = "alertar_pendiente_aprobacion"


class ResponseRecord(BaseModel):
    """Registro de auditoría completo de una respuesta (R1 + R2)."""
    trace_id: str
    tier: int
    risk_score: float
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int = 0
    enrichment: EnrichmentResult | None = None
    block: BlockResult | None = None
    # Acción recomendada según tabla sección 4 de la especificación —
    # ver constantes ACCION_* arriba. "" si el evento no llegó a evaluarse
    # (tier < r1_min_tier, no pasa por el worker de respuesta en absoluto).
    accion_recomendada: str = ""
    # Poblado cuando accion_recomendada == ACCION_ALERTAR_CREAR_CASO —
    # referencia al caso abierto en soc:cases: (mismo esquema que
    # vigilante/cases.py, ver response/cases.py).
    case_id: str | None = None
    # rules_fired[]/reasoning[]/rules_total_weight: motor de reglas
    # declarativo (rules/engine.py sobre rules.yaml) -- EXPLICA la decisión
    # de arriba (tier, block, accion_recomendada) con las mismas señales ya
    # calculadas, no la cambia. Listas vacías si tier < 2 (no se evalúa,
    # ver worker.py:_rule_context) o si rules.yaml no cargó (degradación
    # con gracia: la decisión real sigue firme aunque falte la explicación).
    rules_fired: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)
    rules_total_weight: float = 0.0
    # corroboration_*: score de corroboración ponderado (scoring/
    # corroboration.py) en MODO SOMBRA -- se calcula para T2+ y se audita
    # junto al gate real (enrichment.corroboration_count), pero NO decide
    # nada: R2 no lo lee. Defaults si tier < 2 o si el cálculo falló
    # (degradación con gracia). Ver H52 en docs/BITACORA_TECNICA.md.
    corroboration_score: float = 0.0
    corroboration_band: str = ""
    corroboration_ambiguous: bool = False
    corroboration_groups: list[dict] = Field(default_factory=list)  # GroupScore.model_dump()
    # Insumos de los grupos signature/context (H53, también modo sombra):
    # alert_lookup = "match" | "no_match" | "unavailable" | "skipped" (""
    # si no se intentó); correlated_alert = AlertMatch.model_dump() si hubo
    # match; recidivism_count = horas previas con T2+ en 30d (None = sin dato).
    alert_lookup: str = ""
    correlated_alert: dict | None = None
    recidivism_count: int | None = None
    processed_at: float = 0.0
    # Segundos entre la detección (task.ts) y el inicio del procesamiento.
    # None si la tarea no trae marca de tiempo (ver worker.process_task).
    event_age_seconds: float | None = None
    worker: str = "response_worker"

    def to_audit_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
