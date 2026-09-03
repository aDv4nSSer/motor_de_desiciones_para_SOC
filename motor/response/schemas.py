"""
response/schemas.py — Contratos de datos de la capa de respuesta SOAR.

Define las estructuras que viajan por la cola de respuesta y los resultados
que producen R1 (enriquecimiento pasivo) y R2 (acción activa).
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ResponseMode(str, Enum):
    """Modo de operación de la capa de respuesta activa (R2)."""
    DRY_RUN = "dry_run"   # registra lo que haría, NO bloquea (default seguro)
    ENFORCE = "enforce"   # ejecuta bloqueos reales


class ActionType(str, Enum):
    ENRICH = "enrich"          # R1
    BLOCK = "block"            # R2
    BLOCK_SKIPPED = "block_skipped"  # R2 omitido (safelist / dry_run / ya bloqueado)
    NOOP = "noop"


class ResponseTask(BaseModel):
    """
    Tarea encolada por el Fast Path para procesamiento asíncrono.
    Se serializa a la stream Redis `soc:response:tasks`.
    """
    trace_id: str
    tier: int
    risk_score: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: int = Field(default=0, alias="L4_DST_PORT")
    classtype: str = ""
    classtype_override: bool = False
    ts: float = 0.0

    model_config = {"populate_by_name": True}


class EnrichmentResult(BaseModel):
    """Resultado de R1 — enriquecimiento pasivo de un evento."""
    src_ip: Optional[str] = None
    reverse_dns: Optional[str] = None
    abuseipdb_score: Optional[int] = None        # 0-100, confidence of abuse
    abuseipdb_total_reports: Optional[int] = None
    abuseipdb_country: Optional[str] = None
    abuseipdb_available: bool = True             # False si la API falló / no configurada
    otx_pulse_count: Optional[int] = None        # reportes de amenaza comunitarios (OTX pulses)
    otx_available: bool = True                   # False si la API falló / no configurada
    cached: bool = False
    notes: list[str] = Field(default_factory=list)


class BlockResult(BaseModel):
    """Resultado de R2 — intento de bloqueo de una IP."""
    src_ip: Optional[str] = None
    action: ActionType = ActionType.NOOP
    enforced: bool = False        # True solo si efectivamente se bloqueó
    ttl_seconds: int = 0
    reason: str = ""              # por qué se bloqueó o por qué se omitió
    enforcer: str = ""            # qué backend ejecutó (wazuh_api / dry_run)
    error: Optional[str] = None


class ResponseRecord(BaseModel):
    """Registro de auditoría completo de una respuesta (R1 + R2)."""
    trace_id: str
    tier: int
    risk_score: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: int = 0
    enrichment: Optional[EnrichmentResult] = None
    block: Optional[BlockResult] = None
    processed_at: float = 0.0
    worker: str = "response_worker"

    def to_audit_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
