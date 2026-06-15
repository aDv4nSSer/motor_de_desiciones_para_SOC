from pydantic import BaseModel, Field
from typing import Optional
from enum import IntEnum

class RiskTier(IntEnum):
    T0 = 0  # Benigno — sin acción
    T1 = 1  # Bajo — registrar
    T2 = 2  # Medio — alerta analista
    T3 = 3  # Crítico — respuesta inmediata

class FlowFeatures(BaseModel):
    """Features del Golden 4 que Vector envía desde Suricata"""
    SERVER_TCP_FLAGS:          int   = Field(0,  ge=0, le=218)
    OUT_PKTS:                  int   = Field(0,  ge=0, le=1158)
    FLOW_DURATION_MILLISECONDS: int  = Field(0,  ge=0, le=120534)
    L4_DST_PORT:               int   = Field(0,  ge=0, le=65535)
    # Campos extra de Vector (no usados por el modelo, sí por contexto)
    PROTOCOL:                  Optional[int] = None
    L4_SRC_PORT:               Optional[int] = None
    IN_BYTES:                  Optional[int] = None
    IN_PKTS:                   Optional[int] = None
    OUT_BYTES:                 Optional[int] = None
    TCP_FLAGS:                 Optional[int] = None
    CLIENT_TCP_FLAGS:          Optional[int] = None

class DecisionResponse(BaseModel):
    """Respuesta del motor de decisiones"""
    trace_id:         str
    tier:             int           # T0-T3
    tier_name:        str           # "T0_BENIGNO", "T3_CRITICO", etc.
    risk_score:       float         # 0.0 - 1.0 (calibrado)
    anomaly_score:    float         # Isolation Forest
    ml_score:         float         # LightGBM
    decision:         str           # "ALLOW", "LOG", "ALERT", "BLOCK"
    classtype_override: bool        # Si Suricata forzó T3
    model_version:    str
    features_used: dict
