from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class FlowFeatures(BaseModel):
    """Golden Subset v4 — 11 features extraídas del pipeline de ingesta."""

    PROTOCOL: int = Field(..., ge=0, le=255, description="Número de protocolo IP (6=TCP, 17=UDP, 1=ICMP)")
    L4_SRC_PORT: int = Field(..., ge=0, le=65535, description="Puerto origen L4")
    L4_DST_PORT: int = Field(..., ge=0, le=65535, description="Puerto destino L4")
    IN_BYTES: int = Field(..., ge=0, description="Bytes entrantes del flujo")
    IN_PKTS: int = Field(..., ge=0, description="Paquetes entrantes del flujo")
    OUT_BYTES: int = Field(..., ge=0, description="Bytes salientes del flujo")
    OUT_PKTS: int = Field(..., ge=0, description="Paquetes salientes del flujo")
    TCP_FLAGS: int = Field(..., ge=0, description="Flags TCP combinados del flujo")
    CLIENT_TCP_FLAGS: int = Field(..., ge=0, description="Flags TCP del cliente")
    SERVER_TCP_FLAGS: int = Field(..., ge=0, description="Flags TCP del servidor")
    FLOW_DURATION_MILLISECONDS: int = Field(..., ge=0, description="Duración del flujo en milisegundos")

    model_config = {"json_schema_extra": {
        "example": {
            "PROTOCOL": 6,
            "L4_SRC_PORT": 52341,
            "L4_DST_PORT": 443,
            "IN_BYTES": 1400,
            "IN_PKTS": 10,
            "OUT_BYTES": 800,
            "OUT_PKTS": 8,
            "TCP_FLAGS": 27,
            "CLIENT_TCP_FLAGS": 27,
            "SERVER_TCP_FLAGS": 18,
            "FLOW_DURATION_MILLISECONDS": 350,
        }
    }}


class SupervisedPredictionResponse(BaseModel):
    label: str = Field(..., description="Clase predicha por el modelo supervisado")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Probabilidad de la clase predicha")
    alert_score: float = Field(..., ge=0.0, le=1.0, description="Score de riesgo normalizado [0, 1]")
    model_version: Optional[str] = Field(None, description="Versión o hash del modelo cargado")

    model_config = {"json_schema_extra": {
        "example": {
            "label": "DDoS",
            "confidence": 0.97,
            "alert_score": 0.91,
            "model_version": "v1.0.0",
        }
    }}


class AnomalyPredictionResponse(BaseModel):
    detail: str = Field(..., description="Resultado del detector de anomalías")

    model_config = {"json_schema_extra": {
        "example": {"detail": "not implemented"}
    }}
