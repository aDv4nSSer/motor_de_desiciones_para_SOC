from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, HTTPException, status

from api.schemas.prediction import (
    AnomalyPredictionResponse,
    FlowFeatures,
    SupervisedPredictionResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/predict", tags=["predict"])

_MODEL_VERSION = os.getenv("ML_MODEL_VERSION", "unknown")
_MODEL_PATH = os.getenv("ML_MODEL_PATH", "./models/classifier.pkl")
_SCALER_PATH = os.getenv("ML_SCALER_PATH", "./models/scaler.pkl")


def _load_supervised_model() -> Any:
    """Carga lazy del modelo supervisado desde la ruta configurada por env."""
    import joblib  # importación diferida — no requerida en tests unitarios

    if not os.path.exists(_MODEL_PATH):
        raise FileNotFoundError(f"Modelo no encontrado en: {_MODEL_PATH}")
    if not os.path.exists(_SCALER_PATH):
        raise FileNotFoundError(f"Scaler no encontrado en: {_SCALER_PATH}")

    model = joblib.load(_MODEL_PATH)
    scaler = joblib.load(_SCALER_PATH)
    return model, scaler


def _features_to_array(features: FlowFeatures) -> list[float]:
    return [
        float(features.PROTOCOL),
        float(features.L4_SRC_PORT),
        float(features.L4_DST_PORT),
        float(features.IN_BYTES),
        float(features.IN_PKTS),
        float(features.OUT_BYTES),
        float(features.OUT_PKTS),
        float(features.TCP_FLAGS),
        float(features.CLIENT_TCP_FLAGS),
        float(features.SERVER_TCP_FLAGS),
        float(features.FLOW_DURATION_MILLISECONDS),
    ]


@router.post(
    "/supervised",
    response_model=SupervisedPredictionResponse,
    summary="Clasificación supervisada de flujo de red",
    description=(
        "Recibe los 11 features del Golden Subset v4 y devuelve la clase predicha "
        "junto con la probabilidad y un alert_score normalizado."
    ),
    status_code=status.HTTP_200_OK,
)
def predict_supervised(features: FlowFeatures) -> SupervisedPredictionResponse:
    logger.info(
        "supervised_prediction_request",
        extra={
            "protocol": features.PROTOCOL,
            "src_port": features.L4_SRC_PORT,
            "dst_port": features.L4_DST_PORT,
        },
    )

    try:
        model, scaler = _load_supervised_model()
    except FileNotFoundError as exc:
        logger.error("model_load_failed", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Modelo no disponible: {exc}",
        ) from exc

    import numpy as np  # importación diferida — evita overhead en importación del módulo

    raw = np.array([_features_to_array(features)])
    scaled = scaler.transform(raw)
    proba = model.predict_proba(scaled)[0]
    class_idx: int = int(proba.argmax())
    confidence = float(proba[class_idx])
    label: str = str(model.classes_[class_idx])
    alert_score = float(1.0 - proba[0]) if proba.shape[0] > 1 else confidence

    logger.info(
        "supervised_prediction_done",
        extra={"label": label, "confidence": confidence, "alert_score": alert_score},
    )

    return SupervisedPredictionResponse(
        label=label,
        confidence=confidence,
        alert_score=alert_score,
        model_version=_MODEL_VERSION,
    )


@router.post(
    "/anomaly",
    response_model=AnomalyPredictionResponse,
    summary="Detección de anomalías en flujo de red",
    description="Endpoint reservado para el detector de anomalías no supervisado. Aún no implementado.",
    status_code=status.HTTP_200_OK,
)
def predict_anomaly(features: FlowFeatures) -> AnomalyPredictionResponse:
    logger.info(
        "anomaly_prediction_request_not_implemented",
        extra={"src_port": features.L4_SRC_PORT, "dst_port": features.L4_DST_PORT},
    )
    return AnomalyPredictionResponse(detail="not implemented")
