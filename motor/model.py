"""
model.py — Cargador y wrapper del modelo ML del motor SOC
Soporta: modelo real de Joaquín (LightGBM) o placeholder para desarrollo.
"""
import os, json, logging, numpy as np
from pathlib import Path

log = logging.getLogger("motor.model")

MODEL_DIR    = Path(os.environ.get("MODEL_DIR", "/home/aiayala/tesis/motor/models"))
MODEL_FILE   = MODEL_DIR / "model_golden4_v7_1_latest.pkl"
IFOREST_FILE = MODEL_DIR / "isolation_forest.pkl"
THRESH_FILE  = MODEL_DIR / "thresholds_v6_latest.json"

# Thresholds por defecto (se sobreescriben con thresholds_v6_latest.json)
DEFAULT_THRESHOLDS = {
    "T0_max": 0.25,
    "T1_max": 0.55,
    "T2_max": 0.80,
}

# Puertos conocidos de alto riesgo para el placeholder
HIGH_RISK_PORTS  = {22, 23, 3389, 5900, 445, 135, 139, 1433, 3306, 6379}
MED_RISK_PORTS   = {80, 443, 8080, 8443, 21, 25, 110, 143, 2222}

class MotorModel:
    def __init__(self):
        self.lgbm         = None
        self.iforest      = None
        self.thresholds   = DEFAULT_THRESHOLDS
        self.model_version = "placeholder_v0"
        self._load()

    def _load(self):
        import joblib
        # Intentar cargar modelo LightGBM real
        if MODEL_FILE.exists():
            try:
                self.lgbm = joblib.load(MODEL_FILE)
                self.model_version = "golden4_v7_1"
                log.info(f"LightGBM cargado: {MODEL_FILE}")
            except Exception as e:
                log.warning(f"No se pudo cargar LightGBM: {e}")

        # Intentar cargar Isolation Forest
        if IFOREST_FILE.exists():
            try:
                self.iforest = joblib.load(IFOREST_FILE)
                log.info(f"IsolationForest cargado: {IFOREST_FILE}")
            except Exception as e:
                log.warning(f"No se pudo cargar IForest: {e}")

        # Thresholds
        if THRESH_FILE.exists():
            with open(THRESH_FILE) as f:
                self.thresholds = json.load(f)
            log.info(f"Thresholds cargados: {THRESH_FILE}")

        if not self.lgbm:
            log.warning("Usando modelo PLACEHOLDER — reemplazar con modelo de Joaquín")

    def _features_array(self, features: dict) -> np.ndarray:
        """Extrae exactamente los 4 features del Golden 4 en orden correcto"""
        return np.array([[
            features.get("SERVER_TCP_FLAGS", 0),
            features.get("OUT_PKTS", 0),
            features.get("FLOW_DURATION_MILLISECONDS", 0),
            features.get("L4_DST_PORT", 0),
        ]], dtype=np.float32)

    def _placeholder_score(self, features: dict) -> float:
        """
        Score heurístico mientras no hay modelo real.
        Basado en comportamiento del flujo, NO en IP.
        """
        port     = features.get("L4_DST_PORT", 0)
        out_pkts = features.get("OUT_PKTS", 0)
        duration = features.get("FLOW_DURATION_MILLISECONDS", 0)
        flags    = features.get("SERVER_TCP_FLAGS", 0)

        score = 0.1  # base benigno

        # Puerto de alto riesgo sin respuesta del servidor
        if port in HIGH_RISK_PORTS and out_pkts == 0:
            score += 0.50

        # Puerto de riesgo medio
        elif port in MED_RISK_PORTS and out_pkts == 0:
            score += 0.20

        # Muchos paquetes salientes (ataque web / exfiltración)
        if out_pkts > 100:
            score += 0.15

        # TCP flags sospechosos (SYN flood, RST scan)
        if flags in (2, 4, 6):  # SYN, RST, SYN+RST
            score += 0.15

        # Flujo muy corto a puertos críticos (scan)
        if duration < 100 and port in HIGH_RISK_PORTS:
            score += 0.20

        return min(score, 0.99)

    def predict(self, features: dict) -> dict:
        """
        Retorna: {ml_score, anomaly_score, risk_score}
        """
        X = self._features_array(features)

        # Score ML
        if self.lgbm is not None:
            try:
                ml_score = float(self.lgbm.predict_proba(X)[0][1])
            except Exception:
                ml_score = self._placeholder_score(features)
        else:
            ml_score = self._placeholder_score(features)

        # Score anomalía (Isolation Forest)
        if self.iforest is not None:
            try:
                # score_samples: más negativo = más anómalo
                raw = self.iforest.score_samples(X)[0]
                # Normalizar a [0,1]: -0.5 (muy anómalo) → 1.0, 0.0 (normal) → 0.0
                anomaly_score = float(np.clip(1.0 - (raw + 0.5) / 0.5, 0.0, 1.0))
            except Exception:
                anomaly_score = ml_score * 0.8
        else:
            anomaly_score = ml_score * 0.8

        # Score final combinado (70% ML, 30% IForest)
        risk_score = 0.70 * ml_score + 0.30 * anomaly_score

        return {
            "ml_score":      round(ml_score, 4),
            "anomaly_score": round(anomaly_score, 4),
            "risk_score":    round(risk_score, 4),
        }

    def tier(self, risk_score: float) -> int:
        """Asigna tier T0-T3 usando thresholds calibrados"""
        if risk_score <= self.thresholds.get("T0_max", 0.25):
            return 0
        elif risk_score <= self.thresholds.get("T1_max", 0.55):
            return 1
        elif risk_score <= self.thresholds.get("T2_max", 0.80):
            return 2
        else:
            return 3

# Singleton
_model = None

def get_model() -> MotorModel:
    global _model
    if _model is None:
        _model = MotorModel()
    return _model
