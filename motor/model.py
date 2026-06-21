"""
model.py — Cargador y wrapper del modelo ML del motor SOC
Soporta: modelo real de Joaquín (LightGBM) + Isolation Forest (anomalías) o placeholder.

CORRECCIÓN v2: el Isolation Forest ahora aplica correctamente el scaler y las
features derivadas, igual que en el entrenamiento (train_isolation_forest_v2.py).
"""
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.isotonic import IsotonicRegression


class CalibratedLightGBM(BaseEstimator, ClassifierMixin):
    """Wrapper LightGBM + calibrador isotonico.
    Debe estar definida ANTES de joblib.load() para que el .pkl deserialice correctamente.
    """
    def __init__(self, base_model=None, calibrator=None):
        self.base_model = base_model
        self.calibrator = calibrator

    def fit(self, X, y):
        return self

    def predict_proba(self, X):
        raw = self.base_model.predict_proba(X)[:, 1]
        if self.calibrator is not None:
            cal = np.clip(self.calibrator.predict(raw), 0.0, 1.0)
        else:
            cal = raw
        return np.column_stack([1 - cal, cal])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


import os, json, logging, sys
import numpy as np
from pathlib import Path

log = logging.getLogger("motor.model")

MODEL_DIR    = Path(os.environ.get("MODEL_DIR", "/home/aiayala/tesis/motor/models"))
MODEL_FILE   = MODEL_DIR / "model_golden4_v7_1_latest.pkl"
IFOREST_FILE = MODEL_DIR / "isolation_forest.pkl"
SCALER_FILE  = MODEL_DIR / "iforest_scaler.pkl"
THRESH_FILE  = MODEL_DIR / "thresholds_v6_latest.json"

DEFAULT_THRESHOLDS = {"T0_max": 0.25, "T1_max": 0.55, "T2_max": 0.80}

HIGH_RISK_PORTS = {22, 23, 3389, 5900, 445, 135, 139, 1433, 3306, 6379}
MED_RISK_PORTS  = {80, 443, 8080, 8443, 21, 25, 110, 143, 2222}

# Límites del contrato (deben coincidir con el entrenamiento)
CLIP_MAX = {
    "SERVER_TCP_FLAGS": 218, "OUT_PKTS": 1158,
    "FLOW_DURATION_MILLISECONDS": 120534, "L4_DST_PORT": 65535, "IN_PKTS": 628,
}

# Registrar CalibratedLightGBM en __main__ para que joblib pueda deserializar
import __main__
__main__.CalibratedLightGBM = CalibratedLightGBM

class MotorModel:
    def __init__(self):
        self.lgbm          = None
        self.iforest       = None
        self.iforest_scaler = None
        self.thresholds    = DEFAULT_THRESHOLDS
        self.model_version = "placeholder_v0"
        self._load()

    def _load(self):
        import joblib
        if MODEL_FILE.exists():
            try:
                self.lgbm = joblib.load(MODEL_FILE)
                self.model_version = "golden4_v7_1"
                log.info(f"LightGBM cargado: {MODEL_FILE}")
            except Exception as e:
                log.warning(f"No se pudo cargar LightGBM: {e}")

        if IFOREST_FILE.exists():
            try:
                self.iforest = joblib.load(IFOREST_FILE)
                log.info(f"IsolationForest cargado: {IFOREST_FILE}")
            except Exception as e:
                log.warning(f"No se pudo cargar IForest: {e}")

        # Scaler del Isolation Forest (CRÍTICO: sin esto el iforest da basura)
        if SCALER_FILE.exists():
            try:
                self.iforest_scaler = joblib.load(SCALER_FILE)
                log.info(f"IForest scaler cargado: {SCALER_FILE}")
            except Exception as e:
                log.warning(f"No se pudo cargar scaler: {e}")

        if THRESH_FILE.exists():
            with open(THRESH_FILE) as f:
                self.thresholds = json.load(f)
            log.info(f"Thresholds cargados: {THRESH_FILE}")

        if not self.lgbm:
            log.warning("Usando modelo PLACEHOLDER — reemplazar con modelo de Joaquín")

    def _features_lgbm(self, f: dict) -> np.ndarray:
        """4 Golden features en orden para LightGBM."""
        return np.array([[
            f.get("SERVER_TCP_FLAGS", 0),
            f.get("OUT_PKTS", 0),
            f.get("FLOW_DURATION_MILLISECONDS", 0),
            f.get("L4_DST_PORT", 0),
        ]], dtype=np.float32)

    def _features_iforest(self, f: dict) -> np.ndarray:
        """
        11 features derivadas para el Isolation Forest, en el MISMO orden y con
        el MISMO cálculo que train_isolation_forest_v2.py.
        """
        sf = min(max(f.get("SERVER_TCP_FLAGS", 0), 0), CLIP_MAX["SERVER_TCP_FLAGS"])
        op = min(max(f.get("OUT_PKTS", 0), 0), CLIP_MAX["OUT_PKTS"])
        dms = min(max(f.get("FLOW_DURATION_MILLISECONDS", 0), 0), CLIP_MAX["FLOW_DURATION_MILLISECONDS"])
        dp = min(max(f.get("L4_DST_PORT", 0), 0), CLIP_MAX["L4_DST_PORT"])
        ip = min(max(f.get("IN_PKTS", 0), 0), CLIP_MAX["IN_PKTS"])
        ds = dms / 1000.0

        derived = [
            sf, op, dms, dp, ip,
            ip / (op + 1),                  # ratio_pkts
            (ip + op) / (ds + 0.1),         # pkts_per_sec
            ip + op,                        # total_pkts
            1.0 if op == 0 else 0.0,        # is_no_response
            1.0 if dms < 100 else 0.0,      # is_short
            1.0 if dp < 1024 else 0.0,      # is_priv_port
        ]
        return np.array([derived], dtype=np.float32)

    def _placeholder_score(self, f: dict) -> float:
        port = f.get("L4_DST_PORT", 0)
        out_pkts = f.get("OUT_PKTS", 0)
        duration = f.get("FLOW_DURATION_MILLISECONDS", 0)
        flags = f.get("SERVER_TCP_FLAGS", 0)
        score = 0.1
        if port in HIGH_RISK_PORTS and out_pkts == 0:
            score += 0.50
        elif port in MED_RISK_PORTS and out_pkts == 0:
            score += 0.20
        if out_pkts > 100:
            score += 0.15
        if flags in (2, 4, 6):
            score += 0.15
        if duration < 100 and port in HIGH_RISK_PORTS:
            score += 0.20
        return min(score, 0.99)

    def predict(self, features: dict) -> dict:
        # ── Score ML (LightGBM o placeholder) ──
        if self.lgbm is not None:
            try:
                X = self._features_lgbm(features)
                ml_score = float(self.lgbm.predict_proba(X)[0][1])
            except Exception:
                ml_score = self._placeholder_score(features)
        else:
            ml_score = self._placeholder_score(features)

        # ── Score anomalía (Isolation Forest con scaler + derivadas) ──
        anomaly_score = ml_score * 0.8  # fallback
        if self.iforest is not None and self.iforest_scaler is not None:
            try:
                Xi = self._features_iforest(features)
                Xi_scaled = self.iforest_scaler.transform(Xi)
                raw = self.iforest.score_samples(Xi_scaled)[0]
                # score_samples: más negativo = más anómalo
                # Normalizar: típico rango [-0.7, -0.4]; mapear a [0,1]
                anomaly_score = float(np.clip((-raw - 0.4) / 0.3, 0.0, 1.0))
            except Exception as e:
                log.debug(f"IForest fallback: {e}")

        risk_score = 0.70 * ml_score + 0.30 * anomaly_score

        return {
            "ml_score":      round(ml_score, 4),
            "anomaly_score": round(anomaly_score, 4),
            "risk_score":    round(risk_score, 4),
        }

    def tier(self, risk_score: float) -> int:
        if risk_score <= self.thresholds.get("T0_max", 0.25):
            return 0
        elif risk_score <= self.thresholds.get("T1_max", 0.55):
            return 1
        elif risk_score <= self.thresholds.get("T2_max", 0.80):
            return 2
        return 3

_model = None

def get_model() -> MotorModel:
    global _model
    if _model is None:
        _model = MotorModel()
    return _model
