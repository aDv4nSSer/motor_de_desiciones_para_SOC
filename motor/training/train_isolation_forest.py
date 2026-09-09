#!/usr/bin/env python3
"""
train_isolation_forest.py — Entrenamiento robusto del detector de anomalías
Tesis UBO — Motor de Decisiones SOC

PRINCIPIO CLAVE: El Isolation Forest se entrena SOLO con tráfico benigno.
Aprende la frontera de lo "normal". Los ataques se detectan como desviaciones.

Validación incorporada: mide recall real contra ataques conocidos del corpus
y false positive rate sobre tráfico benigno held-out.
"""
import csv, json, os, sys
import numpy as np
from datetime import datetime, timezone

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    from sklearn.model_selection import train_test_split
    import joblib
except ImportError:
    print("ERROR: instalar dependencias:")
    print("  pip3 install scikit-learn joblib numpy --break-system-packages")
    sys.exit(1)

# ── Configuración ─────────────────────────────────────────────────────────────
CORPUS = "/home/aiayala/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv"
OUT_DIR = "/home/aiayala/tesis/motor/models"

# Features para el Isolation Forest
# 4 Golden + IN_PKTS (relación cliente/servidor revela anomalías)
FEATURES = [
    "SERVER_TCP_FLAGS",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
    "L4_DST_PORT",
    "IN_PKTS",
]

# Límites de saneamiento (del contrato Vector)
CLIP_MAX = {
    "SERVER_TCP_FLAGS": 218,
    "OUT_PKTS": 1158,
    "FLOW_DURATION_MILLISECONDS": 120534,
    "L4_DST_PORT": 65535,
    "IN_PKTS": 628,
}

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

# ── Carga y saneamiento ───────────────────────────────────────────────────────
def load_corpus():
    log(f"Cargando corpus: {CORPUS}")
    X_benign, X_attack = [], []
    skipped = 0

    with open(CORPUS) as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Saltar flows con features faltantes
            valid = True
            features = []
            for feat in FEATURES:
                v = row.get(feat, "")
                if v in ("", "-1"):
                    valid = False
                    break
                try:
                    val = float(v)
                    # Clip a límites del contrato
                    val = min(val, CLIP_MAX[feat])
                    val = max(val, 0)
                    features.append(val)
                except ValueError:
                    valid = False
                    break

            if not valid:
                skipped += 1
                continue

            if row["label"] == "0":
                X_benign.append(features)
            elif row["label"] == "1":
                X_attack.append(features)

    log(f"  Benignos válidos : {len(X_benign):,}")
    log(f"  Ataques válidos  : {len(X_attack):,}")
    log(f"  Saltados (NaN)   : {skipped:,}")

    return np.array(X_benign), np.array(X_attack)

# ── Entrenamiento con validación ──────────────────────────────────────────────
def train_and_validate(X_benign, X_attack):
    # Split benigno: 80% entrena, 20% valida (mide false positive rate)
    X_train, X_benign_test = train_test_split(
        X_benign, test_size=0.2, random_state=42
    )
    log(f"\nEntrenamiento: {len(X_train):,} benignos")
    log(f"Validación benigna: {len(X_benign_test):,} benignos")
    log(f"Validación ataque : {len(X_attack):,} ataques")

    # Escalado robusto (resistente a outliers)
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_benign_test_scaled = scaler.transform(X_benign_test)
    X_attack_scaled = scaler.transform(X_attack)

    # Probar varios valores de contaminación
    log("\n── Calibración de contaminación ──")
    log(f"{'cont':>6} {'recall_atk':>11} {'fpr_benign':>11} {'f1_aprox':>9}")

    resultados = []
    for contamination in [0.05, 0.10, 0.15, 0.20, 0.25]:
        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train_scaled)

        # predict: -1 = anomalía, 1 = normal
        pred_attack = model.predict(X_attack_scaled)
        pred_benign = model.predict(X_benign_test_scaled)

        # Recall: % de ataques detectados como anomalía
        recall = np.mean(pred_attack == -1)
        # FPR: % de benignos marcados como anomalía (falsos positivos)
        fpr = np.mean(pred_benign == -1)

        # F1 aproximado (precisión estimada vs recall)
        tp = recall * len(X_attack)
        fp = fpr * len(X_benign_test)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        log(f"{contamination:>6.2f} {recall:>10.1%} {fpr:>10.1%} {f1:>9.3f}")
        resultados.append((contamination, recall, fpr, f1, model))

    # Elegir el de mejor F1
    mejor = max(resultados, key=lambda x: x[3])
    log(f"\n✓ Mejor contaminación: {mejor[0]} (F1={mejor[3]:.3f}, recall={mejor[1]:.1%}, fpr={mejor[2]:.1%})")

    return mejor[4], scaler, {
        "contamination": mejor[0],
        "recall_attack": round(mejor[1], 4),
        "fpr_benign": round(mejor[2], 4),
        "f1_approx": round(mejor[3], 4),
        "features": FEATURES,
        "n_train": len(X_train),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("=" * 60)
    log("Entrenamiento Isolation Forest — Detector de Anomalías SOC")
    log("=" * 60)

    X_benign, X_attack = load_corpus()

    if len(X_benign) < 1000:
        log("ERROR: insuficientes datos benignos para entrenar")
        sys.exit(1)

    model, scaler, metrics = train_and_validate(X_benign, X_attack)

    # Guardar modelo + scaler + métricas
    os.makedirs(OUT_DIR, exist_ok=True)
    joblib.dump(model, f"{OUT_DIR}/isolation_forest.pkl")
    joblib.dump(scaler, f"{OUT_DIR}/iforest_scaler.pkl")
    with open(f"{OUT_DIR}/iforest_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    log(f"\n✓ Modelo guardado: {OUT_DIR}/isolation_forest.pkl")
    log(f"✓ Scaler guardado: {OUT_DIR}/iforest_scaler.pkl")
    log(f"✓ Métricas: {OUT_DIR}/iforest_metrics.json")
    log("\nResumen de validación:")
    log(f"  Detecta {metrics['recall_attack']:.1%} de ataques conocidos como anomalía")
    log(f"  Falsos positivos sobre benigno: {metrics['fpr_benign']:.1%}")

if __name__ == "__main__":
    main()
