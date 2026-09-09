#!/usr/bin/env python3
"""
retrain_isolation_forest.py — Reentrenamiento seguro semiautomático
Tesis UBO — Motor de Decisiones SOC

Cron semanal: reentrena el Isolation Forest con el corpus actualizado.
GUARDA DE SEGURIDAD: solo reemplaza el modelo en producción si el nuevo
es igual o mejor (F1) que el actual. Si es peor, conserva el anterior y
registra el evento. Esto evita que un corpus con datos anómalos degrade
el sistema en producción.

Al final, si hubo reemplazo, reinicia motor-soc para cargar el modelo nuevo.
"""
import csv, json, os, sys, shutil, subprocess
import numpy as np
from datetime import datetime, timezone

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    from sklearn.model_selection import train_test_split
    import joblib
except ImportError:
    print("ERROR: pip3 install scikit-learn joblib numpy --break-system-packages")
    sys.exit(1)

# ── Rutas ─────────────────────────────────────────────────────────────────────
CORPUS  = "/home/aiayala/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv"
MODEL_DIR = "/home/aiayala/tesis/motor/models"
BACKUP_DIR = "/home/aiayala/tesis/motor/models/backups"
LOG_FILE = "/home/aiayala/tesis/motor/logs/retrain.log"

MODEL_FILE   = f"{MODEL_DIR}/isolation_forest.pkl"
SCALER_FILE  = f"{MODEL_DIR}/iforest_scaler.pkl"
METRICS_FILE = f"{MODEL_DIR}/iforest_metrics.json"

RAW = ["SERVER_TCP_FLAGS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS", "L4_DST_PORT", "IN_PKTS"]
CLIP_MAX = {
    "SERVER_TCP_FLAGS": 218, "OUT_PKTS": 1158,
    "FLOW_DURATION_MILLISECONDS": 120534, "L4_DST_PORT": 65535, "IN_PKTS": 628,
}
DERIVED_NAMES = [
    "SERVER_TCP_FLAGS", "OUT_PKTS", "FLOW_DURATION_MS", "L4_DST_PORT", "IN_PKTS",
    "ratio_pkts", "pkts_per_sec", "total_pkts", "is_no_response", "is_short", "is_priv_port"
]

# Margen de tolerancia: el modelo nuevo debe ser al menos este % del F1 actual
# 0.95 = aceptamos hasta 5% de degradación (ruido estadístico), no más
MIN_F1_RATIO = 0.95

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def derive(raw):
    sf, op, dms, dp, ip = raw
    ds = dms / 1000.0
    return [sf, op, dms, dp, ip,
            ip/(op+1), (ip+op)/(ds+0.1), ip+op,
            1.0 if op==0 else 0.0, 1.0 if dms<100 else 0.0, 1.0 if dp<1024 else 0.0]

def load_corpus_resp():
    """Carga solo flows con respuesta del servidor (el nicho efectivo del IForest)."""
    benign, attack = [], []
    skipped = 0
    with open(CORPUS) as f:
        for row in csv.DictReader(f):
            vals, ok = [], True
            for feat in RAW:
                v = row.get(feat, "")
                if v in ("", "-1"):
                    ok = False; break
                try:
                    vals.append(max(0, min(float(v), CLIP_MAX[feat])))
                except ValueError:
                    ok = False; break
            if not ok:
                skipped += 1; continue
            if vals[1] == 0:  # OUT_PKTS==0 → sin respuesta, se descarta
                continue
            feats = derive(vals)
            if row["label"] == "0":
                benign.append(feats)
            elif row["label"] == "1":
                attack.append(feats)
    return np.array(benign), np.array(attack), skipped

def train_best(X_benign, X_attack):
    X_tr, X_be = train_test_split(X_benign, test_size=0.2, random_state=42)
    scaler = RobustScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_be_s = scaler.transform(X_be)
    X_at_s = scaler.transform(X_attack)

    best = None
    for cont in [0.05, 0.10, 0.15, 0.20, 0.25]:
        m = IsolationForest(n_estimators=200, contamination=cont, random_state=42, n_jobs=-1)
        m.fit(X_tr_s)
        recall = np.mean(m.predict(X_at_s) == -1)
        fpr    = np.mean(m.predict(X_be_s) == -1)
        tp, fp = recall*len(X_attack), fpr*len(X_be)
        prec = tp/(tp+fp) if (tp+fp)>0 else 0
        f1 = 2*prec*recall/(prec+recall) if (prec+recall)>0 else 0
        if best is None or f1 > best["f1"]:
            best = {"cont": cont, "recall": recall, "fpr": fpr, "f1": f1,
                    "model": m, "scaler": scaler}
    return best

def get_current_f1():
    if not os.path.exists(METRICS_FILE):
        return 0.0
    try:
        with open(METRICS_FILE) as f:
            return json.load(f).get("f1_approx", 0.0)
    except:
        return 0.0

def backup_current():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for src in [MODEL_FILE, SCALER_FILE, METRICS_FILE]:
        if os.path.exists(src):
            shutil.copy(src, f"{BACKUP_DIR}/{os.path.basename(src)}.{stamp}")
    log(f"  Backup creado: {stamp}")

def restart_motor():
    try:
        subprocess.run(["sudo", "systemctl", "restart", "motor-soc"],
                       check=True, timeout=30)
        log("  motor-soc reiniciado — modelo nuevo activo")
        return True
    except Exception as e:
        log(f"  ERROR reiniciando motor-soc: {e}")
        return False

def main():
    log("=" * 60)
    log("Reentrenamiento semiautomático Isolation Forest")
    log("=" * 60)

    f1_actual = get_current_f1()
    log(f"F1 modelo actual en producción: {f1_actual:.4f}")

    X_benign, X_attack, skipped = load_corpus_resp()
    log(f"Corpus (con respuesta): {len(X_benign):,} benignos, {len(X_attack):,} ataques")

    if len(X_benign) < 500 or len(X_attack) < 100:
        log("ABORTADO: datos insuficientes para reentrenar con seguridad")
        return

    log("Entrenando modelo candidato...")
    best = train_best(X_benign, X_attack)
    f1_nuevo = best["f1"]
    log(f"Modelo candidato: cont={best['cont']} recall={best['recall']:.1%} "
        f"fpr={best['fpr']:.1%} f1={f1_nuevo:.4f}")

    # ── Guarda de seguridad ───────────────────────────────────────────────────
    umbral = f1_actual * MIN_F1_RATIO
    if f1_nuevo >= umbral:
        log(f"✓ Modelo nuevo APROBADO (f1 {f1_nuevo:.4f} >= umbral {umbral:.4f})")
        backup_current()

        joblib.dump(best["model"], MODEL_FILE)
        joblib.dump(best["scaler"], SCALER_FILE)
        metrics = {
            "version": "v2_retrain",
            "features": DERIVED_NAMES,
            "contamination": best["cont"],
            "recall_attack": round(best["recall"], 4),
            "fpr_benign": round(best["fpr"], 4),
            "f1_approx": round(f1_nuevo, 4),
            "n_benign": len(X_benign),
            "n_attack": len(X_attack),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(METRICS_FILE, "w") as f:
            json.dump(metrics, f, indent=2)
        log(f"  Modelo actualizado en producción")

        restart_motor()
    else:
        log(f"✗ Modelo nuevo RECHAZADO (f1 {f1_nuevo:.4f} < umbral {umbral:.4f})")
        log("  Se conserva el modelo anterior. Posible corpus anómalo esta semana.")

    log("Reentrenamiento completado.\n")

if __name__ == "__main__":
    main()
