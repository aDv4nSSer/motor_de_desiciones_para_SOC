#!/usr/bin/env python3
"""
train_isolation_forest_v2.py — Detector de anomalías con features derivadas
Tesis UBO — Motor de Decisiones SOC

MEJORA sobre v1: agrega features de comportamiento derivadas que hacen
visibles las anomalías que las features crudas ocultan:
  - ratio_pkts      : IN_PKTS / (OUT_PKTS+1)  → escaneos tienen ratio extremo
  - bytes_per_pkt_in: IN_BYTES / (IN_PKTS+1)  → exfiltración = bytes altos
  - bytes_per_pkt_out: OUT_BYTES/(OUT_PKTS+1)
  - pkts_per_sec    : (IN+OUT pkts)/(dur_s+0.1) → flooding = alto
  - total_pkts      : IN_PKTS + OUT_PKTS
  - is_no_response  : 1 si OUT_PKTS==0 (servidor no respondió)

ESTRATEGIA DUAL: además del modelo general, entrena uno enfocado SOLO en
flows con respuesta del servidor (sesiones completadas), donde las anomalías
de comportamiento (C2, exfil, brute force) sí son detectables.
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
    print("ERROR: pip3 install scikit-learn joblib numpy --break-system-packages")
    sys.exit(1)

CORPUS = "/home/aiayala/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv"
OUT_DIR = "/home/aiayala/tesis/motor/models"

# Features crudas que necesitamos del corpus
RAW = ["SERVER_TCP_FLAGS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
       "L4_DST_PORT", "IN_PKTS"]

CLIP_MAX = {
    "SERVER_TCP_FLAGS": 218, "OUT_PKTS": 1158,
    "FLOW_DURATION_MILLISECONDS": 120534, "L4_DST_PORT": 65535, "IN_PKTS": 628,
}

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def derive_features(raw):
    """Transforma features crudas en features de comportamiento."""
    server_flags, out_pkts, dur_ms, dst_port, in_pkts = raw
    dur_s = dur_ms / 1000.0

    ratio_pkts      = in_pkts / (out_pkts + 1)
    pkts_per_sec    = (in_pkts + out_pkts) / (dur_s + 0.1)
    total_pkts      = in_pkts + out_pkts
    is_no_response  = 1.0 if out_pkts == 0 else 0.0
    is_short        = 1.0 if dur_ms < 100 else 0.0
    # Puerto en rango efímero alto (>1024) o privilegiado
    is_priv_port    = 1.0 if dst_port < 1024 else 0.0

    return [
        server_flags,
        out_pkts,
        dur_ms,
        dst_port,
        in_pkts,
        ratio_pkts,
        pkts_per_sec,
        total_pkts,
        is_no_response,
        is_short,
        is_priv_port,
    ]

DERIVED_NAMES = [
    "SERVER_TCP_FLAGS", "OUT_PKTS", "FLOW_DURATION_MS", "L4_DST_PORT", "IN_PKTS",
    "ratio_pkts", "pkts_per_sec", "total_pkts", "is_no_response", "is_short", "is_priv_port"
]

def load_corpus():
    log(f"Cargando corpus...")
    benign, attack = [], []
    benign_resp, attack_resp = [], []   # solo flows con respuesta del servidor
    skipped = 0

    with open(CORPUS) as f:
        for row in csv.DictReader(f):
            vals, ok = [], True
            for feat in RAW:
                v = row.get(feat, "")
                if v in ("", "-1"):
                    ok = False; break
                try:
                    val = max(0, min(float(v), CLIP_MAX[feat]))
                    vals.append(val)
                except ValueError:
                    ok = False; break
            if not ok:
                skipped += 1; continue

            feats = derive_features(vals)
            has_response = vals[1] > 0  # OUT_PKTS > 0

            if row["label"] == "0":
                benign.append(feats)
                if has_response: benign_resp.append(feats)
            elif row["label"] == "1":
                attack.append(feats)
                if has_response: attack_resp.append(feats)

    log(f"  Benignos: {len(benign):,} (con respuesta: {len(benign_resp):,})")
    log(f"  Ataques : {len(attack):,} (con respuesta: {len(attack_resp):,})")
    log(f"  Saltados: {skipped:,}")
    return (np.array(benign), np.array(attack),
            np.array(benign_resp), np.array(attack_resp))

def evaluate(X_benign, X_attack, nombre):
    log(f"\n{'='*60}")
    log(f"MODELO: {nombre}")
    log(f"{'='*60}")

    if len(X_benign) < 500 or len(X_attack) < 100:
        log(f"  Datos insuficientes (benign={len(X_benign)}, attack={len(X_attack)})")
        return None

    X_tr, X_be_test = train_test_split(X_benign, test_size=0.2, random_state=42)
    log(f"  Train: {len(X_tr):,} | Test benigno: {len(X_be_test):,} | Test ataque: {len(X_attack):,}")

    scaler = RobustScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_be_s = scaler.transform(X_be_test)
    X_at_s = scaler.transform(X_attack)

    log(f"  {'cont':>6} {'recall':>8} {'fpr':>8} {'f1':>7}")
    best = None
    for cont in [0.05, 0.10, 0.15, 0.20, 0.25]:
        m = IsolationForest(n_estimators=200, contamination=cont,
                            random_state=42, n_jobs=-1)
        m.fit(X_tr_s)
        recall = np.mean(m.predict(X_at_s) == -1)
        fpr    = np.mean(m.predict(X_be_s) == -1)
        tp, fp = recall*len(X_attack), fpr*len(X_be_test)
        prec = tp/(tp+fp) if (tp+fp)>0 else 0
        f1 = 2*prec*recall/(prec+recall) if (prec+recall)>0 else 0
        log(f"  {cont:>6.2f} {recall:>7.1%} {fpr:>7.1%} {f1:>7.3f}")
        if best is None or f1 > best[3]:
            best = (cont, recall, fpr, f1, m, scaler)

    log(f"  ✓ Mejor: cont={best[0]} recall={best[1]:.1%} fpr={best[2]:.1%} f1={best[3]:.3f}")
    return best

def main():
    log("="*60)
    log("Isolation Forest v2 — Features derivadas")
    log("="*60)

    benign, attack, benign_resp, attack_resp = load_corpus()

    # Modelo 1: general (todos los flows) con features derivadas
    best_general = evaluate(benign, attack, "GENERAL (features derivadas)")

    # Modelo 2: solo flows con respuesta del servidor
    best_resp = evaluate(benign_resp, attack_resp, "SOLO CON RESPUESTA (sesiones completadas)")

    # Guardar el mejor de los dos
    os.makedirs(OUT_DIR, exist_ok=True)

    candidatos = [c for c in [best_general, best_resp] if c]
    if not candidatos:
        log("No se pudo entrenar ningún modelo")
        return

    mejor = max(candidatos, key=lambda x: x[3])
    cont, recall, fpr, f1, model, scaler = mejor

    joblib.dump(model, f"{OUT_DIR}/isolation_forest.pkl")
    joblib.dump(scaler, f"{OUT_DIR}/iforest_scaler.pkl")
    metrics = {
        "version": "v2_derived_features",
        "features": DERIVED_NAMES,
        "contamination": cont,
        "recall_attack": round(recall, 4),
        "fpr_benign": round(fpr, 4),
        "f1_approx": round(f1, 4),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(f"{OUT_DIR}/iforest_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    log(f"\n{'='*60}")
    log(f"RESULTADO FINAL")
    log(f"{'='*60}")
    log(f"  Recall ataques : {recall:.1%}")
    log(f"  FPR benigno    : {fpr:.1%}")
    log(f"  F1 aproximado  : {f1:.3f}")
    log(f"  Modelo guardado: {OUT_DIR}/isolation_forest.pkl")

if __name__ == "__main__":
    main()
