"""
Inspecciona las primeras filas del parquet limpio de Joaquín
(generado por el notebook 01).
"""
import json
import pandas as pd

PATH = "/mnt/d/tesis/proyecto_tesis/analisis/data/processed/NF-CICIDS2018-v3.parquet"

print(f"Leyendo {PATH}")
df = pd.read_parquet(PATH)

# ------------------------------------------------------------
# Estructura
# ------------------------------------------------------------
print(f"\n{'='*70}")
print(f"Filas totales:    {len(df):,}")
print(f"Columnas totales: {len(df.columns)}")
print(f"Columnas:         {list(df.columns)}")
print(f"{'='*70}")

GOLDEN_11 = [
    "PROTOCOL", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
]

# ------------------------------------------------------------
# Estadísticas del Golden Subset
# ------------------------------------------------------------
print("\nESTADÍSTICAS (Golden Subset)")
print("-"*70)
print(df[GOLDEN_11].describe().T.to_string())

# ------------------------------------------------------------
# Tipos de datos
# ------------------------------------------------------------
print(f"\nTIPOS DE DATOS")
print("-"*70)
print(df[GOLDEN_11].dtypes.to_string())

# ------------------------------------------------------------
# Primeras 5 filas como JSON (casos de oro para tests del VRL)
# ------------------------------------------------------------
print(f"\n{'='*70}")
print("PRIMERAS 5 FILAS (formato JSON, casos de oro)")
print(f"{'='*70}")
for i, row in df[GOLDEN_11].head(5).iterrows():
    print(f"\n--- Fila {i} ---")
    print(json.dumps(row.to_dict(), indent=2, default=str))

# ------------------------------------------------------------
# Verificación crítica: ¿coinciden los valores con la fórmula del contrato?
# ------------------------------------------------------------
print(f"\n{'='*70}")
print("VERIFICACIÓN DE FÓRMULA")
print(f"{'='*70}")

# Solo flujos donde la verificación tiene sentido
sub = df[
    (df["FLOW_DURATION_MILLISECONDS"] > 0)
    & (df["IN_BYTES"] > 0)
    & (df["SRC_TO_DST_SECOND_BYTES"] > 0)
].copy()

if len(sub) == 0:
    print("⚠️  No hay flujos válidos para verificar.")
else:
    print(f"Flujos analizados: {len(sub):,} ({len(sub)/len(df):.1%} del total)")

    # F1: la fórmula del contrato: bytes / (duracion_ms / 1000)
    sub["calc_F1"] = (
        sub["IN_BYTES"] / (sub["FLOW_DURATION_MILLISECONDS"] / 1000.0)
    )

    # F2: bytes / duracion_ms  (sin /1000) — bytes por milisegundo
    sub["calc_F2"] = (
        sub["IN_BYTES"] / sub["FLOW_DURATION_MILLISECONDS"]
    )

    # F3: bytes / duracion_ms * 1000 — equivalente a F1 reformulado
    # (matemáticamente igual a F1; lo dejamos solo para sanity check)
    sub["calc_F3"] = sub["IN_BYTES"] * 1000.0 / sub["FLOW_DURATION_MILLISECONDS"]

    # Tolerancia: ±1% del valor esperado, o ±0.01 absoluto si es muy chico
    for nombre, calc in [("F1: bytes/(ms/1000)", "calc_F1"),
                          ("F2: bytes/ms       ", "calc_F2")]:
        diff = (sub[calc] - sub["SRC_TO_DST_SECOND_BYTES"]).abs()
        tol = (sub["SRC_TO_DST_SECOND_BYTES"] * 0.01).clip(lower=0.01)
        match = (diff <= tol).mean()
        print(f"  {nombre}  →  match ±1%: {match:>6.1%}")

    print(f"\nEjemplos comparativos (10 filas):")
    print(sub[["IN_BYTES", "FLOW_DURATION_MILLISECONDS",
               "SRC_TO_DST_SECOND_BYTES", "calc_F1", "calc_F2"]].head(10).to_string())

# ------------------------------------------------------------
# Distribución de clases si existe Label
# ------------------------------------------------------------
if "Label" in df.columns:
    print(f"\n{'='*70}")
    print("DISTRIBUCIÓN DE CLASES")
    print(f"{'='*70}")
    print(df["Label"].value_counts().to_string())

if "Attack" in df.columns:
    print(f"\nTOP ATAQUES")
    print("-"*70)
    print(df["Attack"].value_counts().head(15).to_string())
