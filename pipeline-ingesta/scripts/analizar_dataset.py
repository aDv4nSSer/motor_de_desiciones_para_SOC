"""
Análisis del parquet del dataset NF-CSE-CIC-IDS2018-v3 (500K rows).

Objetivos:
1. Resolver definitivamente el mapeo CLIENT_TCP_FLAGS / SERVER_TCP_FLAGS
   vs los campos tcp_flags_ts / tcp_flags_tc de Suricata.
2. Establecer baseline estadística de las 11 features del Golden Subset.
"""

from pathlib import Path
import pandas as pd

PARQUET_PATH = "/mnt/d/tesis/proyecto_tesis/analisis/data/processed/sample_500k.parquet"

GOLDEN_SUBSET = [
    "PROTOCOL",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
]


def main() -> None:
    print(f"Leyendo {PARQUET_PATH}...")
    df = pd.read_parquet(PARQUET_PATH)

    # ------------------------------------------------------------
    # 1. Estructura del dataset
    # ------------------------------------------------------------
    print(f"\n{'='*60}")
    print("1. ESTRUCTURA DEL DATASET")
    print(f"{'='*60}")
    print(f"Total de filas: {len(df):,}")
    print(f"Total de columnas: {len(df.columns)}")
    print("\nColumnas disponibles:")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i:>3}. {col} ({df[col].dtype})")

    # ------------------------------------------------------------
    # 2. ¿Están las 11 features del Golden Subset?
    # ------------------------------------------------------------
    print(f"\n{'='*60}")
    print("2. VERIFICACIÓN DEL GOLDEN SUBSET")
    print(f"{'='*60}")
    presentes = [c for c in GOLDEN_SUBSET if c in df.columns]
    faltantes = [c for c in GOLDEN_SUBSET if c not in df.columns]
    print(f"Presentes: {len(presentes)}/11")
    for c in presentes:
        print(f"  OK  {c}")
    if faltantes:
        print(f"Faltantes:")
        for c in faltantes:
            print(f"  XX  {c}")

    # ------------------------------------------------------------
    # 3. RESOLUCIÓN DEL MAPEO tc/ts (objetivo principal)
    # ------------------------------------------------------------
    print(f"\n{'='*60}")
    print("3. MAPEO CLIENT_TCP_FLAGS vs SERVER_TCP_FLAGS")
    print(f"{'='*60}")

    tcp = df[df["PROTOCOL"] == 6].copy()
    print(f"Flujos TCP en el dataset: {len(tcp):,}")

    # Estrategia: en un handshake TCP estándar, el cliente envía SYN (0x02 = 2)
    # y el servidor responde con SYN+ACK (0x12 = 18). Si CLIENT_TCP_FLAGS contiene
    # el bit SYN con más frecuencia que SERVER_TCP_FLAGS en flujos cortos,
    # confirma "cliente = quien inicia la conexión".
    SYN_BIT = 2
    ACK_BIT = 16

    # Flujos cortos (≤10 paquetes totales) para que los flags acumulados sean limpios
    cortos = tcp[(tcp["IN_PKTS"] + tcp["OUT_PKTS"]) <= 10].copy()
    print(f"Flujos TCP cortos (≤10 pkts totales): {len(cortos):,}")

    cortos["client_has_syn"] = (cortos["CLIENT_TCP_FLAGS"] & SYN_BIT) > 0
    cortos["server_has_syn"] = (cortos["SERVER_TCP_FLAGS"] & SYN_BIT) > 0
    cortos["client_has_ack"] = (cortos["CLIENT_TCP_FLAGS"] & ACK_BIT) > 0
    cortos["server_has_ack"] = (cortos["SERVER_TCP_FLAGS"] & ACK_BIT) > 0

    print(f"\nFracción de flujos donde CLIENT tiene bit SYN: "
          f"{cortos['client_has_syn'].mean():.1%}")
    print(f"Fracción de flujos donde SERVER tiene bit SYN: "
          f"{cortos['server_has_syn'].mean():.1%}")
    print(f"Fracción de flujos donde CLIENT tiene bit ACK: "
          f"{cortos['client_has_ack'].mean():.1%}")
    print(f"Fracción de flujos donde SERVER tiene bit ACK: "
          f"{cortos['server_has_ack'].mean():.1%}")

    print("\nINTERPRETACIÓN:")
    print("- Si CLIENT_TCP_FLAGS tiene SYN en >90% de los flujos cortos,")
    print("  significa que 'cliente' = quien inicia la conexión (convención estándar).")
    print("- Si SERVER_TCP_FLAGS tiene SYN en >90% en lugar de CLIENT, hay inversión.")
    print("- Ambos suelen tener ACK porque después del handshake todos los paquetes")
    print("  llevan ACK.")

    # Ejemplos representativos: 10 flujos cortos para inspección visual
    print(f"\nMuestra de 10 flujos TCP cortos para inspección manual:")
    cols_muestra = [
        "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
        "IN_PKTS", "OUT_PKTS", "IN_BYTES", "OUT_BYTES",
    ]
    cols_muestra = [c for c in cols_muestra if c in cortos.columns]
    print(cortos[cols_muestra].head(10).to_string())

    # ------------------------------------------------------------
    # 4. Baseline estadística de las 11 features
    # ------------------------------------------------------------
    print(f"\n{'='*60}")
    print("4. BASELINE ESTADÍSTICA (descripción de las 11 features)")
    print(f"{'='*60}")
    cols_existentes = [c for c in GOLDEN_SUBSET if c in df.columns]
    print(df[cols_existentes].describe().T.to_string())

    # ------------------------------------------------------------
    # 5. Conteo de clases (si existe Label / Attack)
    # ------------------------------------------------------------
    print(f"\n{'='*60}")
    print("5. ETIQUETAS (si existen)")
    print(f"{'='*60}")
    for col_label in ("Label", "label", "Attack", "attack", "Class", "class"):
        if col_label in df.columns:
            print(f"Columna '{col_label}':")
            print(df[col_label].value_counts(dropna=False).to_string())
            print()

    verificar_formula_bytes_per_second(df)

def verificar_formula_bytes_per_second(df: pd.DataFrame) -> None:
    """
    Análisis profundo: probamos más fórmulas y vemos qué relación tiene
    el valor esperado del dataset con IN_BYTES y duración.
    """
    print(f"\n{'='*60}")
    print("6. ANÁLISIS PROFUNDO de SRC_TO_DST_SECOND_BYTES")
    print(f"{'='*60}")

    sub = df[
        (df["FLOW_DURATION_MILLISECONDS"] > 100)
        & (df["IN_BYTES"] > 100)
        & (df["SRC_TO_DST_SECOND_BYTES"] > 0)
        & (df["DURATION_IN"] > 0)
        & (df["IN_PKTS"] > 0)
    ].copy()

    print(f"Flujos analizados: {len(sub):,}")

    # Calculamos el "factor implícito": esperado * duracion / bytes
    # Si nProbe usa bytes/duracion entonces este factor es ~1.0
    # Si usa bytes/(duracion*1000) entonces el factor es ~1000
    sub["factor_fl"] = (
        sub["SRC_TO_DST_SECOND_BYTES"] * sub["FLOW_DURATION_MILLISECONDS"]
        / sub["IN_BYTES"]
    )
    sub["factor_du"] = (
        sub["SRC_TO_DST_SECOND_BYTES"] * sub["DURATION_IN"]
        / sub["IN_BYTES"]
    )

    print(f"\nFactor implícito si la fórmula fuera 'IN_BYTES * factor / FLOW_DURATION_MS':")
    print(sub["factor_fl"].describe().to_string())

    print(f"\nFactor implícito si la fórmula fuera 'IN_BYTES * factor / DURATION_IN':")
    print(sub["factor_du"].describe().to_string())

    # Veamos también la correlación de SRC_TO_DST_SECOND_BYTES con IN_BYTES e IN_PKTS
    print(f"\nCorrelación de SRC_TO_DST_SECOND_BYTES con otras features:")
    corr_cols = ["IN_BYTES", "IN_PKTS", "FLOW_DURATION_MILLISECONDS", "DURATION_IN"]
    for col in corr_cols:
        c = sub["SRC_TO_DST_SECOND_BYTES"].corr(sub[col])
        print(f"  {col:35s}: {c:+.3f}")

    # Veamos también si SRC_TO_DST_SECOND_BYTES está cerca de IN_PKTS
    sub["diff_in_pkts"] = (sub["SRC_TO_DST_SECOND_BYTES"] - sub["IN_PKTS"]).abs()
    print(f"\n¿SRC_TO_DST_SECOND_BYTES está cerca de IN_PKTS?")
    print(f"  Median |diff|: {sub['diff_in_pkts'].median()}")
    print(f"  Match exacto SRC_TO_DST_SECOND_BYTES == IN_PKTS: "
          f"{(sub['SRC_TO_DST_SECOND_BYTES'] == sub['IN_PKTS']).mean():.1%}")

    # Mostrar histograma simple de SRC_TO_DST_SECOND_BYTES
    print(f"\nDistribución de SRC_TO_DST_SECOND_BYTES (todo el dataset):")
    print(df["SRC_TO_DST_SECOND_BYTES"].describe().to_string())

    # Mostrar 10 ejemplos con MUCHOS datos para inspeccionar manualmente
    print(f"\n20 ejemplos con todos los datos relevantes:")
    cols_show = [
        "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
        "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT",
        "SRC_TO_DST_SECOND_BYTES", "SRC_TO_DST_AVG_THROUGHPUT",
    ]
    cols_show = [c for c in cols_show if c in sub.columns]
    print(sub[cols_show].head(20).to_string())

if __name__ == "__main__":
    main()
