# Contrato del Modelo ML — Golden 4 v7.1

Documento de referencia para integrar el modelo en el motor de decisiones.
Toda modificación requiere alineación con el equipo ML (Joaquín Arias).

## Modelo activo

| Campo | Valor |
|---|---|
| Archivo | `model_golden4_v7_1_latest.pkl` |
| Algoritmo | LightGBM binario + calibración isotónica |
| Schema features | `feature_schema_v5_latest.json` |
| Thresholds | `/outputs/thresholds/thresholds_v6_latest.json` |
| Corpus entrenamiento | 308k flows (94% académico NF-v3 + 6% Suricata real) |
| Validación | 231k flows no vistos en entrenamiento |

**El score de salida [0.0–1.0] ES probabilidad real de ataque** (calibración isotónica verificada).
Un score 0.85 significa 85% de probabilidad, no un valor arbitrario.

## Features activos (4 únicos — Golden 4)

```
SERVER_TCP_FLAGS          Flags TCP del servidor (SYN, ACK, RST, FIN, etc.)
OUT_PKTS                  Paquetes salientes del cliente al servidor en el flujo
FLOW_DURATION_MILLISECONDS Duración total del flujo en milisegundos
L4_DST_PORT               Puerto destino TCP/UDP (0–65535)
```

El orden y los nombres deben coincidir exactamente con `feature_schema_v5_latest.json`.
Verificar contra el schema antes de construir cualquier vector de features.

## Métricas del modelo (producción validada)

| Métrica | Valor | Contexto |
|---|---|---|
| AUC | 0.97 | Corpus académico 1.75M flows |
| AUC (tráfico real) | 0.98 | Suricata etiquetado alta confianza |
| Precisión | 56% | Suricata test — datos reales |
| Recall | 85% | Suricata test — datos reales |
| Brier score | 0.058 | Calibración verificada, reliability diagram disponible |
| AUC vs Suricata IDS | 0.38 | **Esperado.** Detectores complementarios, no rivales. |
| Tasa alertas sin filtrar | 43% | Mayoría son escaneos automáticos (TP técnicos) |

El AUC 0.38 contra Suricata NO es defecto. Suricata detecta firmas; LightGBM detecta
patrones sospechosos generales. El motor de decisiones maneja la zona gris entre ambos.

## Thresholds operacionales — NO usar 0.5 global

Archivo de referencia: `/outputs/thresholds/thresholds_v6_latest.json`

Zonas de decisión para el motor (guía de implementación):
```python
# Cargar desde archivo — nunca hardcodear
thresholds = load_json("/outputs/thresholds/thresholds_v6_latest.json")
T_LOW  = thresholds["operational"]["threshold_low"]   # zona T0
T_HIGH = thresholds["operational"]["threshold_high"]  # zona T3 candidato

if score < T_LOW:
    provisional_tier = "T0"                   # loggear, no actuar
elif score < T_HIGH:
    provisional_tier = "T1_OR_T2_PENDING"    # contexto + TI deciden
else:
    provisional_tier = "T3_CANDIDATE"        # señal fuerte, contexto puede confirmar
```

## Tracking obligatorio en soc-decisions

Cada documento de decisión DEBE incluir el bloque `ml` completo:

```json
{
  "ml": {
    "model_version": "golden4-v7.1",
    "model_file": "model_golden4_v7_1_latest.pkl",
    "calibration": "isotonic",
    "lgbm_score": 0.0,
    "if_score": 0.0,
    "threshold_used": 0.0,
    "features_used": [
      "SERVER_TCP_FLAGS",
      "OUT_PKTS",
      "FLOW_DURATION_MILLISECONDS",
      "L4_DST_PORT"
    ],
    "feature_snapshot": {
      "SERVER_TCP_FLAGS": 0,
      "OUT_PKTS": 0,
      "FLOW_DURATION_MILLISECONDS": 0,
      "L4_DST_PORT": 0
    },
    "shap_top_features": []
  }
}
```

`feature_snapshot` almacena los valores exactos del flujo — permite reproducir la
predicción y es parte del mecanismo de trazabilidad de la tesis.

## Versiones históricas — NUNCA usar en producción

| Archivo | Versión | Problema crítico |
|---|---|---|
| `model_golden11_v4_latest.pkl` | v4 | **DATA LEAKAGE.** AUC 0.9977 inflado artificialmente. |
| `model_golden4_v5_latest.pkl` | v5 | Sin estratificación. Reemplazado. |
| `model_golden4_v5_stratified_latest.pkl` | v5s | Solo datos académicos. Precisión 14% en tráfico real. |
| `model_golden4_v6_hybrid_latest.pkl` | v6 | Suricata 1.1%. Precisión 34%. Superado por v7.1. |
| `model_golden5_v7_latest.pkl` | v7 | Categorización de puertos. Experimento descartado. |

## Features rechazados — nunca agregar

| Feature | Razón documentada |
|---|---|
| `FLOW_STATE` | Ausente en datasets NF-v3 de entrenamiento |
| `APP_PROTO` | Ausente en datasets NF-v3 de entrenamiento |
| `SRC_TO_DST_SECOND_BYTES` | Fórmula documentada ≠ valores nProbe Pro reales (0% match) |
| `DST_TO_SRC_SECOND_BYTES` | Mismo problema de implementación |
| `L4_SRC_PORT` como señal | Data leakage de entorno de laboratorio — no generalizable |
