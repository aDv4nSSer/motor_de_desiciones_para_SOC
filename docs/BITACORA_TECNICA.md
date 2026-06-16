# Bitácora Técnica — Motor de Decisiones SOC

> Registro cronológico de hallazgos, decisiones de diseño y evidencia experimental.
> Cada entrada alimenta el capítulo de metodología y resultados de la tesis.
> **Formato:** fecha · hallazgo · contexto · decisión · evidencia/métricas

---

## Índice de hallazgos clave

| # | Tema | Impacto | Estado |
|---|------|---------|--------|
| H1 | Domain shift en datasets académicos | Alto | Documentado |
| H2 | L4_SRC_PORT es data leakage | Alto | Resuelto |
| H3 | Etiquetado por IP vs comportamiento | Alto | Resuelto |
| H4 | Isolation Forest no detecta escaneos | Medio | Documentado |
| H5 | Honeypot como fuente de telemetría real | Alto | Implementado |

---

## H1 — Domain shift: el modelo aprende el laboratorio, no el ataque

**Fecha:** Sesiones iniciales
**Contexto:** Al entrenar con datasets NF-v3 Queensland, el modelo alcanzaba AUC 0.99+, sospechosamente alto.

**Hallazgo:** Un experimento de "predecir el dataset" logró 99.9% de accuracy identificando de qué dataset provenía un flujo, usando solo las features de red. Esto significa que el modelo aprendía la **firma del ambiente de laboratorio** (rangos de IP, patrones de captura) en lugar de patrones de ataque genuinos.

**Decisión:** Estimar el rendimiento realista de producción en AUC 0.93–0.97, no el 0.99 académico. Adoptar GroupKFold con split host-disjunto para el reentrenamiento de tesis (Camino E).

**Evidencia:** Experimento predict-the-dataset, accuracy 99.9%.

---

## H2 — L4_SRC_PORT es fuga de datos (data leakage)

**Fecha:** Diseño del feature contract
**Contexto:** El puerto de origen aparecía como feature muy predictiva.

**Hallazgo:** L4_SRC_PORT mostró 22.6% de ganancia en entrenamiento pero solo 2.8% de importancia por permutación — señal clásica de leakage. El modelo memorizaba puertos efímeros específicos del dataset, no un patrón generalizable.

**Decisión:** Excluir L4_SRC_PORT del Golden 4. Features finales: SERVER_TCP_FLAGS, OUT_PKTS, FLOW_DURATION_MILLISECONDS, L4_DST_PORT.

**Evidencia:** Gain 22.6% vs permutation importance 2.8%.

---

## H3 — Etiquetado por reputación de IP vs comportamiento del flujo

**Fecha:** 2026-06-13
**Contexto:** El etiquetador v1 solo consultaba AbuseIPDB para IPs con alerta de Suricata. Resultado: 4 ataques de 505k flows (0.001%).

**Hallazgo:** Al consultar AbuseIPDB para TODAS las IPs externas priorizadas por volumen (v2), la tasa de ataques subió a 11% del corpus. La IP 37.77.150.67 (score 100, 3441 reportes) generó 53.348 flows de escaneo en un día.

**Decisión:** Etiquetado híbrido — categoría Suricata (alta confianza) + AbuseIPDB score ≥40 para todas las IPs externas. Documentar que el 97.5% de ataques se etiquetan por reputación de IP, no por comportamiento del flujo.

**Evidencia:** v1: 0.001% ataques → v2: 11.04% ataques. Corpus 512k flows.

**Limitación reconocida:** El etiquetado por IP no enseña al modelo el *comportamiento* del ataque, solo la reputación del origen. Mitigado con honeypot (H5).

---

## H4 — Isolation Forest no detecta escaneos de puertos

**Fecha:** 2026-06-15
**Contexto:** Se evaluó Isolation Forest como detector de anomalías no supervisado, entrenado solo con tráfico benigno (484k flows).

**Hallazgo:** Mejor configuración (contamination 0.25) detecta solo 20.9% de ataques con 24.9% de falsos positivos. El motivo: el 97% de los ataques son escaneos (OUT_PKTS=0, DURATION≈0), estadísticamente indistinguibles del tráfico benigno trivial (conexiones fallidas, health checks).

**Decisión:** El Isolation Forest NO es viable como detector primario en este dominio. Confirma la arquitectura: LightGBM supervisado calibrado es el clasificador principal; Isolation Forest queda como complemento para anomalías extremas (exfiltración, C2 de duración inusual).

**Evidencia:**

| Contaminación | Recall ataque | FPR benigno | F1 |
|---------------|---------------|-------------|-----|
| 0.05 | 0.4% | 4.9% | 0.007 |
| 0.10 | 4.1% | 9.9% | 0.070 |
| 0.15 | 8.5% | 14.9% | 0.132 |
| 0.20 | 11.4% | 19.6% | 0.165 |
| 0.25 | 20.9% | 24.9% | 0.269 |

**Valor metodológico:** Demuestra objetivamente por qué la clasificación supervisada calibrada supera a la detección no supervisada para este tipo de tráfico.

---

## H5 — Honeypot Cowrie como fuente de telemetría de ataque real

**Fecha:** 2026-06-15
**Contexto:** El corpus carecía de ataques con sesión completada (OUT_PKTS>0, DURATION>1000ms). Los escaneos dominaban.

**Hallazgo:** Cowrie desplegado en puerto 22 (SSH real movido a 2222) capturó 5 atacantes reales en los primeros 3 minutos, con sesiones de login exitoso y duraciones de 6.9–12.8 segundos. Credenciales reales probadas: Support/maintenance, Test/letmein.

**Decisión:** Cowrie como fuente permanente de brute force SSH real. Aislamiento verificado: usuario cowrie sin acceso al sistema SOC. Genera el patrón de "ataque completado" que los escaneos no aportan.

**Evidencia:** 5 sesiones en 3 min. Duraciones 6.9–12.8s. IPs con score 100 en AbuseIPDB.

**Seguridad:** Honeypot de emulación, sistema de archivos falso, sin acceso al OS real.

---

## Plantilla para nuevos hallazgos

```
## H[N] — [Título descriptivo]

**Fecha:** YYYY-MM-DD
**Contexto:** [Qué se estaba haciendo / problema observado]

**Hallazgo:** [Qué se descubrió, con números concretos]

**Decisión:** [Qué se decidió hacer al respecto]

**Evidencia:** [Métricas, comandos, resultados que respaldan]
```

---

## H6 — Isolation Forest mejora con features derivadas y segmentación por respuesta

**Fecha:** 2026-06-15
**Contexto:** Tras el fracaso del Isolation Forest crudo (H4, 20.9% recall), se probaron features derivadas de comportamiento (ratio_pkts, pkts_per_sec, bytes_per_pkt, is_no_response) y segmentación del corpus por presencia de respuesta del servidor (OUT_PKTS>0).

**Hallazgo:** El modelo "general" con features derivadas sigue pobre (11.3% recall). Pero el modelo entrenado SOLO sobre flows con respuesta del servidor (sesiones completadas) alcanza:
- Contaminación 0.05: recall 26.6%, FPR 4.6% (excelente precisión)
- Contaminación 0.25: recall 55.6%, FPR 24.2%

La diferencia confirma que las anomalías de comportamiento (C2, exfiltración, brute force completado) solo son detectables en flows con sesión establecida. Los escaneos (97% del corpus) ahogan la señal en el modelo general.

**Decisión:** Adoptar arquitectura de Isolation Forest segmentado — aplicar el detector de anomalías únicamente a flows con OUT_PKTS>0. Para escaneos, confiar en LightGBM + reglas. A medida que Cowrie genere más sesiones SSH completas, el corpus de ataques-con-respuesta (hoy 2.693) crecerá y mejorará el recall.

**Evidencia:**

| Modelo | Mejor cont | Recall | FPR | F1 |
|--------|-----------|--------|-----|-----|
| General (crudo, H4) | 0.25 | 20.9% | 24.9% | 0.269 |
| General (derivado) | 0.25 | 11.3% | 24.9% | 0.155 |
| Solo-con-respuesta | 0.05 | 26.6% | 4.6% | 0.296 |
| Solo-con-respuesta | 0.25 | 55.6% | 24.2% | 0.256 |

**Limitación actual:** solo 2.693 ataques con respuesta en el corpus. Dependiente del crecimiento vía honeypot (H5).

---

## H7 — Desajuste de features entre entrenamiento e inferencia del Isolation Forest

**Fecha:** 2026-06-15
**Contexto:** Tras integrar el Isolation Forest al motor (model.py), un flow de prueba (sesión SSH de 8s, 50 paquetes) recibía anomaly_score de 0.08 — absurdamente bajo para tráfico que debería ser anómalo.

**Hallazgo:** El model.py tenía tres desajustes con el entrenamiento (train_isolation_forest_v2.py):
1. No cargaba ni aplicaba el RobustScaler — pasaba features crudos a un modelo entrenado con datos escalados.
2. No calculaba las 6 features derivadas (ratio_pkts, pkts_per_sec, etc.) — pasaba 4 features a un modelo que espera 11.
3. La normalización del score usaba un rango incorrecto.

El modelo recibía datos en un formato incompatible con su entrenamiento, produciendo scores sin sentido.

**Decisión:** Reescribir model.py para replicar EXACTAMENTE el pipeline de entrenamiento: clip a límites del contrato → cálculo de las 11 features derivadas → transform con el scaler guardado → score_samples. Principio: la transformación de features en inferencia debe ser idéntica a la de entrenamiento.

**Evidencia:**
- Antes: anomaly_score 0.08 (datos mal formateados)
- Después: anomaly_score 0.9611 (sesión SSH correctamente detectada como anómala)
- El flow pasó de T0 (ALLOW) a T1 (LOG) gracias al detector de anomalías.

**Lección de diseño:** Cualquier transformación aplicada en entrenamiento (escalado, features derivadas, clipping) DEBE guardarse y aplicarse idénticamente en inferencia. Un scaler desalineado degrada silenciosamente el modelo sin lanzar errores.

## H8 — Colisión entre IP del investigador e IP atacante en etiquetado por campaña

**Fecha:** 2026-06-15
**Contexto:** Al revisar flows de la IP 190.114.34.111 (IP actual del investigador), se detectaron sesiones SSH largas en puerto 2222 con OUT_PKTS de 299-1656 y duraciones de 15-23 minutos. El registro de campañas tenía esa IP como atacante.

**Hallazgo:** El etiquetador v3 etiquetaba TODOS los flows de la IP atacante como label=1 sin distinguir el puerto. Las sesiones SSH legítimas de administración del investigador habrían quedado etiquetadas como ataque, contaminando el corpus.

**Decisión:** Agregar campo puertos_excluir al registro_campanas.jsonl. El etiquetador verifica si dest_port está en la lista de exclusión antes de asignar label=1.

**Evidencia:** 281 flows desde 190.114.34.111 el 15-06-2026. Puerto 2222: DUR=1383s, OUT_PKTS=1656 (sesión SSH legítima). Puerto 8080: DUR=13s, OUT_PKTS=953 (HTTP flood de campaña).

**Lección:** En entornos donde el investigador usa la misma IP para trabajar y atacar, el etiquetado por IP sin filtro de puerto introduce ruido en el corpus.
