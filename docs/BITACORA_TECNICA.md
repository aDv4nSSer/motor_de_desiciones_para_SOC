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
