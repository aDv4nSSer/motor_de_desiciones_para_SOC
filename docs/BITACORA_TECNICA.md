# Bitácora Técnica — Motor de Decisiones SOC

> Registro cronológico de hallazgos, decisiones de diseño y evidencia experimental.
> Cada entrada alimenta el capítulo de metodología y resultados de la tesis.
> **Formato:** fecha · hallazgo · contexto · decisión · evidencia/métricas

---

## Índice de hallazgos clave

Categorías: **ML** (dataset/modelo/features) · **Resp** (respuesta activa/FIM/worker) · **Red** (red/VLAN/switch/firewall) · **Ops** (systemd/supervisión/servicios)

| # | Categoría | Tema | Impacto | Estado |
|---|-----------|------|---------|--------|
| [H1](#h1) | ML | Domain shift en datasets académicos | Alto | Documentado |
| [H2](#h2) | ML | L4_SRC_PORT es data leakage | Alto | Resuelto |
| [H3](#h3) | ML | Etiquetado por IP vs comportamiento | Alto | Resuelto |
| [H4](#h4) | ML | Isolation Forest no detecta escaneos | Medio | Documentado — refinado por H6, no reemplazado |
| [H5](#h5) | ML | Honeypot como fuente de telemetría real | Alto | Implementado |
| [H6](#h6) | ML | Isolation Forest segmentado por presencia de respuesta | Medio | Implementado |
| [H7](#h7) | ML | Desajuste de features IF entre entrenamiento e inferencia | Alto | Resuelto |
| [H8](#h8) | ML | Colisión IP investigador/atacante en etiquetado por campaña | Alto | Resuelto |
| [H9](#h9) | Ops | Cowrie caído 3 días por PATH faltante en systemd | Medio | Resuelto |
| [H10](#h10) | ML | Feature contract rechaza sesiones largas (Golden 4) | Medio | Documentado — limitación conocida, sin fix |
| [H11](#h11) | Resp | Payload incompatible en Wazuh Active Response on-demand | Alto | Resuelto |
| [H12](#h12) | Resp | FIM ampliado a WordPress + bug de detección realtime | Alto | Mitigado — causa raíz de realtime sigue abierta |
| [H13](#h13) | Resp | Cuarentena de archivo como 2da forma de Active Response | Alto | Implementado |
| [H14](#h14) | Ops | Timeout de systemd insuficiente en wazuh-manager | Medio | Resuelto |
| [H15](#h15) | Ops | Caída de Redis expone falta de supervisión en response.worker | Alto | Documentado — fix diseñado, implementación sin confirmar (ver nota en la entrada) |
| [H16](#h16) | Red | Punto ciego: Suricata no ve tráfico directo al uplink ISP de .138 | Alto | **Superado por H17 (arquitectura) y H21 (confirmación empírica)** |
| [H17](#h17) | Red | Migración de topología: subred plana → NAT/gateway con VLANs | Alto | Implementado parcialmente — ver nota de alcance en la entrada |
| [H18](#h18) | Red | Riesgo de comodín en perfil NetworkManager de `.139` | Medio | Resuelto |
| [H19](#h19) | Red | Cambio de VLAN de gestión del switch — "no route to host" | Bajo | Resuelto |
| [H20](#h20) | Red | Switch SG350: firmware solo ofrece algoritmos SSH obsoletos | Bajo | Mitigado — workaround en cliente, firmware pendiente |
| [H21](#h21) | Red | Suricata in-line con cero alertas — orden de reglas en `before.rules` | Alto | Resuelto — retest confirmado con evidencia |
| [H22](#h22) | Ops | Redis caído por bind a IP pública obsoleta — motor-soc casi 1 semana sin levantar | Alto | Resuelto — fix aplicado y verificado; brecha de monitoreo queda pendiente |
| [H23](#h23) | Resp | OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1) | Medio | Implementado — API key real ya cargada en `.140`, pendiente deploy del código |

---

<a id="h1"></a>
## H1 — Domain shift: el modelo aprende el laboratorio, no el ataque

**Fecha:** Sesiones iniciales
**Contexto:** Al entrenar con datasets NF-v3 Queensland, el modelo alcanzaba AUC 0.99+, sospechosamente alto. Un AUC tan cercano al máximo teórico en un problema de detección de intrusiones es una señal de alarma clásica, no un resultado a celebrar sin más: suele indicar que el modelo está aprendiendo algo más fácil de separar que el fenómeno real (el ataque), como un artefacto del propio proceso de captura del dataset.

**Hallazgo:** Para probar esa sospecha se corrió un experimento de "predecir el dataset": entrenar un clasificador cuya única tarea es decir de cuál de los datasets que componen el corpus NF-v3 proviene un flujo dado, usando exactamente las mismas features de red que el modelo de detección (sin la etiqueta de ataque/benigno). Ese clasificador auxiliar logró 99.9% de accuracy — es decir, las features por sí solas casi identifican unívocamente el origen del flujo. Contienen una "huella" del entorno de captura (rangos de IP propios de ese laboratorio, patrones de timing o de conteo de paquetes propios de cómo se generó ese dataset en particular) mucho más fuerte que cualquier patrón de ataque genérico. Un modelo de detección entrenado sobre esas mismas features puede alcanzar AUC alto simplemente reconociendo "esto viene del dataset X, que tiene muchos ataques" en vez de reconociendo qué hace que un flujo *sea* un ataque — funcionaría casi perfecto en evaluación (mismos datasets, split aleatorio) y degradaría en producción real, donde esa huella de laboratorio no existe.

**Decisión:** Estimar el rendimiento realista de producción en AUC 0.93–0.97, no el 0.99 académico — descontando explícitamente el margen que corresponde a la fuga de identidad de dataset. Adoptar GroupKFold con split host-disjunto (agrupando por IP origen del flujo) para el reentrenamiento de tesis (Camino E): en vez de repartir flows individuales al azar entre train y test —donde flows del mismo host pueden terminar en ambos lados, dejando que el modelo memorice ese host en vez de generalizar—, GroupKFold obliga a que todos los flows de un mismo grupo (host) caigan enteros en un solo lado del split, impidiendo que el modelo se beneficie de haber "visto" ese host durante entrenamiento al evaluarlo. La separación se mantiene explícita también en el código de reetiquetado: `scripts/training/relabeling/re_labeler.py` documenta en su cabecera que el campo `host_group` (IP origen) "es SOLO para GroupKFold — NUNCA entra al modelo", para que el agrupamiento del split no se filtre por accidente como feature.

**Evidencia:** Experimento predict-the-dataset, accuracy 99.9% identificando el dataset de origen a partir únicamente de las features de red.

---

<a id="h2"></a>
## H2 — L4_SRC_PORT es fuga de datos (data leakage)

**Fecha:** Diseño del feature contract
**Contexto:** Durante la selección de features para LightGBM, el puerto de origen (L4_SRC_PORT) aparecía como una de las features más predictivas del modelo — candidata fuerte a entrar al Golden 4.

**Hallazgo:** Se compararon dos métricas de importancia de feature que miden cosas distintas: **gain** (cuánto reduce la impureza del árbol cada vez que LightGBM particiona usando esa feature, medido sobre el propio entrenamiento) vs. **permutation importance** (cuánto cae el rendimiento en un set de validación separado cuando se baraja al azar el valor de esa feature, rompiendo su relación con el target — mide si el modelo *depende* de ella para generalizar, no solo si la usó mucho para ajustar el training set). L4_SRC_PORT mostró 22.6% de gain pero solo 2.8% de importancia por permutación. Una brecha grande entre ambas es la señal clásica de leakage: el modelo la usa agresivamente para memorizar el training set (gain alto), pero esa memorización no aporta nada a la generalización real (permutation importance bajo). El mecanismo concreto: los puertos de origen son asignados por el sistema operativo del cliente de forma efímera y en gran medida arbitraria por conexión — no codifican ninguna propiedad del tráfico en sí, pero en un dataset de laboratorio con un número limitado de máquinas generando tráfico, ciertos rangos de puertos efímeros terminan correlacionados por casualidad con qué máquina (y por tanto qué clase) generó cada flujo. El modelo aprende esa correlación espuria del laboratorio, no un patrón de ataque generalizable — la misma familia de problema que H1, a nivel de una sola feature en vez de todo el dataset.

**Decisión:** Excluir L4_SRC_PORT del Golden 4. Features finales: SERVER_TCP_FLAGS, OUT_PKTS, FLOW_DURATION_MILLISECONDS, L4_DST_PORT. El criterio (gain alto + permutation importance bajo → sospechar leakage antes de aceptar una feature) queda como método a replicar para cualquier feature candidata futura, no solo para este caso puntual — de ahí también la prohibición explícita en `CLAUDE.md` de reintroducir `L4_SRC_PORT` como señal.

**Evidencia:** Gain 22.6% vs permutation importance 2.8% para L4_SRC_PORT.

---

<a id="h3"></a>
## H3 — Etiquetado por reputación de IP vs comportamiento del flujo

**Fecha:** 2026-06-13
**Contexto:** El corpus de entrenamiento necesita una etiqueta (ataque/benigno) por flujo, y no existe ground truth manual disponible a esa escala — el etiquetado se deriva de fuentes automáticas. La primera versión del etiquetador (v1) solo consultaba AbuseIPDB (score de reputación de IP) para las IPs que YA tenían una alerta de Suricata asociada, es decir, dependía enteramente de que la detección por firmas hubiera marcado el flujo primero. Resultado: 4 ataques de 505k flows (0.001%) — tasa de positivos casi nula, insuficiente para entrenar cualquier clasificador supervisado.

**Hallazgo:** El problema no era la escasez de ataques reales en el tráfico, sino que el etiquetador v1 heredaba exactamente el punto ciego de Suricata: solo consideraba "posible ataque" lo que una firma ya conocida detectaba, ignorando cualquier IP con mala reputación externa cuyo tráfico no había disparado ninguna regla. Al reescribir el etiquetador (v2, `scripts/training/etiquetador/etiquetador_diario.py`, con el log de arranque explícito "Etiquetador diario v2 — AbuseIPDB para todas las IPs externas") para consultar AbuseIPDB de TODAS las IPs externas priorizadas por volumen de flows —no solo las que Suricata ya había marcado—, la tasa de ataques etiquetados subió a 11% del corpus, casi tres órdenes de magnitud más. La IP 37.77.150.67 (score 100 en AbuseIPDB, 3441 reportes) por sí sola generó 53.348 flows de escaneo en un día, sin haber sido flageada jamás por una firma de Suricata. El etiquetado final quedó como esquema híbrido, visible en el propio código: categorías Suricata de alta confianza (`ATTACK_CATS` — Web Application Attack, privilege gain, network trojan, DoS, C2 — y `NOISE_CATS` para ruido benigno confirmado como escaneos genéricos) combinadas con un umbral de reputación externa (AbuseIPDB score ≥40) aplicado a cualquier IP externa, tenga o no alerta de Suricata asociada.

**Decisión:** Etiquetado híbrido — categoría Suricata (alta confianza) + AbuseIPDB score ≥40 para todas las IPs externas. Documentar que el 97.5% de ataques se etiquetan por reputación de IP, no por comportamiento del flujo. Este hallazgo anticipa la misma idea que después se formaliza en `CLAUDE.md` sobre por qué Suricata y LightGBM son "detectores complementarios" (AUC 0.38 entre ellos, esperado): si el etiquetado de entrenamiento solo confiara en las firmas de Suricata, el modelo entrenado heredaría exactamente sus puntos ciegos en vez de aprender a cubrirlos.

**Evidencia:** v1: 0.001% ataques → v2: 11.04% ataques. Corpus 512k flows. IP 37.77.150.67: score 100, 3441 reportes AbuseIPDB, 53.348 flows de escaneo en un día.

**Limitación reconocida:** El etiquetado por IP no enseña al modelo el *comportamiento* del ataque, solo la reputación del origen. Mitigado con honeypot (H5).

---

<a id="h4"></a>
## H4 — Isolation Forest no detecta escaneos de puertos

> **Nota (auditoría 2026-08-25):** H6, el mismo día, refina este hallazgo — no lo reemplaza.
> La conclusión central de H4 se mantiene (Isolation Forest general no es viable como
> detector primario de escaneos, que son el 97% del corpus de ataques). Lo que cambia en H6
> es el alcance: segmentado a flows con respuesta del servidor, el mismo detector mejora
> sustancialmente (ver tabla comparativa en H6). Léanse como una sola línea de investigación
> continua, no como hallazgos en conflicto.

**Fecha:** 2026-06-15
**Contexto:** Se evaluó Isolation Forest como detector de anomalías no supervisado, entrenado solo con tráfico benigno (484k flows) — a diferencia de LightGBM, no recibe ninguna etiqueta de ataque/benigno durante el entrenamiento: aprende únicamente la forma de la distribución "normal" y marca como anómalo lo que se aleja de ella. El parámetro `contamination` fija de antemano qué proporción del tráfico se espera que sea anómala, y con eso calibra el umbral de score que separa "normal" de "anómalo" — subirlo captura más casos (recall) a costa de marcar más tráfico benigno como anómalo (más falsos positivos).

**Hallazgo:** Se barrió `contamination` entre 0.05 y 0.25; incluso la mejor configuración (0.25) detecta solo 20.9% de ataques con 24.9% de falsos positivos. La causa de fondo: el 97% de los ataques del corpus son escaneos de puertos, y un escaneo típico (OUT_PKTS=0, DURATION≈0 — el cliente manda el SYN y no llega a completar ni un intercambio) es, sobre las features Golden 4, estadísticamente indistinguible del tráfico benigno trivial (una conexión fallida, un health check, un cliente que se rinde rápido). Isolation Forest no tiene forma de aprender la diferencia entre "falla porque es benigno y el servicio no respondió" y "falla porque es un escaneo" si ambos casos ocupan la misma región del espacio de features — necesitaría una señal de comportamiento (frecuencia, dispersión de puertos destino en el tiempo) que las features Golden 4, evaluadas flow a flow, no capturan por sí solas.

**Decisión:** El Isolation Forest NO es viable como detector primario en este dominio. Confirma la arquitectura: LightGBM supervisado calibrado es el clasificador principal — sí tiene la etiqueta para aprender que ese patrón trivial es, en este contexto, mayoritariamente malicioso, algo que un detector no supervisado no puede inferir solo de la forma de la distribución; Isolation Forest queda como complemento para anomalías extremas (exfiltración, C2 de duración inusual) donde el patrón sí se aleja de lo normal en forma medible.

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

<a id="h5"></a>
## H5 — Honeypot Cowrie como fuente de telemetría de ataque real

**Fecha:** 2026-06-15
**Contexto:** El corpus, dominado por escaneos (H4: 97% de los ataques), carecía casi por completo de ataques con sesión completada (OUT_PKTS>0, DURATION>1000ms) — el patrón de un atacante que efectivamente logra conectarse y operar, no solo tocar el puerto y desaparecer. Sin ejemplos reales de ese patrón, ni LightGBM ni el Isolation Forest segmentado (H6, diseñado específicamente para detectar anomalías en flows-con-respuesta) tenían de dónde aprenderlo.

**Hallazgo:** Se desplegó Cowrie (honeypot de emulación SSH) en el puerto 22 — liberado moviendo el SSH real de administración al puerto 2222, el mismo puerto que después queda como estándar de acceso a los servidores del proyecto. En los primeros 3 minutos capturó 5 atacantes reales con sesiones de login exitoso (Cowrie simula aceptar credenciales de fuerza bruta) y duraciones de 6.9–12.8 segundos — casi tres órdenes de magnitud más que un escaneo típico (DURATION≈0). Credenciales reales probadas por los atacantes: Support/maintenance, Test/letmein — patrones de fuerza bruta genéricos, no dirigidos específicamente al proyecto.

**Decisión:** Cowrie como fuente permanente de brute force SSH real. Aislamiento verificado por diseño, no solo por configuración de red: el servicio systemd (`infra/systemd/cowrie.service`) corre bajo un usuario dedicado sin privilegios (`User=cowrie`), con `WorkingDirectory=/home/cowrie/cowrie` contenido a su propio árbol de directorios — Cowrie emula un sistema de archivos falso ante el atacante, sin dar acceso real al sistema operativo subyacente en ningún momento de la sesión emulada. Genera el patrón de "ataque completado" que los escaneos no aportan, alimentando tanto el reentrenamiento de LightGBM como el corpus segmentado del Isolation Forest (H6).

**Evidencia:** 5 sesiones en 3 min. Duraciones 6.9–12.8s. IPs con score 100 en AbuseIPDB. Configuración real del servicio en `infra/systemd/cowrie.service` (`User=cowrie`, `Restart=always`).

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

<a id="h6"></a>
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

<a id="h7"></a>
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

<a id="h8"></a>
## H8 — Colisión entre IP del investigador e IP atacante en etiquetado por campaña

**Fecha:** 2026-06-15
**Contexto:** Al revisar flows de la IP 190.114.34.111 (IP actual del investigador), se detectaron sesiones SSH largas en puerto 2222 con OUT_PKTS de 299-1656 y duraciones de 15-23 minutos. El registro de campañas tenía esa IP como atacante.

**Hallazgo:** El etiquetador v3 etiquetaba TODOS los flows de la IP atacante como label=1 sin distinguir el puerto. Las sesiones SSH legítimas de administración del investigador habrían quedado etiquetadas como ataque, contaminando el corpus.

**Decisión:** Agregar campo puertos_excluir al registro_campanas.jsonl. El etiquetador verifica si dest_port está en la lista de exclusión antes de asignar label=1.

**Evidencia:** 281 flows desde 190.114.34.111 el 15-06-2026. Puerto 2222: DUR=1383s, OUT_PKTS=1656 (sesión SSH legítima). Puerto 8080: DUR=13s, OUT_PKTS=953 (HTTP flood de campaña).

**Lección:** En entornos donde el investigador usa la misma IP para trabajar y atacar, el etiquetado por IP sin filtro de puerto introduce ruido en el corpus.

---

<a id="h9"></a>
## H9 — Cowrie caído 3 días por PATH faltante en servicio systemd

**Fecha:** 2026-06-18
**Contexto:** Al revisar el estado de Cowrie el 18 de junio, se detectó que llevaba inactivo desde el 15 de junio a las 23:17 — exactamente después de la sesión de ataques controlados y el reinicio de UFW.

**Hallazgo:** El servicio systemd de Cowrie no tenía configurada la variable de entorno PATH del virtualenv. Al intentar iniciar, Cowrie ejecuta `os.execvp("twistd", ...)` pero systemd no incluye el directorio `cowrie-env/bin/` en el PATH del proceso, causando `FileNotFoundError`.

**Decisión:** Agregar `Environment=PATH=/home/cowrie/cowrie/cowrie-env/bin:...` al archivo cowrie.service. Cowrie reiniciado exitosamente.

**Impacto:** 3 días sin captura de sesiones SSH reales (15-18 junio). El corpus perdió aproximadamente 3-4 días de sesiones Cowrie estimadas en 50-100 sesiones adicionales.

**Lección:** Los servicios systemd que usan virtualenvs de Python deben declarar explícitamente el PATH del virtualenv en la configuración del servicio, ya que systemd no hereda el PATH del usuario.

---

<a id="h10"></a>
## H10 — Feature contract rechaza sesiones largas: limitación del Golden 4

**Fecha:** 2026-06-21
**Contexto:** Durante la validación del modelo LightGBM v7.1 integrado al motor, se probaron flows de brute force SSH real con FLOW_DURATION_MILLISECONDS=900.000ms (15 minutos), como los que captura Cowrie.

**Hallazgo:** El feature contract define FLOW_DURATION_MILLISECONDS con límite superior de 120.534ms (≈2 minutos). Flows que superen ese límite son rechazados por validación Pydantic y el motor devuelve ALLOW por defecto — sin analizar el flujo. Esto significa que sesiones SSH largas reales quedan fuera del rango de detección del motor.

**Resultados de validación completa del modelo (21 junio 2026):**

| Patrón | ML score | IForest | Tier | Veredicto |
|--------|----------|---------|------|-----------|
| Escaneo SSH (OUT=0, DUR=0) | 0.61 | 0.43 | T2 ALERT | ✓ correcto |
| Escaneo RDP (OUT=0, DUR=0) | 0.61 | 0.63 | T2 ALERT | ✓ correcto |
| Escaneo PostgreSQL (OUT=0) | 0.61 | 0.70 | T2 ALERT | ✓ correcto |
| Slow HTTP (SYN=2, DUR=25s) | 1.00 | 0.64 | T3 BLOCK | ✓ excelente |
| SQL Injection (8080, 120ms) | 1.00 | 0.34 | T3 BLOCK | ✓ excelente |
| Credential stuffing (8080) | 0.99 | 0.72 | T3 BLOCK | ✓ excelente |
| Exfiltración (OUT=950pkts) | 0.27 | 1.00 | T1 LOG | ⚠ solo IForest |
| Telnet completado (23, 5s) | 0.00 | 0.96 | T1 LOG | ⚠ IF detecta, ML no |
| C2 beacon (4444, 30s) | 0.49 | 0.53 | T1 LOG | ⚠ ambiguo |
| Web benigno (80, 250ms) | 0.49 | 0.37 | T1 LOG | ✓ no bloqueado |
| SSH sesión real (22, 8s) | 0.00 | 0.96 | T1 LOG | ~ aceptable |
| SSH brute force (900s) | ERROR | — | T0 ALLOW | ✗ fuera de rango |

**Decisión:** Documentar como limitación conocida del Golden 4 para la defensa de noviembre. El rango fue definido sobre el dataset académico Queensland donde las sesiones largas son raras. Para producción real, se recomienda clipear los flows largos al límite máximo (120.534ms) en Vector antes de enviarlo al motor, en lugar de rechazarlos.

**Valor para la tesis:** Demuestra que el sistema fue validado con casos reales, que se identificaron sus límites con precisión, y que el diseño híbrido ML+IForest compensa las debilidades del modelo supervisado en sesiones completadas.

---

<a id="h11"></a>
## H11 — API de Wazuh: payload incompatible en Active Response on-demand

**Fecha:** 2026-07-04
**Contexto:** Activación de R2 en modo enforce (bloqueo real vía Wazuh Active Response), tras validar R1/R2 en dry_run el 22 de junio.

**Hallazgo:** El payload inicial de enforcer.py (WazuhAPIEnforcer.block) fallaba con 400 Bad Request en TODAS las IPs reales, mientras que la autenticación (POST /security/user/authenticate) funcionaba correctamente. La salvaguarda de degradación diseñada en R2 funcionó como se esperaba: el motor no crasheó, solo registró block_skipped con el error. Se identificaron tres causas combinadas:
1. Faltaba el prefijo "!" en el nombre del comando ("!firewall-drop" en vez de "firewall-drop") — sin él, la API busca un binding <active-response> ya configurado en ossec.conf (inexistente en este manager), en vez de ejecutar el script directamente.
2. El campo "custom" es inválido en la API de Wazuh 4.14.5 y causa rechazo total del request (mensaje exacto: "Invalid field found {'custom'}").
3. La IP debe enviarse en alert.data.srcip, no en arguments — formato que espera internamente el script firewall-drop.

**Decisión:** Corregido el body en WazuhAPIEnforcer.block() a:
`{"command": f"!{wazuh_ar_command}", "alert": {"data": {"srcip": ip}}}`
Validado primero con curl manual aislado antes de reiniciar el worker, para descartar fallos en el resto del pipeline.

**Evidencia:** Bloqueo real confirmado en iptables del agente .138 sobre 3 IPs con abuse=100 en AbuseIPDB (85.217.149.73, 160.119.71.136, 91.231.89.90), TTL=1800s, ejecutados automáticamente por el worker en producción.

**Lección de diseño:** Un 400 Bad Request en la primera llamada real (no en pruebas triviales) es la razón por la que probar el payload exacto con curl antes de activar el modo enforce en el pipeline completo ahorra ciclos de debugging — el error habría sido indistinguible de un problema de red o credenciales sin aislar la llamada.

---

<a id="h12"></a>
## H12 — FIM ampliado a WordPress + bugs de sintaxis restrict y limitación de tiempo real

**Fecha:** 2026-07-05
**Contexto:** El análisis de "qué pasa si un atacante traspasa el perímetro" llevó a auditar el alcance real del FIM de Wazuh en .138 (servidor web). Se encontró que syscheck solo vigilaba rutas del sistema operativo (/etc, /usr/bin, etc.), dejando el webroot completo de WordPress/educasex sin ningún tipo de monitoreo de integridad.

**Hallazgo:** Se amplió syscheck para cubrir wp-admin, wp-includes, wp-content/plugins, wp-content/themes (vigilancia completa) y wp-content/uploads (vigilancia restringida solo a ejecutables vía atributo restrict, dado que ahí hay escritura legítima constante de WordPress). Surgieron dos problemas reales:
1. La sintaxis inicial del restrict (`\.(php|phtml|phar|php[0-9])$`, con grupo de alternancia entre paréntesis) es sintaxis PCRE no soportada por el motor sregex de Wazuh — el filtro coincidía con cero archivos en vez de fallar visiblemente. Corregido a `.php$|.phtml$|.phar$|.php[0-9]$` (patrones repetidos, sin paréntesis, sin escapar el punto), siguiendo el ejemplo oficial de Wazuh.
2. Tras corregir el restrict, el escaneo por lotes detecta y filtra correctamente (validado: 471 archivos en uploads/, solo 4 .php capturados). Pero la detección en tiempo real (realtime, basada en inotify) no procesa archivos nuevos en ninguna carpeta agregada — confirmado que el kernel entrega los eventos correctamente (probado con pyinotify de forma aislada), así que el problema está específicamente en cómo wazuh-syscheckd consume esos eventos. Sospecha no confirmada: relacionada a los ciclos de reconexión agente-manager (ver Pendientes).

**Decisión:** Mitigación mientras se investiga la causa raíz del bug de realtime: frecuencia del escaneo programado bajada de 12h a 5 minutos para syscheck (rootcheck se mantuvo en 12h). Acota la ventana de exposición de "hasta 12 horas sin detectar un webshell" a "hasta 5 minutos", con el restrict funcionando correctamente en modo batch.

**Evidencia:** 471 archivos totales bajo uploads/, 4 correctamente capturados con el restrict corregido (3 pruebas .php + 1 index.php legítimo de plugin). pyinotify confirmó entrega de eventos IN_CREATE/IN_CLOSE_WRITE del kernel en <1s. auditd/whodata evaluado como alternativa pero no instalado — queda para noviembre.

---

<a id="h13"></a>
## H13 — Segunda forma de respuesta activa: cuarentena de archivo para compromiso interno

**Fecha:** 2026-07-05 / 2026-07-06
**Contexto:** El análisis de "qué pasa si un atacante traspasa el perímetro" identificó que R2 solo sabe ejecutar una acción (bloqueo de IP externa vía firewall-drop), que no sirve si el compromiso ya ocurrió dentro de la infraestructura propia (protegida además por la safelist, correctamente). Se diseñó e implementó una segunda forma de Active Response: cuarentena de archivo, disparable cuando el FIM (H12) detecta un ejecutable nuevo en una carpeta de solo-uploads — señal de alta confianza de webshell.

**Hallazgo:** El script (quarantine-file, Python, registrado como Active Response custom) mueve el archivo sospechoso fuera del webroot servible a /var/ossec/quarantine/, con permisos 000 y un archivo .origin para trazabilidad/restauración manual — preserva evidencia en vez de borrar. Restringido por diseño a rutas dentro del webroot de educasex. Surgieron dos bugs de ingeniería no triviales:
1. Wazuh resolvió el `<executable>` configurado (quarantine-file.py) sin la extensión al invocar el script (invocó active-response/bin/quarantine-file, sin .py) — el archivo no existía con ese nombre exacto, sin error explícito, solo silencio. Corregido renombrando el script sin extensión (mismo patrón que los binarios nativos de Wazuh).
2. Bug más serio: el script usaba `sys.stdin.read()` (espera EOF) en vez de `sys.stdin.readline()` (espera \n). Wazuh no cierra el pipe de stdin tras enviar el JSON (protocolo de handshake check_keys/continue), así que el script quedó colgado indefinidamente esperando un EOF que nunca llega — deadlock clásico, advertido en la documentación oficial de Wazuh pero no verificado en el desarrollo inicial. Esto bloqueó wazuh-execd por completo durante ~3 minutos, deteniendo los bloqueos reales de R2 (firewall-drop) para tráfico malicioso real en producción durante esa ventana. Detectado por ausencia de actividad en active-responses.log, confirmado con ps aux (proceso python3 huérfano en estado sleeping), resuelto matando el proceso y corrigiendo el código.

**Decisión:** quarantine-file.py → quarantine-file (sin extensión). readline() en vez de read(). Validado el ciclo completo (FIM detecta archivo → API dispara cuarentena → archivo movido con permisos 000 → firewall-drop sigue operando en paralelo sin bloquearse) antes de dar el hallazgo por cerrado.

**Evidencia:** 3 archivos de prueba puestos en cuarentena exitosamente tras el fix. Confirmado que firewall-drop procesó tráfico real (IPs con abuse=100) inmediatamente antes y después del incidente de deadlock, acotando el impacto real a ~3 minutos.

**Lección de diseño:** un script de Active Response que se cuelga no solo falla su propia acción — bloquea TODO el pipeline de respuesta activa del agente, incluidas acciones ya validadas en producción (R2/firewall-drop). Todo script custom de AR debe probarse con `timeout` en pruebas manuales antes de conectarlo al pipeline real, y debe seguir el protocolo de lectura por línea (readline), no por EOF (read).

**Pendiente para noviembre:** la Pieza A del diseño (traer alertas FIM del manager de vuelta al motor de decisiones para clasificación automática T3) no se implementó — hoy la cuarentena se disparó manualmente vía API para validar el mecanismo, no automáticamente desde una alerta real.

---

<a id="h14"></a>
## H14 — Timeout de systemd insuficiente en wazuh-manager.service

**Fecha:** 2026-07-05
**Contexto:** Un `systemctl restart wazuh-manager` (necesario para cargar el comando de H13) falló con timeout, marcando el servicio como failed pese a que los daemons reales (incluidos wazuh-analysisd y wazuh-remoted) seguían arrancando y terminaban operativos como procesos huérfanos.

**Hallazgo:** El unit de systemd de Wazuh trae TimeoutSec=45, insuficiente para un arranque completo bajo carga real (~40-50s medidos, margen ajustado). systemd mata el proceso ExecStart al cumplirse el timeout, pero los daemons ya lanzados sobreviven como huérfanos y siguen funcionando — generando un falso "failed" que no refleja el estado real del servicio.

**Decisión:** Override permanente vía drop-in de systemd (/etc/systemd/system/wazuh-manager.service.d/override.conf), sin modificar el unit file del paquete. TimeoutStartSec=180, TimeoutStopSec=60.

**Evidencia:** Tras el override, `systemctl restart wazuh-manager` completa limpio (active (running), status=0/SUCCESS) sin intervención manual con wazuh-control.

**Lección de diseño:** un estado "failed" de systemd no siempre significa que el servicio esté caído — puede ser un falso negativo de monitoreo. Verificar el estado funcional real (agent_control -l, API respondiendo) antes de asumir una falla real.

---

<a id="h15"></a>
## H15 — Caída de Redis expone falta de supervisión de proceso en response.worker

> **Nota (auditoría 2026-08-25):** la Decisión de este hallazgo es un diseño
> (`response-worker.service` con `Requires=`/`Restart=on-failure`), no una confirmación de
> implementación. No aparece en `docs/BACKLOG_INFRA.md` ni en la sección Pendientes de este
> documento como ítem abierto, así que su estado real (¿se creó el unit file? ¿sigue
> corriendo como proceso manual sin supervisión?) queda ambiguo para un lector nuevo.
> Confirmar y actualizar esta nota con el estado real antes de la defensa.

**Fecha:** 2026-08-11

**Contexto:** `redis-server.service` (`.140`) dejó de estar disponible entre las 06:49 y las 22:34 (~15.5h). `motor-soc` (FastAPI, Fast Path) degradó con gracia como estaba diseñado — decisiones provisionales continuaron sin bloquear por IO externo. `response.worker`, en cambio, corría en ese momento como proceso sin supervisión de systemd (lanzado manualmente, sin unit propio), sin `Requires=redis-server.service` ni política de `Restart=`.

**Hallazgo:** Al perder la conexión a Redis, `response.worker` no terminó ni entró en un ciclo de retry visible — quedó como proceso vivo pero funcionalmente muerto (zombie): sin consumir la stream `soc:response:tasks`, sin nuevas líneas `[ENFORCE]` en `worker.log`, sin excepción no capturada que un supervisor pudiera detectar. Cuando `redis-server.service` volvió a las 22:34, el worker **no** retomó el consumo por sí solo — siguió colgado en el mismo estado hasta que se lo mató manualmente (`kill`/`pkill`) y se relanzó a mano. El motor (FastAPI) sí se recuperó automáticamente al reconectar con Redis, confirmando que la degradación con gracia funciona correctamente en el Fast Path — el punto ciego era exclusivamente el worker.

**Causa raíz:** Evento de reinicio masivo de servicios a las 06:49:02, patrón consistente con `unattended-upgrades`/`needrestart` tras la actualización de una librería compartida (121 actualizaciones pendientes, flag "system restart required" confirmado en el sistema). Docenas de servicios no relacionados se reiniciaron limpio en esa misma ventana; `redis-server` fue de los pocos en fallar el reinicio automático — exit-code 1, 5 intentos agotados antes de que systemd desistiera con "Start request repeated too quickly for redis-server.service".

**Factor contribuyente:** `vm.overcommit_memory=0` en el host. El propio log de Redis advierte explícitamente que este valor puede causar fallos de arranque incluso sin baja memoria real (Redis necesita poder hacer `fork()` para el guardado en background del RDB; con overcommit=0 el kernel puede rechazar esa asignación bajo ciertas condiciones de memoria virtual comprometida). **Recomendación pendiente de aplicar** — al 2026-08-12 el valor sigue en `0`; no se cambió a `vm.overcommit_memory=1` (sin acceso SSH a `.140` para ejecutarlo o confirmarlo; ver bloqueo de acceso registrado en la sesión de auditoría del 2026-08-12).

**Decisión:** Diseñar `response-worker.service` (systemd) con `Requires=redis-server.service`, `Restart=on-failure`, `RestartSec=5`, y `StartLimitIntervalSec=300`/`StartLimitBurst=6` calibrados para tolerar una reconexión breve pero no una caída sostenida — tras agotar el burst, el servicio queda en `failed` de forma visible en lugar de reintentar indefinidamente en silencio, forzando intervención humana ante un corte largo de Redis en vez de repetir el zombie de hoy en otra forma. Logging mantenido en `worker.log` (vía `StandardOutput=append:`) para no romper el paso 1 de la metodología de auditoría del skill `soc-audit`, que cuenta líneas `[ENFORCE]` ahí.

**Evidencia:** Ventana de caída confirmada 06:49–22:34 (2026-08-11) en `journalctl -u redis-server` / ausencia de `[ENFORCE]` nuevos en `worker.log` durante ese rango. Proceso `response.worker` confirmado vivo pero sin actividad (`ps aux` mostraba PID activo sin avance de logs) antes del kill manual. El log específico de `redis-server` para la ventana del incidente (11 de agosto) ya no existe por rotación semanal — la causa raíz se reconstruyó vía `journalctl` del sistema (timestamps, exit codes y unidades reiniciadas), no del log de Redis mismo.

**Nota metodológica — impacto en auditorías futuras:** el paso 1 de la metodología de `soc-audit` (comparar 1:1 líneas `[ENFORCE]` de `worker.log` contra `"command":"add"` en `active-responses.log` de `.138`) **debe excluir o marcar por separado la ventana 06:49–22:34 del 2026-08-11** al calcular cualquier discrepancia de conteo que abarque este día. Durante esa ventana el worker no procesó tareas por el zombie documentado acá, no por pérdida o duplicación real del pipeline — cualquier auditoría que cubra este rango sin anotar la exclusión reportaría una discrepancia inexplicada que en realidad ya está explicada y resuelta en este hallazgo.

---

<a id="h16"></a>
## H16 — Punto ciego estructural: Suricata no ve tráfico directo al uplink ISP de .138

> **Superado — auditoría 2026-08-25:** este punto ciego fue resuelto arquitectónicamente
> por la migración a NAT/VLAN documentada en H17 (`.139` pasa de sensor pasivo a punto de
> paso in-line), y la confirmación empírica pendiente que H17 dejó abierta ("repetir la
> prueba de H16") se cerró en H21 (mismo día, causa distinta encontrada en el camino: orden
> de reglas de firewall). Se conserva el hallazgo original íntegro por su valor metodológico
> — documenta un punto ciego real y por qué "mismo subnet IP" no implica "misma visibilidad
> de captura", lección que sigue aplicando a cualquier sensor pasivo futuro.

**Fecha:** 2026-08-13

**Contexto:** Al probar end-to-end la Parte A de detección experimental L7 (Suricata + los 9 SIDs de scanner/herramienta curados en `infra/suricata/enable.conf`), se envió tráfico de prueba real contra la landing page desplegada en `.138` (`curl` con payload de SQLi genérico `UNION ALL SELECT` y de path traversal unicode `..%c0%af..`, desde una IP pública externa real). Las alertas esperadas nunca aparecieron en `eve.json` de `.139` — ni siquiera como evento `http` normal sin alerta, lo que descartó de entrada explicaciones de encoding del payload o de umbral de regla (`sid:2012754` tiene además un `detection_filter` de 4 hits/20s, pero eso por sí solo no explica la ausencia total de cualquier rastro del tráfico).

**Hallazgo:** `.138` tiene dos interfaces de red físicas con rutas por defecto independientes:
```
eno1: 200.54.12.138/29 → gateway 200.54.12.137    (uplink directo al ISP)
eno2: 192.168.153.41/24 → gateway 192.168.153.254  (LAN interna del proyecto, DHCP)
```
El tráfico de prueba, dirigido directamente a la IP pública `200.54.12.138`, entra por `eno1` y nunca atraviesa ningún segmento visible para `.139`. La interfaz que Suricata captura en `.139` (`af-packet: interface: eno2`, IP `200.54.12.139/29`) está en el **mismo bloque `/29`** que `eno1` de `.138` — pero pertenecer al mismo subnet IP no implica visibilidad de captura en una red conmutada: un switch solo entrega a un puerto el tráfico dirigido a su propia MAC, salvo que exista un puerto espejo (SPAN/mirror) configurado explícitamente, y no hay evidencia de que exista tal mirror. Por eso Suricata solo ve tráfico donde `.139` mismo es origen o destino directo — confirmado con tráfico real ya presente en `eve.json`: scraping de Prometheus `.138→.139:9100`, un flow `.139→.138:80` originado por el propio `.139`, y peticiones del scanner externo real `l9explore` que sí aparecen logueadas — pero con `src_ip:200.54.12.139` en vez de la IP real del scanner (`45.148.10.125`, visible solo en un campo adicional), es decir, ese tráfico llegó a `.138` relayado a través de `.139` por algún mecanismo no investigado en esta sesión, no entrando directo por el ISP.

**Decisión:** No se investiga ni se configura el puerto espejo esta semana — requiere acceso físico al switch (fuera del control directo del proyecto) y no hay tiempo de validarlo con seguridad antes de la próxima sesión. Se documenta como punto ciego estructural conocido de la Parte A. La detección L7 experimental sigue siendo válida para tráfico que efectivamente atraviese `.139` (confirmado con `l9explore`), pero **no detecta tráfico dirigido directamente a la IP pública de `.138` vía su uplink ISP propio** — que es, en un escenario realista, el camino más probable de un atacante apuntando directo a la IP publicada.

**Evidencia:**
- `curl -v "http://200.54.12.138/?id=1%20UNION%20ALL%20SELECT%20NULL--%20AND%201=1"` desde IP pública `201.188.180.46`, corrido dos veces (`05:27:50 UTC` y `06:27:51 UTC`) — confirmado `200 OK` real vía `docker logs demo-landing` en `.138` (contenedor nginx que sirve la landing page).
- Cero coincidencias en `eve.json` completo (14.6GB) para `UNION%20ALL` y para `c0%af` (payload de traversal), en cualquier punto del archivo — no solo en la ventana de tiempo del test.
- `ip -4 addr show` en `.138`: `eno1: 200.54.12.138/29`, `eno2: 192.168.153.41/24`; `ip route show default` confirma dos rutas por defecto independientes, una por interfaz.
- `ip -4 addr show eno2` en `.139`: `200.54.12.139/29` — mismo `/29` que `eno1` de `.138`.
- Tráfico del scanner `l9explore` (IP real `45.148.10.125`) presente en `eve.json` con `src_ip:200.54.12.139`, confirmando que Suricata ve tráfico que efectivamente pasa por `.139`, pero no el que entra directo por `eno1` de `.138`.

**Lección de diseño:** estar en el mismo subnet IP no implica estar en el mismo dominio de visibilidad de captura de paquetes en una red conmutada. Cualquier arquitectura de monitoreo pasivo (Suricata, tcpdump, o similar) en un solo host necesita puerto espejo explícito hacia cada segmento físico que se quiera observar — la topología IP por sí sola no lo garantiza. Vale como advertencia general para cualquier despliegue futuro de sensores de red en este proyecto, no solo para `.138`.

<a id="h17"></a>
## H17 — Migración de topología: de subred plana a NAT/gateway con VLANs, cerrando el punto ciego de H16

> **Nota de alcance (auditoría 2026-08-25):** el Hallazgo describe el diseño completo de
> switch/VLANs para los cuatro servidores, lo que puede leerse como que los cuatro ya
> operaban sobre la nueva topología al cerrar esta entrada. En la práctica, a la fecha de
> esta auditoría solo `.139` (gateway) y `.140` (motor, `10.10.10.3`) están efectivamente
> migrados y verificados; `.138`, `.141` y `.142` siguen con su acceso/IP pública vieja,
> pendientes de migración física (`.141`/`.142` ni siquiera están cableados al switch aún).
> Estado vivo de cada host en la tabla de Infraestructura de `CLAUDE.md`. Este hallazgo no
> se corrige — se aclara para que un lector nuevo no asuma una migración total ya cerrada.

**Fecha:** 2026-08-19

**Contexto:** H16 documentó que Suricata en `.139` operaba como sensor pasivo dependiente de que el tráfico atravesara físicamente esa interfaz, sin puerto espejo hacia el uplink ISP directo de `.138`, lo que dejaba fuera de visibilidad cualquier tráfico dirigido directo a la IP pública de un servidor protegido. Para cerrar ese punto ciego estructural se rediseñó la topología completa de red del proyecto, pasando de una subred plana única (`200.54.12.136/29` compartida entre todos los hosts) a una topología NAT/gateway con VLANs, donde `.139` deja de ser un sensor pasivo y pasa a ser el punto de paso físico obligatorio (in-line) de todo el tráfico entre el router ISP y los cuatro servidores del proyecto.

**Hallazgo:** La nueva topología quedó así: Router ISP 892FSP (`.137`) hacia `.139` (interfaz `eno1` con la IP pública `200.54.12.139/29` hacia el ISP, interfaz `eno2` como trunk hacia el switch, actuando como NAT gateway y sensor Suricata in-line) hacia el switch Cisco SG350 hacia los cuatro servidores en VLANs separadas. En el switch se crearon tres VLANs: VLAN 10 (producción del motor, puerto gi2 hacia `.140`, subred `10.10.10.0/24`), VLAN 20 (terceros, puerto gi3 hacia `.141` y gi4 hacia `.142`, subred `10.20.20.0/24`) y VLAN 30 (web genérica, puerto gi1 hacia `.138`, subred `10.30.30.0/24`), con el puerto gi6 como trunk hacia `.139` permitiendo las tres VLANs. La sesión SPAN que existía antes (monitor session 1, gi1-5 como source, gi6 como destination) se eliminó por quedar obsoleta: ya no hace falta espejar tráfico para que Suricata lo vea, porque ahora pasa físicamente por `.139`. En `.139` se crearon subinterfaces VLAN sobre `eno2` vía NetworkManager (`eno2.10` en `10.10.10.1/24`, `eno2.20` en `10.20.20.1/24`, `eno2.30` en `10.30.30.1/24`), se activó `ip_forward`, y se agregó NAT vía MASQUERADE en `/etc/ufw/before.rules` para que las tres subredes salgan a Internet por `eno1`. Las reglas UFW que antes apuntaban a la subred pública vieja `200.54.12.136/29` (API de Wazuh 55000, Node Exporter 9100, xRDP 3389, agentes Wazuh 1514/1515) se migraron a las tres VLANs nuevas, con un criterio de separación explícito: los puertos de monitoreo (1514, 1515, 9100) quedaron abiertos a las tres VLANs, mientras que los de administración (55000, 3389) quedaron restringidos únicamente a VLAN 10.

Se verificó el estado real de `.139` por SSH antes de cerrar este hallazgo. `ip -4 addr show` confirma `eno1` con `200.54.12.139/29` y las tres subinterfaces `eno2.10`, `eno2.20`, `eno2.30` con las IPs `.1` de cada VLAN; `ip route show` confirma las tres rutas `10.10.10.0/24`, `10.20.20.0/24` y `10.30.30.0/24` cada una vía su subinterfaz; `cat /proc/sys/net/ipv4/ip_forward` devuelve `1`; `nmcli connection show` confirma los tres perfiles `vlan10`/`vlan20`/`vlan30` con `vlan.parent: eno2` e `id` 10/20/30 respectivamente; `ip link show eno2` confirma la interfaz física up sin IP propia, consistente con su rol de trunk. `iptables -L ufw-user-input -n -v` confirma exactamente el criterio de separación descrito: reglas para 1514/1515/9100 (TCP y UDP) repetidas para `10.10.10.0/24`, `10.20.20.0/24` y `10.30.30.0/24`, y reglas para 55000/3389 presentes únicamente para `10.10.10.0/24`. La regla NAT/MASQUERADE en `/etc/ufw/before.rules` y la tabla `nat` de iptables no se pudieron leer en esta sesión porque el `sudo` restringido de auditoría solo permite `iptables -L*` (sin `-t nat`) y no incluye lectura de `/etc/ufw/before.rules`; se toma como evidencia indirecta suficiente que `ip_forward=1` está activo y que las tres VLANs tienen salida a Internet operativa según lo reportado por el usuario.

**Decisión:** Adoptar la topología NAT/gateway con VLANs como arquitectura de red estable del proyecto, reemplazando la subred plana original. `.139` pasa de sensor pasivo a punto de paso in-line, lo que resuelve de raíz el punto ciego documentado en H16 para tráfico dirigido directo a la IP pública de cualquier servidor detrás del gateway: ahora todo ese tráfico atraviesa `.139` por diseño, no por coincidencia de que el atacante relaye a través de él. Queda pendiente repetir en una sesión futura la prueba de H16 (payload SQLi/traversal contra un servidor VLAN) para confirmar empíricamente que las alertas de Suricata ahora sí se generan.

**Evidencia:** Salida real de `ip -4 addr show`, `ip route show`, `ip_forward`, `nmcli connection show` e `iptables -L ufw-user-input -n -v` capturada por SSH en `.139` el 2026-08-19, resumida en el hallazgo anterior.

---

<a id="h18"></a>
## H18 — Riesgo de coincidencia por comodín en perfil NetworkManager de `.139`, corregido antes de causar incidente

**Fecha:** 2026-08-19

**Contexto:** Durante la migración de topología (H17), se revisaron los perfiles de NetworkManager en `.139` que gestionan la interfaz con la IP pública del proyecto, para asegurar que la nueva interfaz de trunk `eno2` no terminara heredando por error configuración destinada a la interfaz pública `eno1`.

**Hallazgo:** El perfil `netplan-zz-all-en` tenía configurado `match.interface-name=en*` (comodín), en vez de fijar la interfaz por nombre exacto. Bajo ese comodín, el perfil podía potencialmente coincidir también con `eno2` (la interfaz de trunk hacia el switch) y no solo con `eno1`, con el riesgo de que NetworkManager aplicara la IP pública `200.54.12.139/29` sobre la interfaz de trunk en vez de sobre la interfaz hacia el ISP. El riesgo se detectó por revisión de configuración antes de que se manifestara como incidente real.

**Decisión:** Se corrigió el perfil fijando `connection.interface-name=eno1` explícito y quitando el `match.interface-name` comodín. Verificado por SSH en `.139` con `nmcli connection show netplan-zz-all-en`: `connection.interface-name` es `eno1` y `match.interface-name` quedó vacío (`--`). Existe además un segundo perfil, `netplan-eno1`, con `connection.interface-name=eno1` también pero sin activar (no aparece como dispositivo conectado en `nmcli connection show`); no se tocó por no representar riesgo mientras permanezca inactivo, queda como candidato a limpieza en una sesión futura.

**Evidencia:** `nmcli connection show netplan-zz-all-en | grep -E 'match|interface-name'` en `.139`, 2026-08-19, confirma `connection.interface-name: eno1` y `match.interface-name: --`.

---

<a id="h19"></a>
## H19 — Cambio de VLAN de gestión del switch SG350 genera "no route to host" transitorio por dominios de capa 2 distintos

**Fecha:** 2026-08-19

**Contexto:** Como parte de la migración de topología (H17), se movió la IP de gestión del switch SG350 de VLAN 1 (`10.10.10.1`, sin etiquetar) a VLAN 10 (`10.10.10.254`, junto al resto del equipo de producción del motor), para que la administración del switch quedara dentro del mismo segmento que el equipo de tesis en vez de en la VLAN nativa por defecto.

**Hallazgo:** Al completar el cambio se produjo brevemente un error "no route to host" al intentar administrar el switch. La causa no fue un error de direccionamiento sino de segmentación: el gateway en `.139` (`eno2.10`, `10.10.10.1/24`) y la gestión del switch en su ubicación anterior (VLAN 1, no etiquetada) vivían en dominios de capa 2 distintos aunque compartieran el mismo rango numérico `10.10.10.0/24` — coincidencia de direccionamiento IP que no implica pertenecer al mismo segmento conmutado, el mismo tipo de confusión ya documentado en H16 para el caso de captura de paquetes.

**Decisión:** La gestión del switch queda definitivamente en VLAN 10, junto al equipo de tesis, resolviendo el error una vez que ambos extremos comparten el mismo dominio de capa 2. Se deja como advertencia general del proyecto: compartir rango numérico no equivale a compartir segmento de red, ya sea para gestión, para captura de paquetes (H16) o para cualquier otro propósito de conectividad de capa 2.

**Evidencia:** Reportado por el usuario durante la migración; no verificable retroactivamente por SSH al ser un estado transitorio de administración del switch (fuera del alcance de acceso SSH de esta sesión, limitado a los tres servidores Linux del proyecto).

---

<a id="h20"></a>
## H20 — Switch SG350 con firmware v2.4.0.94 solo ofrece algoritmos SSH obsoletos

**Fecha:** 2026-08-19

**Contexto:** Al intentar administrar el switch SG350 por SSH tras la migración de topología (H17), la conexión falló con clientes OpenSSH modernos.

**Hallazgo:** El firmware v2.4.0.94 del switch solo ofrece algoritmos de intercambio de llaves y de host key ya deprecados por defecto en OpenSSH moderno: `diffie-hellman-group1-sha1` y `diffie-hellman-group14-sha1` como `KexAlgorithms`, y `ssh-rsa`/`ssh-dss` como `HostKeyAlgorithms`. Un cliente OpenSSH sin esos algoritmos habilitados explícitamente rechaza la negociación antes de llegar a pedir credenciales.

**Decisión:** Workaround aplicado en el cliente, forzando los algoritmos legacy en la invocación de SSH con `-oKexAlgorithms=+diffie-hellman-group14-sha1` y `-oHostKeyAlgorithms=+ssh-rsa` (u equivalentes según el cliente). Queda pendiente evaluar la actualización de firmware del switch para dejar de depender de algoritmos obsoletos en el canal de gestión.

**Evidencia:** Reportado por el usuario durante la migración; no verificable retroactivamente por SSH al ser un estado del propio switch (fuera del alcance de acceso SSH de esta sesión, limitado a los tres servidores Linux del proyecto).

---

<a id="h21"></a>
## H21 — Suricata in-line con cero alertas: la cola NFQUEUE recibía tráfico pero el firewall solo dejaba pasar el primer paquete de cada conexión

**Fecha:** 2026-08-25

**Contexto:** Como parte del pendiente dejado por H17 (repetir la prueba de H16 sobre la
nueva topología NAT/VLAN, para confirmar empíricamente que Suricata genera alertas para
tráfico dirigido a un servidor detrás del gateway), se pasó a Suricata en `.139` a modo
in-line real vía NFQUEUE — interceptando activamente el tráfico en la ruta de netfilter, no
solo capturándolo pasivamente por AF-PACKET como antes de H17. Se repitió tráfico de prueba
equivalente al de H16 contra un host detrás del gateway. Confirmado que el tráfico
efectivamente atravesaba la cola NFQUEUE (contadores de la regla incrementando), pero
`eve.json` seguía sin registrar ninguna alerta — ni las esperadas, ni ningún evento en
absoluto para ese tráfico.

**Hallazgo:** Se descartaron en orden: reglas de Suricata mal cargadas, permisos de lectura
sobre el ruleset, y el modo de captura configurado en `suricata.yaml`. La causa raíz estaba
en `/etc/ufw/before.rules`: la regla de fast-path para tráfico ya establecido (`ct state
RELATED,ESTABLISHED ACCEPT` / equivalente `-m state --state RELATED,ESTABLISHED -j ACCEPT`)
aparecía **antes** que la regla que desvía tráfico a la cola NFQUEUE de Suricata. Netfilter
evalúa las reglas en orden y aplica la primera que hace match: en cuanto el primer paquete
(SYN) de una conexión nueva pasaba por NFQUEUE y Suricata lo dejaba seguir, conntrack
marcaba esa conexión como ESTABLISHED — y todos los paquetes siguientes de esa misma
conexión (el resto del handshake, el payload real, la respuesta del servidor) hacían match
con la regla de fast-path *antes* de llegar a la regla NFQUEUE, sin pasar nunca por
Suricata. Efecto práctico: Suricata solo veía el primer paquete de cada conexión — no
alcanza para que la inmensa mayoría de los SIDs (que inspeccionan payload HTTP, múltiples
paquetes del stream, o la respuesta) disparen ninguna alerta. No era un problema de reglas
de Suricata ni de la cola NFQUEUE en sí — el tráfico nunca llegaba completo a Suricata.

**Decisión:** Reordenar `/etc/ufw/before.rules` para que la desviación a NFQUEUE preceda a
la regla de fast-path `RELATED,ESTABLISHED ACCEPT`, de modo que todo paquete de toda
conexión pase por Suricata antes de que conntrack pueda aplicar el atajo. Suricata se dejó
además como servicio systemd persistente vía
`/etc/systemd/system/suricata.service.d/override.conf` (mismo patrón de drop-in ya usado en
H14 para `wazuh-manager.service`, sin tocar el unit file empaquetado), para que el modo
in-line sobreviva a un reinicio del host sin relanzarlo a mano.

**Lección generalizable:** en cualquier firewall (iptables/nftables/ufw, en cualquier host
presente o futuro del proyecto) que combine reglas de fast-path para tráfico establecido con
una desviación a un motor IPS/NFQUEUE, las reglas de fast-path deben ir **siempre después**
de la desviación al IPS — nunca antes. Puestas antes, el "atajo" de aceleración para tráfico
ya establecido se convierte, sin que nadie lo decida explícitamente, en un bypass casi total
del IPS: solo el primer paquete de cada conexión nueva llega a inspeccionarse.

**Detalles secundarios encontrados en el camino (no son la causa raíz, pero se corrigieron
en la misma sesión):**
- `eve.json` y `stats.log` habían crecido a 16GB+ sin rotación configurada. Esto es
  continuación del mismo problema ya documentado en `docs/BACKLOG_INFRA.md` (detectado
  2026-08-12 con `eve.json` en 14.6GB) — no es un hallazgo nuevo, es el mismo riesgo sin
  mitigar, ahora también en `stats.log` y con más volumen. `logrotate` para ambos archivos
  sigue pendiente de configurar (ver ese documento para la propuesta ya escrita).
- Permisos rotos entre `root` y el usuario `suricata` tras pruebas manuales del proceso
  durante el diagnóstico (se había ejecutado/tocado archivos como `root` en el camino,
  dejando algunos artefactos sin el owner correcto para que el servicio systemd, que corre
  como `suricata`, los leyera/escribiera) — corregido antes de dejar el servicio persistente.

**Evidencia:** Retest confirmado tras el reordenamiento de `before.rules` — Suricata volvió
a generar alertas para tráfico que atraviesa el gateway hacia un host detrás de una VLAN,
cerrando en firme el pendiente que H17 había dejado abierto:

```
08/25/2026-16:00:28.323021 [**] [1:2100498:7] GPL ATTACK_RESPONSE id
check returned root [**] [Classification: Potentially Bad Traffic]
[Priority: 2] {TCP} 217.160.0.187:80 -> 10.10.10.3:37796
```

Esta alerta (SID 2100498, `GPL ATTACK_RESPONSE id check returned root`) dispara sobre la
*respuesta* de una conexión — no sobre el primer paquete (SYN) de la conexión, sino sobre
contenido de payload en un paquete posterior del stream ya establecido. Es exactamente el
tipo de alerta que la causa raíz de este hallazgo (fast-path `ESTABLISHED,RELATED` evaluado
antes que la desviación a NFQUEUE) impedía ver: antes del fix, esta alerta específica no
podría haber disparado nunca, porque todo paquete posterior al primero de la conexión
saltaba a Suricata vía el atajo de conntrack. Que dispare confirma que el stream completo
—no solo el SYN— vuelve a pasar por Suricata tras reordenar `before.rules`. Con esto se
cierra también el pendiente original de H17 (repetir la prueba de H16 sobre la nueva
topología NAT/VLAN).

**Addendum — verificación independiente (SSH en `.139`, 2026-08-26):** confirmado
directamente en la tabla `filter`, cadena `ufw-before-forward` (no `ufw-before-input` — el
tráfico hacia hosts VLAN se reenvía, no se destina a `.139` mismo): posición 5 `NFQUEUE num
0 bypass` (18.065 paquetes / 9,76MB acumulados desde el arranque), posición 6 `ctstate
RELATED,ESTABLISHED ACCEPT` — el orden corregido descrito en la Decisión ya está aplicado y
en producción. `eve.json` registra exactamente 2 alertas desde que Suricata arrancó en este
modo (`ActiveEnterTimestamp` 2026-08-25 15:58:46), ambas SID 2100498, ambas contra
`10.10.10.3` — la segunda es la citada arriba.

Dos hallazgos adicionales de esta verificación, no solicitados pero registrados para no
perderlos:
- **Corrección de tamaño:** `eve.json` pesa hoy 83MB, no 16GB+ — bajó desde el diagnóstico
  del día anterior, consistente con una rotación o truncado al aplicar `override.conf` y
  reiniciar el servicio (mecanismo exacto no confirmado). `stats.log` sigue en 13GB — el
  problema de logrotate de `docs/BACKLOG_INFRA.md` (2026-08-12) sigue sin resolver y ahora
  pesa también sobre este archivo.
- **NFQUEUE en modo `bypass`:** si Suricata deja de leer la cola (caída, reinicio lento), el
  tráfico no se bloquea por defecto — sigue pasando sin inspección (fail-open, no
  fail-closed). Puede ser una decisión de diseño razonable para no tumbar la red si Suricata
  falla, pero es una limitación conocida que vale la pena dejar explícita para la sección de
  autocrítica de la tesis. No se cambió nada de la configuración; queda como candidato a
  hallazgo propio futuro (numeración pendiente — H22 ya se usó para el incidente de Redis
  del 2026-09-02) si se decide investigar o mitigar.

---

<a id="h22"></a>
## H22 — Redis caído por bind a IP pública obsoleta tras la migración a VLAN — `motor-soc.service` casi 1 semana sin levantar por "Dependency failed"

**Fecha:** 2026-09-02 (la caída real empezó el 2026-08-26, con un episodio previo el 2026-08-11)

**Contexto:** Verificación de rutina de conectividad SSH a `.139` y `.140`, seguida de una limpieza de sesiones de `systemd-logind` acumuladas en `.140` (8 sesiones huérfanas de la cuenta de operación, la mayoría con proceso líder ya muerto). Antes de cerrar una de ellas (`session-1706.scope`) se encontró que tenía dentro un proceso `opensearch_indexer.py` con PID vivo desde 2026-07-04 — señal de que no era una sesión vacía, lo que llevó a investigar en vez de cerrarla directamente.

**Hallazgo:** Encadenamiento de tres problemas en `.140`, todos con la misma causa raíz:

1. **`redis-server.service` fallaba en cada arranque** con `bind: Cannot assign requested address` sobre `200.54.12.140:6379`. `/etc/redis/soc-motor.conf` (incluido al final de `redis.conf` vía `include`, por lo que sobreescribe el `bind 127.0.0.1 -::1` por defecto) tenía `bind 127.0.0.1 200.54.12.140` — la IP pública que `.140` tenía **antes** de migrar a NAT/VLAN (H17). Desde que `.140` vive solo en `10.10.10.3` (VLAN 10), esa IP ya no existe en ninguna interfaz del host, y como la dirección no lleva el prefijo `-` (que le indicaría a Redis "intentá, pero no fallés si no está disponible"), Redis abortaba el arranque completo en vez de omitir solo esa dirección. El log de systemd muestra el mismo fallo repitiéndose en cada intento de reinicio del host: 2026-08-11 06:49 (coincide con el evento de `unattended-upgrades` ya descrito en H15), 2026-08-26 06:32, y 2026-08-30 04:00 — cada uno agotando 5 reintentos antes de "Start request repeated too quickly".
2. **`motor-soc.service`** (el motor FastAPI real, Fast Path) declara `Requires=`/`After=redis-server.service`. Cuando Redis falló el 2026-08-26 06:32, systemd marcó el arranque de `motor-soc` como "Dependency failed" — un tipo de fallo que **no** activa la política `Restart=` del propio servicio, porque el servicio nunca llega a arrancar: no se reintenta solo, queda muerto hasta un trigger externo (reboot u orden manual). Resultado: el motor de decisiones real estuvo inactivo desde 2026-08-26 06:32 hasta 2026-09-02 15:50 — casi 6 días y 9 horas — sin ningún reintento automático y sin ninguna alerta, mientras Redis seguía fallando en cada ventana de reinicio del host (el episodio del 2026-08-30 04:00 confirma que el problema persistía, no que fue un evento aislado).
3. **`opensearch-indexer.service`** (indexador del hash-chain de `soc-decisions`) tiene el mismo `Requires=redis-server`, pero con `Restart=always`/`RestartSec=10`, así que quedó crasheando en loop indefinido en vez de morir como `motor-soc`. La única razón por la que algo seguía indexando durante la caída fue un proceso manual huérfano (`opensearch_indexer.py`, PID vivo desde 2026-07-04) corriendo dentro de una sesión SSH que se cortó ese mismo día por "Connection reset by peer" y nunca se cerró — exactamente el mismo patrón de "proceso sin supervisión de systemd" que H15 documentó para `response.worker`, esta vez en el indexador. Al restaurar el servicio systemd sano quedaron los dos corriendo un momento; se confirmó por el log del proceso nuevo que usa un *consumer group* de Redis Streams (`INFO Consumer group... existe`) antes de matar el huérfano, para no asumir que la duplicación era inofensiva sin evidencia.

**Causa raíz:** `/etc/redis/soc-motor.conf` nunca se actualizó al migrar `.140` de IP pública directa a VLAN privada (H17, cerrado 2026-08-25/26) — el mismo día en que, según el log de systemd, Redis empezó a fallar en cada arranque (2026-08-26 06:32). La migración de red cambió la superficie de direcciones del host, pero no se revisaron los `bind` de servicios que antes también escuchaban en la IP pública.

**Decisión:**
- `soc-motor.conf` corregido a `bind 127.0.0.1` (se quita la IP pública obsoleta). Redis solo lo usan servicios del mismo host (motor, indexador) — nadie externo necesita hablarle directo, así que además de arreglar el arranque esto reduce la superficie de exposición respecto a la config anterior.
- Reinicio en orden: `redis-server` → `motor-soc.service` (verificado con `/health`: `{"status":"ok","model_version":"golden4_v7_1","model_real":true,"iforest_real":true}`) → confirmado que `opensearch-indexer.service` reconectó solo.
- Matado el proceso indexador huérfano (PID vivo desde 2026-07-04) una vez confirmado que el de systemd ya procesaba sano.
- Limpiadas las 8 sesiones huérfanas de `systemd-logind` en `.140` — varias no se liberaban con `loginctl terminate-session` (bug conocido de logind cuando el scope queda vacío); hubo que pararlas por su unidad `systemd` directamente (`systemctl stop session-N.scope`, `systemctl stop user@<uid>.service` para el manager de escritorio residual).
- **Pendiente, no resuelto en esta sesión:** no existe monitoreo de `motor-soc.service` ni de `redis-server.service` en `.140`. El único heartbeat activo (`vigilante/heartbeat_check.py`) vigila `motor-watcher.service` en `.139` (el lazo FIM), no el motor de decisiones — y ese mismo heartbeat depende de una conexión a Redis sin `try/except` alrededor (`redis.Redis(...).get(...)` directo), así que durante esta misma caída de Redis tampoco habría podido avisar de nada. Es la misma clase de punto ciego que H15 señaló para `response.worker`, ahora confirmada también en el propio motor y en su mecanismo de alerta — candidato fuerte para `docs/BACKLOG_INFRA.md`.

**Evidencia:**
```
# journalctl -u redis-server (extracto)
Aug 26 06:32:04 iaubo systemd[1]: redis-server.service: Failed with result 'exit-code'.
Aug 30 04:00:49 iaubo systemd[1]: redis-server.service: Start request repeated too quickly.

# log de arranque de Redis
Warning: Could not create server TCP listening socket 200.54.12.140:6379: bind: Cannot assign requested address
Failed listening on port 6379 (tcp), aborting.

# motor-soc.service
Aug 26 06:32:04 iaubo systemd[1]: Dependency failed for motor-soc.service — Motor de Decisiones SOC.
Aug 30 04:00:47 iaubo systemd[1]: Dependency failed for motor-soc.service — Motor de Decisiones SOC.
Sep 02 15:50:29 iaubo systemd[1]: Started motor-soc.service — Motor de Decisiones SOC — Tesis UBO.
Sep 02 15:51:48 iaubo uvicorn[661929]: 127.0.0.1:46960 - "GET /health HTTP/1.1" 200 OK

# /etc/redis/soc-motor.conf, antes / después
- bind 127.0.0.1 200.54.12.140
+ bind 127.0.0.1
```
Indexador huérfano: PID 2256436, arranque `Jul04` confirmado por `ps -ef`, viviendo dentro de `session-1706.scope` (`loginctl session-status 1706`), asociado a una sesión SSH cortada ese mismo día por "Connection reset by peer".

**Impacto en la tesis:** ventana real de motor de decisiones inactivo ≈6 días 9h (2026-08-26 06:32 → 2026-09-02 15:50). Cualquier análisis de disponibilidad o métricas de valor que cubra este período (sección 7 de `docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`, "disponibilidad operativa vía Prometheus/Zabbix") debe excluir o marcar explícitamente esta ventana — mismo criterio metodológico que H15 estableció para su propia caída.

---

<a id="h23"></a>
## H23 — OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1)

**Fecha:** 2026-09-03
**Contexto:** La ampliación SOAR (`docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`, sección 1) decidió que R1 sume OTX/AlienVault como corroboración comunitaria además de AbuseIPDB, ya integrado. Se implementó `_otx_lookup()` en `motor/response/enrichment.py`, calcando exactamente el patrón ya validado de `_abuseipdb_lookup()`: cache Redis primero (prefijo `soc:enrich:otx:`), cache miss dispara `GET /api/v1/indicators/IPv4/{ip}/general` con header `X-OTX-API-KEY`, se extrae `pulse_info.count` (cantidad de pulses/reportes comunitarios que mencionan el indicador) y se cachea con TTL 6h.

**Hallazgo:** Mismo principio de degradación elegante que AbuseIPDB — sin `otx_api_key` configurada o ante cualquier fallo HTTP/de red, la función nunca lanza excepción: marca `otx_available = False`, agrega una nota en `EnrichmentResult.notes` y R1 continúa con el resto del enriquecimiento (reverse DNS + AbuseIPDB) sin bloquear el pipeline. `enrich()` ahora llama a ambos lookups (`_abuseipdb_lookup` y `_otx_lookup`) y fusiona los campos `otx_pulse_count`/`otx_available` en el mismo `EnrichmentResult` que ya se persistía.

**Decisión:** `ABUSEIPDB_API_KEY=` y `OTX_API_KEY=` agregadas a `.env.example` (la de AbuseIPDB faltaba pese a que el código ya la usaba desde antes). La key real de OTX se configura directamente en el `.env` de producción de `.140` — no se toca en este cambio ni se commitea.

**Evidencia:** 5 tests unitarios nuevos en `tests/unit/test_otx_enrichment.py` (cache hit, cache miss con llamada a API + escritura de cache, sin API key, timeout de conexión, HTTP 429) — 5/5 pasan. Suite completa del repo: 24/24 pasan tras el cambio (`pytest tests/ -v`).

**Pendiente:** validar en `.140` con la key real de OTX que la cuota/rate limit del proveedor es compatible con el volumen real de tráfico (OTX no impone un límite tan estricto como AbuseIPDB, pero no se ha medido en producción). MISP queda diferido según PROHIBICIONES de `CLAUDE.md`.

---

## Pendientes detectados (no resueltos hoy)

- **Inestabilidad de conexión periódica agente-manager:** patrón recurrente (~cada hora) de "Agent key already in use", "Response timeout", "Cannot send request to agent" entre .139 y .138. Causa no confirmada — candidatos: desincronización de reloj, proceso periódico en .138 reiniciando la conexión, configuración de keepalive. Pendiente investigar antes de noviembre, puede explicar fallos silenciosos de Active Response a futuro.
- **20 reglas de threat intel inactivas** (IDs 99901-99920): referencian listas IOC (malicious-ioc/malware-hashes, malicious-ip, malicious-domains) que nunca se cargaron con contenido real. Las reglas existen pero no tienen efecto. Pendiente decidir si se completan con feeds reales o se eliminan del ruleset.
- **Verificar directamente la regla NAT/MASQUERADE en `.139`:** el `sudo` restringido de auditoría documentado no permitía leer `/etc/ufw/before.rules` ni `iptables -t nat -L` (ver H17). El diagnóstico de H21 sí involucró leer y editar `before.rules` directamente — si eso se hizo con acceso ampliado o manual, actualizar acá y en el alcance del `sudo` de auditoría (`.claude/skills/soc-audit/SKILL.md`) para que quede consistente con lo que realmente es accesible hoy.
- **Perfil `netplan-eno1` duplicado en `.139`:** perfil de NetworkManager inactivo con el mismo `interface-name=eno1` que `netplan-zz-all-en` (H18). No representa riesgo mientras siga sin autoconectar, pero es candidato a limpieza para evitar ambigüedad futura.
- **Sin monitoreo de `motor-soc.service`/`redis-server.service` en `.140`** (H22): el heartbeat existente solo cubre `motor-watcher.service` en `.139` y además depende de Redis sin manejo de fallo — sería ciego a una repetición exacta de H22. Diseñar un check independiente de Redis (o con fallback que no dependa de él) que cubra el motor y el propio Redis, no solo el vigilante FIM.
- **Cuantificar el hueco real en `soc-decisions`/OpenSearch durante la ventana de H22** (2026-08-26 a 2026-09-02): no se verificó cuántas decisiones reales faltaron indexar en esos ~6 días (el motor estaba muerto, no solo el indexador) — útil para el capítulo de resultados si se necesita justificar o excluir ese rango de cualquier métrica de disponibilidad.
- **Actualización de firmware del switch SG350** (H20): evaluar upgrade desde v2.4.0.94 para dejar de depender del workaround de algoritmos SSH legacy en el cliente.
