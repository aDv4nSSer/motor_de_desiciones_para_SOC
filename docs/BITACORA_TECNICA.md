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
| [H23](#h23) | Resp | OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1) | Medio | Implementado y desplegado en `.140` — validado con evento real (ver H24) |
| [H24](#h24) | Resp | `response-worker.service` caído ~9 días (SIGTERM en migración + nunca reiniciado tras fix de H22); gap real de R1/R2 sin enriquecer es de ~17 días | Alto | Resuelto — worker reiniciado y verificado con evento real; causa del gap de encolado diagnosticada en H25 |
| [H25](#h25) | Red | Vector dejó de entregar tráfico al motor desde el 18-ago: sink `motor_soc` en `.139` apuntaba a la IP pública obsoleta de `.140` (no VLAN), nunca actualizada en la migración H17 | Alto | Resuelto — fix aplicado en `.139` y validado con tráfico real; hallazgo colateral de auth (401) en `suricata_alerts_os` resuelto en H27 |
| [H26](#h26) | Ops | Drift repo/prod: `vector.production.toml` real en `.139` no está bajo git, difiere sustancialmente del tracked en `develop` | Medio | Resuelto en `.139` y `.140`: ambos convertidos a checkout real de git con deploy key de solo lectura, 4 servicios reapuntados (`vector-soar`, `motor-soc`, `response-worker`, `opensearch-indexer`) y validados con tráfico real. `motor/model.py` excluido de sync (H31). Regresión real detectada y corregida en el camino: `MODEL_DIR` hardcodeado causó ~2 min de Fast Path con modelo placeholder tras el primer restart en `.140` |
| [H27](#h27) | Ops | Credenciales de OpenSearch desincronizadas en 4 lugares (`opensearch-indexer.service`, `dashboard.py`, `vector-soar.env`, `shadow-detect.env`) por falta de `load_dotenv()` y nombres de variable inconsistentes | Alto | Resuelto — 3 de 4 lugares corregidos y validados con datos reales; rotación de la contraseña real bloqueada por diseño de OpenSearch (usuario reservado), pendiente como tarea separada |
| [H28](#h28) | Resp | Corroboración multi-fuente de R1 (AbuseIPDB+OTX) no influía en tier/`accion_recomendada` — solo quedaba en `soc:response:audit` sin efecto en R2; además, R1 en producción enriquece IPs privadas post-migración VLAN (`10.10.10.3`/`10.30.30.2`), lo que rompía OTX (HTTP 400) y explica por qué la corroboración real nunca se validó bajo carga | Alto | Resuelto y validado en producción: gate real en `worker.py` (2+ fuentes → automático, <2 → `BLOCK_PENDING_APPROVAL` N1) + guard de IP privada en `enrichment.py`, desplegado a `.140` y confirmado con evento real (`worker.log`). 25 tests nuevos, 44/44 pasan. Circuit-breaker evaluado y descartado con evidencia. Efecto colateral medido: guard también drenó un backlog real de 99.594 mensajes. Cuota de OTX bajo tráfico externo real sigue sin validar (bloqueado por el hallazgo de IP privada, fuera de alcance de red/Suricata) |
| [H29](#h29) | Resp | `r2_min_tier=2` (default desde jul-2026 + override idéntico hardcodeado en el `.env` real de `.140`, ambos previos a la especificación de sep-2026) permitía que eventos T2 llegaran al gate de bloqueo automático de R2, contra la sección 4 de la especificación (bloqueo automático exclusivo de T3) | Alto | Auditado con 3 fuentes independientes (`soc:response:audit`, `worker.log` sin capar, `active-responses.log` real de Wazuh en `.138`): **cero bloqueos reales de T2 ocurrieron** — no por diseño correcto, sino porque no hubo tráfico con corroboración≥2 desde el gate de H28 ni active-response alguno desde el apagón del 18-ago (H25). Corregido en código y en el `.env` real (que tenía el valor pisado, no detectado hasta el deploy). Desplegado tras resolver una saturación colateral de `motor-soc` (reboot completo) y validado con evento T2 real: confirmado que el evento ya ni siquiera llega a evaluarse para bloqueo (`block` ausente), no solo `BLOCK_PENDING_APPROVAL` |
| [H30](#h30) | Ops | `motor-soc.service` (Fast Path) se saturó dos veces durante la validación de H29 — proceso único sin `--workers`, IO síncrono (Redis sin timeout en `response/queue.py`) y CPU-bound (`model.predict()`) ejecutados directamente dentro de `async def decide()` | Alto | Mecanismo identificado y **mitigación estructural aplicada y validada**: `run_in_executor` + `retry=Retry(NoBackoff(), 0)` explícito en ambos clientes Redis del Fast Path (hallazgo adicional: redis-py 8.x reintenta 10x sobre timeout por defecto, invalidando el `socket_timeout` sin este fix). Desplegado a `.140` y confirmado con Redis de prueba pausado (degrada en 2s, no se cuelga) y 5 requests concurrentes reales. **Disparador inicial del 3-sep sigue no determinado** — la mitigación estructural es independiente de esa causa puntual |
| [H31](#h31) | ML | `motor/model.py` real en `.140` usa nombres de columna `Column_0..3` y unwrap de modelo empaquetado en dict — no coincide con `model-contract.md` ni con el `model.py` versionado en el repo | Alto | Documentado como contraste textual puro, sin interpretar bug vs. diseño intencional (le corresponde a Joaquín). No se modifica ni se reconcilia — queda explícitamente excluido de la conversión a git checkout de H26 hasta su revisión |
| [H32](#h32) | Ops | `redis_client.py` en producción tenía la password real de Redis hardcodeada como fallback (`"soc_ubo_2026"`) — `motor-soc.service` corría sin `REDIS_PASSWORD` en su entorno y dependía silenciosamente de ese hardcodeo para funcionar | Alto | Corregido: fail-fast si falta `REDIS_PASSWORD`, `load_dotenv()` agregado (mismo patrón de H27). Desplegado y validado con tráfico real. Password tratada como expuesta (apareció en esta sesión) — rotación pendiente, mismo criterio que H27 |

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

> **Corrección (2026-09-04, ver [H24](#h24)):** esta ventana de ≈6 días cubre solo `motor-soc.service` (Fast Path). `response-worker.service` (R1/R2, el que efectivamente enriquece y auditaría bloqueos) estuvo caído por esta misma causa y **nunca se reinició** al resolver H22 — su ventana real sin procesar nada es ≈9 días de proceso muerto, dentro de un hueco más amplio de ≈17 días sin ningún enriquecimiento real (ver H24). Cualquier métrica de R1/R2 (no solo de disponibilidad del motor) debe excluir el rango completo 2026-08-18 a 2026-09-04.

---

<a id="h23"></a>
## H23 — OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1)

**Fecha:** 2026-09-03
**Contexto:** La ampliación SOAR (`docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`, sección 1) decidió que R1 sume OTX/AlienVault como corroboración comunitaria además de AbuseIPDB, ya integrado. Se implementó `_otx_lookup()` en `motor/response/enrichment.py`, calcando exactamente el patrón ya validado de `_abuseipdb_lookup()`: cache Redis primero (prefijo `soc:enrich:otx:`), cache miss dispara `GET /api/v1/indicators/IPv4/{ip}/general` con header `X-OTX-API-KEY`, se extrae `pulse_info.count` (cantidad de pulses/reportes comunitarios que mencionan el indicador) y se cachea con TTL 6h.

**Hallazgo:** Mismo principio de degradación elegante que AbuseIPDB — sin `otx_api_key` configurada o ante cualquier fallo HTTP/de red, la función nunca lanza excepción: marca `otx_available = False`, agrega una nota en `EnrichmentResult.notes` y R1 continúa con el resto del enriquecimiento (reverse DNS + AbuseIPDB) sin bloquear el pipeline. `enrich()` ahora llama a ambos lookups (`_abuseipdb_lookup` y `_otx_lookup`) y fusiona los campos `otx_pulse_count`/`otx_available` en el mismo `EnrichmentResult` que ya se persistía.

**Decisión:** `ABUSEIPDB_API_KEY=` y `OTX_API_KEY=` agregadas a `.env.example` (la de AbuseIPDB faltaba pese a que el código ya la usaba desde antes). La key real de OTX se configura directamente en el `.env` de producción de `.140` — no se toca en este cambio ni se commitea.

**Evidencia:** 5 tests unitarios nuevos en `tests/unit/test_otx_enrichment.py` (cache hit, cache miss con llamada a API + escritura de cache, sin API key, timeout de conexión, HTTP 429) — 5/5 pasan. Suite completa del repo: 24/24 pasan tras el cambio (`pytest tests/ -v`).

**Deploy a `.140` (2026-09-04):** merge a `develop` + push a `origin/develop`, copia puntual de `config.py`/`enrichment.py`/`schemas.py` a `/home/aiayala/tesis/motor/response/` vía `scp` (sha256 idéntico verificado, backups `*.bak-preOTX` guardados), `motor-soc.service` reiniciado sin errores. Validado con un evento real a través de `/decide` (no solo llamada directa a la función) tras resolver [H24](#h24): `soc:response:audit` muestra `enrichment.otx_available` poblado para el trace real — ver H24 para el detalle completo (incluyó un `ReadTimeout` transitorio de OTX en el primer intento real, resuelto solo, sin cambios de código).

**Pendiente:** validar en `.140` con volumen de tráfico real sostenido que la cuota/rate limit de OTX es compatible (no se ha medido bajo carga). MISP queda diferido según PROHIBICIONES de `CLAUDE.md`.

---

<a id="h24"></a>
## H24 — `response-worker.service` caído ~9 días desde H22, nunca reiniciado; gap real de R1/R2 es de ~17 días

**Fecha:** 2026-09-04
**Contexto:** Al cerrar el deploy de OTX (H23) se detectó que `motor-soc.service` (Fast Path, `/decide`) estaba sano, pero `response-worker.service` — el proceso separado que consume `soc:response:tasks` y ejecuta R1 (enrich) / R2 (block) — aparecía `inactive (dead)`. Se investigó antes de reiniciar nada, sin asumir que la causa era la misma de H22 ya resuelta.

**Hallazgo — causa raíz de la muerte del proceso:** `worker.log` (log de aplicación, no journalctl — el usuario `aiayala` no tiene acceso a journal de servicios de sistema sin sudo interactivo) muestra al proceso reintentando conexiones a Redis de forma correcta y resiliente (`ERROR error leyendo cola: Timeout reading from socket; reintentando en 2s`, repetido durante horas, comportamiento esperado del `except redis.RedisError` en `response/worker.py`) hasta la última línea a las **2026-08-26 06:32:01** — exactamente el mismo segundo en que H22 registró "Dependency failed" para `motor-soc.service`. `systemctl status` confirma `Main PID ... (code=killed, signal=TERM)`: el proceso no crasheó por una excepción propia, fue terminado externamente (reboot/corte de servicio durante el cutover de red de la migración VLAN). Al reiniciar el sistema, `Requires=redis-server.service` bloqueó el arranque de `response-worker.service` porque Redis todavía tenía el bug de bind a IP pública obsoleta (H22) — mismo mecanismo que dejó "Dependency failed" a `motor-soc.service`. La diferencia: cuando H22 se resolvió manualmente el 2026-09-02, solo se reinició `motor-soc.service` — `response-worker.service` quedó olvidado, sin que nada lo marcara como "failed" (con `Requires` no satisfecho, el unit nunca llega a intentar `ExecStart`, así que se queda en `inactive (dead)` silencioso en vez de `failed`, más fácil de pasar por alto).

**Hallazgo — el backlog NO era el riesgo esperado, había uno más serio detrás:** Antes de reiniciar se verificó `soc:response:tasks` con `XINFO STREAM`/`XINFO GROUPS`/`XPENDING`: `lag: 0`, `entries-read == entries-added` (2.416.860). En vez de asumir que esto era un artefacto de conteo de Redis, se verificaron los timestamps reales (`ts`) de las entradas más nuevas y más viejas físicamente presentes en el stream (con `maxlen=200_000 approximate` en `enqueue_response_task`, la mayoría del historial ya se había purgado). Resultado: la entrada más reciente en el stream tiene `ts = 2026-08-18T15:13:00` — **8 días antes** de que el worker muriera el 26-ago. Es decir, cuando el proceso fue terminado, ya llevaba días sin recibir tareas nuevas (por eso `lag: 0` es real, no un artefacto: el worker había drenado todo lo que existía). El único `pending: 1` de `XPENDING` apunta a un ID anterior al primer entry físico actual (ya purgado por el `maxlen`), inofensivo — `response/worker.py` solo lee con `>` (mensajes nunca entregados), nunca reprocesa el PEL.

Esto separa dos problemas distintos: (1) por qué murió el proceso el 26-ago (respondido arriba — SIGTERM externo + `Requires` no satisfecho, ya resuelto de raíz junto con H22), y (2) **por qué el pipeline dejó de encolar tareas tier≥1 desde el 18-ago, ocho días antes de que el proceso muriera** — esto NO quedó diagnosticado hoy. `enqueue_response_task()` en `response/queue.py` traga errores de Redis en silencio (`except redis.RedisError: log.warning(...)`, nunca rompe el Fast Path) — es consistente con que la misma inestabilidad de red de la migración VLAN (ver H16/H17/H21) haya estado causando fallos silenciosos de encolado bastante antes de que el worker mismo cayera, pero no se confirmó con evidencia directa (no hay log de `response.queue` capturado para ese rango — vive en el log de `motor-soc.service`, no revisado en este hallazgo).

**Decisión:** Se confirmó que la causa raíz documentada (bug de bind de Redis, H22) sigue resuelta — `redis-server.service` activo y estable desde 2026-09-02 15:47:58 (~42h de uptime sin caídas al momento de este hallazgo), `PING` exitoso. Con eso y el backlog real en cero, se reinició `response-worker.service` (2026-09-04 09:33:51). Arrancó limpio (`Response worker iniciando | mode=enforce enforcer=wazuh_api r1_tier>=1 r2_tier>=2 safelist=8 IPs`), sin errores nuevos tras el arranque.

**Validación con evento real (no llamada directa a la función):** `POST /decide` con `src_ip=200.54.12.140` (IP propia del host, en la safelist — elegida deliberadamente para que R2, que corre en `mode=enforce` con `enforcer=wazuh_api` real, nunca pudiera ejecutar un bloqueo real sin importar el tier que resultara) y features de un probe RDP típico (`SERVER_TCP_FLAGS=2, OUT_PKTS=0, FLOW_DURATION_MILLISECONDS=50, L4_DST_PORT=3389`). Resultado: `tier=1` (T1_BAJO, dispara solo R1). El registro en `soc:response:audit` para ese `trace_id` muestra R1 ejecutado de verdad: `abuseipdb_score=0`, `reverse_dns=polavarr.andes.codelco.cl`, y `otx_available` presente (ver siguiente punto). Confirma que R1 corre en producción tras el reinicio, sobre un evento real del Fast Path, no una invocación aislada de la función.

**Nota OTX en esta misma prueba:** el primer intento real tras el reinicio dio `otx_available: false` con nota `"otx error: ReadTimeout"` — degradación elegante funcionando (no rompió el worker ni el resto del enriquecimiento). Tres llamadas directas inmediatamente después respondieron en 0.37–0.53s cada una — blip transitorio de la API de OTX, no un problema sistemático de conectividad ni de que `otx_timeout=4.0s` sea insuficiente.

**Impacto en la tesis — SÍ afecta el rango a excluir de cualquier métrica futura de R1/R2:** el gap real sin ningún enriquecimiento real es **2026-08-18 15:13 → 2026-09-04 09:35, ≈16 días 18h** (no los ≈9 días que el proceso estuvo con PID muerto, y bastante más que los ≈6 días 9h que H22 documentó para `motor-soc.service`). No se encontró ninguna métrica ya publicada en este documento o en el README que dependa de datos de `soc:response:audit`/`soc-decisions` de ese rango — las métricas del modelo (AUC, precisión, recall en `.claude/rules/model-contract.md`) vienen de datasets de entrenamiento/validación offline, no del pipeline en vivo. Pero cualquier análisis futuro de disponibilidad, tasa de bloqueo real, o efectividad de R1/R2 en producción (sección 7 de `docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`) debe excluir o marcar explícitamente el rango 2026-08-18 a 2026-09-04 completo, no solo la ventana de H22.

**Pendiente:** diagnosticar por qué el encolado se detuvo el 18-ago (8 días antes de la muerte del proceso) — candidato principal: la misma inestabilidad de red de la migración VLAN, pero sin confirmar con evidencia directa del log de `motor-soc`/`response.queue` de ese rango. Revisar también si vale la pena degradar `enqueue_response_task()` para loguear más ruidosamente (hoy es `WARNING` silencioso) cuando el fallo de encolado se sostiene por más de N minutos, para no depender de descubrir esto por accidente la próxima vez.

---

<a id="h25"></a>
## H25 — Causa raíz del gap de encolado del 18-ago (H24): Vector no pudo entregar tráfico al motor porque su sink apuntaba a la IP pública obsoleta de `.140`

**Fecha:** 2026-09-04

**Contexto:** H24 dejó abierta la pregunta de por qué `soc:response:tasks` dejó de recibir tareas nuevas desde 2026-08-18 15:13, ocho días antes de que `response-worker.service` muriera, sin asumir que la causa fuera la misma de H22 (bind de Redis a IP obsoleta, que no empezó a fallar hasta el 26-ago). Se investigó por separado: (1) si el motor seguía generando decisiones T1+ o dejó de clasificar tráfico como riesgoso, consultando `soc-decisions`/`soc:decisions` directamente; (2) si algún cambio de código tocó la lógica de encolado cerca del 18-ago; (3) si el pipeline de ingesta (Suricata/Vector) seguía entregando eventos al motor.

**Hallazgo 1 — no es un problema de tier, es un apagón total del Fast Path:** se agregó `soc-decisions` (OpenSearch) por día y tier para el rango 14-ago a 5-sep. El 18-ago hay 42.925 decisiones (todos los tiers, T0 incluido); del 19-ago al 3-sep hay **cero decisiones de cualquier tier**, ningún día. Se confirmó de forma independiente contando directamente las entradas del stream Redis `soc:decisions` (el que alimenta al indexador) por día: 10.013 entradas el 18-ago, cero entre el 19-ago y el 3-sep, 1 entrada el 4-sep (la prueba de validación de H24). La última entrada real, antes del apagón, tiene `timestamp = 2026-08-18T19:13:00+00:00` (**2026-08-18 15:13:00 hora local**, `tier=2`, `decision=ALERT`) — coincide al segundo con el corte que ya se había observado en `soc:response:tasks`. Esto descarta la hipótesis de H24 ("dejó de encolar tier≥1 pero el motor seguía clasificando"): el motor no clasificó tráfico de ningún tier durante ~16 días porque nunca le llegó ningún evento nuevo, no porque el tráfico dejara de calificar como riesgoso.

**Hallazgo 2 — descartado un cambio de código:** `git log` no muestra ningún commit entre el 2026-07-06 (`e7a27b7`, última vez que se tocó `response/queue.py`) y el 2026-09-03 que modifique `response/queue.py`, `response/config.py` o `response/worker.py`. `r1_min_tier` y el `XADD` de `enqueue_response_task()` son exactamente los mismos del código que ya estaba en producción antes del gap.

**Hallazgo 3 — causa raíz confirmada: Vector no podía alcanzar a `.140`:** en `.139`, `journalctl -u vector-soar.service` muestra el sink `motor_soc` (el que hace `POST /decide` al Fast Path) empezando a fallar con `HTTP error. error=error trying to connect: tcp connect error: No route to host (os error 113)` desde las **2026-08-18 15:01:57**, cada vez con más frecuencia, hasta que el motor deja de recibir absolutamente nada a partir de las 15:13. El archivo de configuración real en producción, `/home/aiayala/tesis/motor_decisiones_soc/pipeline-ingesta/configs/vector.production.toml` en `.139`, tiene el sink `motor_soc` apuntando a:

```toml
[sinks.motor_soc]
uri = "http://200.54.12.140:8000/decide"
```

`200.54.12.140` es la IP pública que `.140` tenía **antes** de migrar a VLAN 10 (H17) — desde que `.140` vive solo en `10.10.10.3` sin IP pública propia, esa dirección ya no existe en ninguna interfaz de la red, así que cada intento de Vector cae en "No route to host" de forma permanente, no transitoria. El archivo tiene fecha de modificación **2026-07-07 23:48**, es decir, nunca se tocó al migrar `.140` a VLAN — exactamente el mismo patrón de "config con IP pública vieja que nadie actualizó en la migración" que H22 documentó para el `bind` de Redis, pero esta vez en Vector (`.139`) y con un impacto mucho mayor: no solo bloquea un servicio al reiniciar, corta *todo* el flujo de eventos hacia el motor en caliente, sin que el proceso se caiga ni se marque como fallido (`vector-soar.service` sigue "activo" reintentando en loop silencioso). El mismo archivo tiene una segunda referencia obsoleta, en el sink `suricata_alerts_os` (línea 190, `endpoints = ["https://200.54.12.140:9201"]`) — el camino directo Suricata→OpenSearch para alertas está roto por la misma causa, aunque no es el que usa el motor de decisiones.

`vector-soar.service` se detuvo solo (salida limpia, `code=exited status=0/SUCCESS`, no un crash) el **2026-08-25 12:40:37** y no se ha vuelto a iniciar desde entonces — sigue `inactive (dead)` hoy, 2026-09-04. Aunque se reiniciara ahora mismo, volvería a fallar exactamente igual porque el archivo de configuración sigue sin corregir.

**Hallazgo 4 — mecanismo distinto y NO resuelto, dejado como causa no determinada:** en paralelo, y casi al mismo minuto (~15:29–15:30 del 18-ago), `response-worker.service` y el proceso huérfano de `opensearch_indexer.py` en `.140` — ambos consumidores de streams Redis en `localhost`, sin relación de red con `.139` — empezaron a fallar con `Timeout reading from socket` contra Redis y nunca se recuperaron durante las mismas ~2.5 semanas (miles de líneas de error en `worker.log` y `opensearch_indexer.log` hasta el 26-ago/4-sep respectivamente). Esto **no puede explicarse por la ruta rota `.139`→`.140`**, porque la conexión es a `127.0.0.1`. H22 confirma además que `redis-server.service` en sí no se cayó hasta el 2026-08-26 06:32 — es decir, hubo más de una semana en la que Redis estaba sano (según el propio journal de systemd) pero sus clientes locales no lograban leer de él. No se encontró evidencia directa de la causa (no hay acceso de auditoría a los logs de `NetworkManager`/journal general de `.140` para esa fecha — el `sudo` restringido solo cubre `motor-soc`, `redis-server` y `opensearch-indexer`). Es razonable sospechar que coincide con el propio corte de red de `.140` migrando de su IP pública vieja a VLAN 10 esa misma tarde, pero **queda como causa no determinada** — no se inventa una explicación sin evidencia directa.

**Decisión:** corregir `vector.production.toml` (las dos IPs obsoletas) y reiniciar `vector-soar.service` — cambio a un componente de ingesta en producción, aplicado el mismo día tras aprobación explícita (ver Resolución).

**Impacto en la tesis:** confirma y reemplaza la hipótesis de H24 — el rango a excluir de cualquier métrica de R1/R2/disponibilidad sigue siendo 2026-08-18 15:13 → 2026-09-04, pero ahora con causa raíz documentada (corte total de ingesta por config obsoleta) en vez de "inestabilidad de red genérica sin confirmar". Es un dato metodológicamente más fuerte para el capítulo de resultados: el motor no tuvo *ningún* dato de entrada durante ese rango, no es un artefacto de tiers o de umbral.

**Evidencia (diagnóstico):**
```
# journalctl -u vector-soar.service (.139), primer fallo del sink motor_soc
Aug 18 15:01:57 ... sink{component_id=motor_soc}: HTTP error. error=... No route to host (os error 113)

# vector.production.toml (.139), sin tocar desde antes de la migración
-rw-rw-r-- 1 aiayala aiayala 7244 Jul  7 23:48 vector.production.toml
143:uri = "http://200.54.12.140:8000/decide"
190:endpoints = ["https://200.54.12.140:9201"]

# soc:decisions (Redis, .140) — conteo por día vía XRANGE
2026-08-18: 10013 entradas | 2026-08-19 a 2026-09-03: 0 | 2026-09-04: 1

# soc-decisions (OpenSearch) — histograma diario por tier
2026-08-18 total=42925 tiers={0:8013,1:18144,2:14158,3:2610}
2026-08-19 ... 2026-09-03: total=0 (todos los días)
2026-09-04: total=1

# git log — sin cambios de código en la ruta de encolado entre el gap
e7a27b7 2026-07-06 feat(response): sincronizar capa de respuesta R1/R2 desde produccion
f1120d5 2026-09-03 feat: integrar OTX/AlienVault como segunda fuente de R1   (primer commit posterior)
```

**Resolución (2026-09-04, mismo día):** antes de aplicar el fix se verificó una discrepancia detectada al comparar este hallazgo contra el repo — el archivo tracked en `develop` (`pipeline-ingesta/configs/vector.production.toml`, 133 líneas) no tiene ningún sink `motor_soc` ni `suricata_alerts_os`. Se confirmó con evidencia directa que **no es un error de esta entrada**: el archivo real en `.139` vive fuera de git (`/home/aiayala/tesis/motor_decisiones_soc`, no es un repositorio), y es real drift entre prod y repo — documentado aparte en [H26](#h26) para no mezclarlo con esta causa raíz.

Con eso aclarado, se aplicó el fix sobre el archivo real de `.139`:

```diff
--- vector.production.toml (backup: vector.production.toml.bak-preH25-20260904102524)
+++ vector.production.toml
@@ [sinks.motor_soc] (línea 143)
-uri = "http://200.54.12.140:8000/decide"
+uri = "http://10.10.10.3:8000/decide"
@@ [sinks.suricata_alerts_os] (línea 190)
-endpoints = ["https://200.54.12.140:9201"]
+endpoints = ["https://10.10.10.3:9201"]
```

`vector-soar.service` reiniciado (por el usuario — el `sudo` de auditoría en `.139` no cubre `restart` de esta unidad, solo de `suricata`/`wazuh-manager`). Validado con evidencia real, no solo "servicio activo":

- `journalctl -u vector-soar.service` desde el reinicio (`Active: active (running) since 2026-09-04 10:26:49`): **cero** ocurrencias de "No route to host".
- `soc:decisions` (Redis, `.140`) volvió a crecer en caliente con tráfico real: `10007 → 10020 → 10024` entradas en ~70s, con `trace_id` distintos cada vez y `src_ip` reales (`10.30.30.2` = `.138` vía puerto 9100/443, y el propio `.140`) — no una llamada de prueba aislada.
- `worker.log` en `.140` procesando R1 en vivo sobre esos mismos eventos nuevos (`[response.worker] INFO [...] R1 ip=10.30.30.2 ...`).

**Hallazgo colateral de la validación, NO resuelto — nuevo pendiente:** al reiniciar, Vector logueó `Healthcheck failed. error=Unexpected status: 401 Unauthorized` para el sink `suricata_alerts_os` (elasticsearch, `.140:9201`). Antes del fix esto estaba enmascarado porque la conexión ni siquiera llegaba a establecerse ("No route to host"); con la IP corregida, se ve que además `OS_PASS` en `/etc/vector/vector-soar.env` (permiso `600`, no legible con el acceso de auditoría actual) no coincide con la credencial real que acepta OpenSearch. Es un problema de autenticación distinto e independiente del de esta entrada — no investigado ni corregido, ver Pendientes. El sink `motor_soc` (el que usa el motor de decisiones) no tiene este problema porque no hace *healthcheck* de OpenSearch.

---

<a id="h26"></a>
## H26 — Drift entre repo y producción: `vector.production.toml` real en `.139` no está bajo control de versiones

**Fecha:** 2026-09-04

**Contexto:** al preparar el fix de [H25](#h25) se detectó, comparando el archivo real de `.139` contra el tracked en `develop`, que las líneas citadas por H25 (143 y 190) no existían en el repo — riesgo de que H25 tuviera un dato incorrecto. Se verificó antes de asumir nada.

**Hallazgo:** `/home/aiayala/tesis/motor_decisiones_soc` en `.139` **no es un repositorio git** (`fatal: no es un repositorio git`) — es una copia manual del pipeline, nunca sincronizada de vuelta al repo. El archivo tracked en `develop` (`pipeline-ingesta/configs/vector.production.toml`, 133 líneas, última modificación en el repo 2026-08-11) es una versión más vieja que **no tiene los sinks `motor_soc` ni `suricata_alerts_os` en absoluto** — solo `jsonl_output` y `stdout_monitor` (salida a archivo/consola, sin integración con el motor ni con OpenSearch). El `diff` completo muestra además diferencias de rutas locales (`data_dir`, `path` de `jsonl_output`) consistentes con que el proyecto se reorganizó de directorio en algún momento sin reflejarlo en ambos lados. Es decir: la pieza de configuración que causó el apagón de H25 (los dos sinks con la IP obsoleta) fue agregada directamente en producción y nunca llegó a control de versiones — nadie podía haber detectado el bug de H25 revisando el repo, porque el repo ni siquiera tiene ese código.

**Decisión:** no se llevó el archivo real a git en esta sesión — implica reconciliar también las otras diferencias (rutas locales, transform de alertas) y decidir la estrategia de despliegue (¿el pipeline entero se vuelve a versionar? ¿se separa config de secretos correctamente, dado que `auth.password = "${OS_PASS}"` ya usa variable de entorno?), que excede el alcance puntual de este fix. Queda como pendiente explícito.

**Impacto:** mismo patrón de raíz que H22 y H25 — cambios aplicados directo en producción sin volver al repo son invisibles para cualquier auditoría futura basada en `git log`/`git diff`, y agrandan la superficie de "algo se rompió y nadie sabe por qué" cada vez que hay que migrar o reconstruir un host.

**Evidencia:**
```
$ cd /home/aiayala/tesis/motor_decisiones_soc && git status
fatal: no es un repositorio git (ni ninguno de los directorios superiores): .git

$ diff repo/pipeline-ingesta/configs/vector.production.toml .139:.../vector.production.toml
# repo: 133 líneas, sinks = {jsonl_output, stdout_monitor}
# .139: 197 líneas, sinks = {jsonl_output, stdout_monitor, motor_soc, suricata_alerts_os}
#       + transform.parse_eve_alerts (no existe en el repo)
#       + diferencias de data_dir/path por reorganización de directorio
```

**Opciones propuestas para que esto no vuelva a pasar (sin aplicar, decisión pendiente):**

1. **Checkout real del repo en `.139` + deploy key de solo lectura.** Convertir `/home/aiayala/tesis/motor_decisiones_soc` en un `git clone` real (deploy key read-only de GitHub, o del remoto que se use), y desplegar con `git pull` en vez de editar a mano. Esfuerzo: bajo (una tarde) — hay que reconciliar primero el contenido real con el repo (los sinks que faltan, las rutas de `data_dir`) antes de poder clonar sin perder nada. Riesgo: bajo — es el patrón más simple y estándar, pero sigue dependiendo de que alguien recuerde correr `git pull` después de cada cambio; no previene el drift, solo lo hace más fácil de corregir.
2. **Script de deploy que sincronice desde el repo en cada cambio.** Un script (`scripts/deploy_vector_config.sh` o similar) que el operador corre explícitamente después de mergear a `develop`: hace `scp`/`rsync` del archivo tracked hacia `.139`, con backup automático del anterior y un `systemctl restart vector-soar` al final. Esfuerzo: bajo-medio (medio día, incluye reconciliar el archivo actual). Riesgo: bajo — no cambia el flujo de trabajo actual (edición local + push), solo reemplaza el `scp` manual por uno con backup/reinicio automático, pero sigue siendo manual (alguien tiene que acordarse de correrlo).
3. **Cron que compare hash y alerte si diverge.** Un chequeo periódico (cron o systemd timer) en `.139` que calcule el hash del archivo real, lo compare contra el hash del archivo en `develop` (vía `git show origin/develop:pipeline-ingesta/configs/vector.production.toml` desde una copia local del repo, o contra un hash publicado), y loguee/alerte si no coinciden. Esfuerzo: medio (día completo — hay que decidir cómo el cron accede al contenido de `develop` sin dar al host acceso de escritura al repo). Riesgo: bajo, pero es **detección, no prevención**: el drift ya pasó y ya causó H25/H27 antes de que este mecanismo avisara de algo — sirve para no tardar 17 días en notarlo la próxima vez, no para que no vuelva a ocurrir.

Ninguna opción es excluyente entre sí — la 1 (checkout real) resuelve la causa de raíz y las otras dos son mitigaciones razonables si la 1 no es viable de inmediato. No se aplica ninguna hasta que Antonio decida.

**Decisión final (2026-09-05, confirmada por Antonio):** Opción 1 (checkout real + deploy key de solo lectura). Justificación: es la única de las tres que da auto-diagnóstico gratis — con un clone real, cualquier auditoría futura (de cualquier persona, o de una sesión de Claude sin contexto previo) puede correr `git status`/`git diff origin/develop` directo en el servidor y ver el drift al instante, exactamente lo que faltó para detectar H25 a tiempo. El "deploy" pasa a ser `git pull`, más simple y más trazable que el patrón manual de scp+backup+sha256 usado hasta ahora en H23/H27/H28/H29 (que de hecho ya produjo un error real: no revisar el `.env` de `.140` en H28/H29). Subsume la Opción 3 sin costo adicional (un cron trivial de `git fetch && git diff` es casi gratis una vez que es un clone real). Limitación explícita: no resuelve drift de *secrets* (`.env`, correctamente fuera de git) — ver H32 para un ejemplo real de ese tipo de drift, que un checkout de git no habría detectado. Se decidió aplicar tanto en `.139` (alcance original de H26) como en `.140` (mismo problema, confirmado durante esta misma sesión: `~/tesis/motor` tampoco es un repo git).

**Implementación en `.139` (2026-09-05):**
1. Reconciliación previa obligatoria: el `vector.production.toml` real de `.139` se trajo completo al repo (commit `708c21b`) — 64 líneas de diferencia (sinks `motor_soc`/`suricata_alerts_os`, transform `parse_eve_alerts`, mapeo `IPV4_SRC_ADDR`/`IPV4_DST_ADDR`, rutas `data_dir`/`path` de un directorio de proyecto ya renombrado). Sin secretos hardcodeados (`auth.password` ya usa `"${OS_PASS}"`).
2. Deploy key de solo lectura generada directamente en `.139` (`~/.ssh/deploy_motor_soc_repo`, ed25519, sin passphrase) — la clave privada nunca salió del servidor. Clave pública registrada en GitHub vía `gh repo deploy-key add` como `read-only`, título `deploy-readonly-.139-vector`.
3. Clone real en `~/tesis/repo` (rama `develop`) usando un alias de `~/.ssh/config` (`github-motor-soc-deploy`) apuntado a esa deploy key. Verificado con `diff -q` que `pipeline-ingesta/configs/vector.production.toml` del clone es **byte a byte idéntico** al archivo real que `vector-soar.service` venía usando — cero cambio de comportamiento en el momento del corte.
4. `vector-soar.service` reapuntado (`ExecStart --config`) de `/home/aiayala/tesis/motor_decisiones_soc/...` a `/home/aiayala/tesis/repo/...`, `daemon-reload` + `restart` (requirió contraseña interactiva de Antonio — no está en el `NOPASSWD` de auditoría). El directorio legacy `~/tesis/motor_decisiones_soc/` se dejó intacto, sin borrar, como red de seguridad.
5. **Validado con tráfico real, no solo "sin errores":** log de `vector-soar.service` muestra `Healthcheck passed` y flows reales parseados correctamente con `IPV4_SRC_ADDR`/`IPV4_DST_ADDR` poblados. `soc:decisions` y `soc:response:tasks` en `.140` confirmados oscilando activamente alrededor de su `maxlen` (10014→10003→10007→10009 y 200016→200000→200002→200003 en ventanas de 5s) — confirma que el sink `motor_soc` sigue entregando correctamente al Fast Path a través del nuevo path gestionado por git.

**A partir de ahora, desplegar cambios de `pipeline-ingesta/` a `.139` es `cd ~/tesis/repo && git pull` (rama `develop`)**, no editar a mano ni copiar por `scp`.

**Implementación en `.140` (2026-09-05, misma sesión):** más compleja que `.139` porque hay 3 servicios (`motor-soc`, `response-worker`, `opensearch-indexer`) con `WorkingDirectory=/home/aiayala/tesis/motor`, y a diferencia de `.139` (donde solo había que reapuntar un sink), acá `motor/` tiene código Y datos de runtime (`.env`, `models/`, `logs/`) mezclados en el mismo árbol. Un `git clone` no puede "aplanar" el subárbol `motor/` del repo para que sus archivos aparezcan directo en la raíz de `~/tesis/motor` (limitación real de `git sparse-checkout`, no algo que se pudiera resolver con más esfuerzo) — se optó por clonar en una ubicación nueva (`~/tesis/repo`) y separar código de datos:

1. **Deploy key** generada in-situ en `.140` (mismo patrón que `.139`), registrada en GitHub como `deploy-readonly-.140-motor`.
2. **Bloqueador de red encontrado y resuelto:** el primer intento de autenticar contra GitHub por el puerto 22 falló (`Permission denied (publickey,password)`) pese a que la clave y el registro en GitHub eran correctos (verificado byte a byte). Se probó puerto 443 con `ssh.github.com` (alternativa documentada por GitHub para redes restrictivas) y funcionó al toque — `.140` vive detrás de NAT/VLAN 10 desde la migración de agosto, y aparentemente el egreso saliente por puerto 22 está filtrado a nivel de red (razonable, no se investigó más a fondo por no ser el objetivo de esta tarea). `~/.ssh/config` de `.140` quedó con `HostName ssh.github.com` / `Port 443` para este alias.
3. **`motor/model.py` (H31) excluido de la sincronización ANTES de tocar cualquier otra cosa:** `git update-index --skip-worktree motor/model.py` en el clone nuevo, seguido de copiar encima el `model.py` real de producción (sin modificarlo). `git status`/`git diff` no muestran ese archivo como modificado — un futuro `git pull` nunca lo va a tocar hasta que alguien revierta el flag explícitamente.
4. **Datos de runtime separados del código, sin mover nada por red:** `.env`, `models/`, `logs/`, `config/` movidos (mismo filesystem, `mv` instantáneo) de `~/tesis/motor/` a un directorio nuevo `~/tesis/motor-runtime/`, y symlinkeados de vuelta desde `~/tesis/repo/motor/`. `.gitignore` actualizado (`motor/models`, `motor/logs`, `motor/config`) porque un patrón `models/` con barra no matchea un symlink — sin esto aparecían como untracked en `git status`.
5. **Dos hallazgos de rutas absolutas hardcodeadas, encontrados y corregidos antes de que causaran daño real:**
   - `model.py`: `MODEL_DIR = Path(os.environ.get("MODEL_DIR", "/home/aiayala/tesis/motor/models"))` — ruta absoluta a la ubicación vieja. **Esto causó una regresión real y momentánea:** tras el primer restart de `motor-soc.service` con el nuevo `WorkingDirectory`, `/decide` respondió con `"model_version":"placeholder_v0"` — el modelo real no cargó y el Fast Path clasificó tráfico real con el modelo placeholder durante los ~2 minutos que tardó en detectarse y corregirse. Se corrigió symlinkeando también la ruta vieja (`~/tesis/motor/models` → `~/tesis/motor-runtime/models`), sin tocar el contenido de `model.py` (excluido por H31). Segundo restart confirmó `"model_version":"golden4_v7_1"` real.
   - `opensearch_indexer.py`: `STATE_FILE = "/home/aiayala/tesis/motor/logs/opensearch_indexer_state.json"` — mismo patrón, independiente del `WorkingDirectory`. Se unificó con el mismo criterio (`~/tesis/motor/logs` → symlink a `~/tesis/motor-runtime/logs`), verificando primero cuál de las dos copias del estado (la vieja, activamente escrita, o la recién movida) tenía el hash más reciente de la cadena antes de fusionarlas, para no retroceder el hash-chain.
6. **Error propio durante el cierre, detectado y revertido de inmediato:** se intentó renombrar `~/tesis/motor` (ya vacío de datos de runtime, solo con el código viejo y los `.bak-*` de sesiones anteriores) a `~/tesis/motor.OLD-preH26-inactivo` para evitar confusión futura — sin darse cuenta de que esa ruta exacta sigue siendo necesaria **permanentemente** como punto de anclaje de las dos rutas absolutas hardcodeadas de arriba. Revertido en el momento (antes de ningún restart adicional, sin impacto real en los servicios activos). **`~/tesis/motor/` debe seguir existiendo con ese nombre exacto de forma indefinida** — hoy solo contiene los symlinks (`models`, `logs`) y archivos legacy inertes, pero dos rutas hardcodeadas dependen de que seguir ahí.
7. **Los 3 servicios reapuntados y reiniciados uno a la vez, con verificación de salud entre cada uno** (requirió contraseña interactiva de Antonio en cada `systemctl restart`, ninguno está en el `NOPASSWD` de auditoría):
   - `motor-soc.service`: `/health` 200, `/decide` real con modelo `golden4_v7_1` confirmado (tras el fix del punto 5).
   - `response-worker.service`: `worker.log` con continuidad total (mismo archivo, mismo inode — el descriptor ya abierto sobrevivió el `mv` de `logs/`, no hubo corte); R1 corriendo correctamente (`avail=False` para IPs privadas, confirma que el guard de H28 sigue activo).
   - `opensearch-indexer.service`: conteo de documentos en `soc-decisions` confirmado creciendo en tiempo real (4.008.721 → 4.008.728 en 10s) tras el restart.

**Estado final validado:** `git status` limpio en `~/tesis/repo` (`.env`/`models`/`logs`/`config` ignorados como corresponde, `model.py` con flag `S` de skip-worktree), los 3 servicios `active`, modelo real cargando, hash-chain de OpenSearch sin discontinuidad. El directorio legacy `~/tesis/motor_decisiones_soc` (de `.139`, sin relación) y `~/tesis/motor/` (de `.140`, ahora solo código legacy + symlinks) quedaron intactos, nada se borró.

**A partir de ahora, desplegar cambios de `motor/` a `.140` es `cd ~/tesis/repo && git pull` + reiniciar el servicio que corresponda** — excepto `motor/model.py`, que sigue siendo responsabilidad exclusiva de actualizar a mano en producción hasta que Joaquín resuelva H31 y alguien decida explícitamente reincorporarlo a la sincronización (`git update-index --no-skip-worktree`).

---

<a id="h27"></a>
## H27 — Credenciales de OpenSearch desincronizadas en 4 lugares por falta de `load_dotenv()` y nombres de variable inconsistentes

**Fecha:** 2026-09-05

**Contexto:** al revisar el hallazgo colateral de H25 (401 en el sink `suricata_alerts_os`), se encontró que el problema no era solo ese sink: `motor/opensearch_indexer.py`, `vigilante/shadow_detect.py` y `motor/dashboard.py` leen `OS_USER`/`OS_PASS` directo de `os.environ` sin `load_dotenv()`, lo que forzó en su momento a inyectar la contraseña real como `Environment=OS_PASS=...` en texto plano dentro de `/etc/systemd/system/opensearch-indexer.service` (permisos `644`, legible por cualquier usuario del host). Además, `.env.example` documentaba `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD`, nombres que ningún archivo de código lee.

**Matriz de credenciales (antes del fix, hashes SHA-256 truncados a 12 caracteres — nunca el valor real):**

| Lugar | Host | Origen de `OS_PASS` | Hash | Auth real contra OpenSearch |
|---|---|---|---|---|
| `opensearch-indexer.service` (unit file) | `.140` | `Environment=OS_PASS=...` | `1f89a70bc452` | ✅ 200 OK |
| `motor-soc.service` → `dashboard.py` (proceso vivo) | `.140` | `EnvironmentFile=/etc/motor-soc/dashboard.env` | `1f89a70bc452` | ✅ 200 OK |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` del contenedor `opensearch-soc` | `.140` | env var Docker (bootstrap inicial) | `d4f384320374` | ❌ 401 — password de bootstrap, ya rotado en algún momento sin actualizar el contenedor |
| `vector-soar.service` → sink `suricata_alerts_os` (proceso vivo) | `.139` | `/etc/vector/vector-soar.env` | `d4f384320374` (= bootstrap viejo) | ❌ 401 |
| `motor-watcher.service` → `shadow_detect.py` | `.139` | — (hipótesis inicial errónea, ver Corrección) | — | — |
| `shadow-detect.service` → `shadow_detect.py` (proceso real, oneshot vía timer) | `.139` | `/etc/motor-soc/shadow-detect.env` | tercer valor distinto de los otros dos | ❌ `No route to host` (además `OS_HOST` apuntaba a `200.54.12.140`, la IP pública obsoleta de H25, en un tercer lugar) |

**Corrección durante la investigación:** se planteó inicialmente que `shadow_detect.py` no tenía `OS_PASS` configurado en absoluto — error propio, producto de revisar el proceso equivocado (`motor-watcher.service`, que corre `watcher.py`, el vigilante FIM). El propio docstring de `shadow_detect.py` documenta que corre como timer systemd independiente (`shadow-detect.timer` → `shadow-detect.service`); se confirmó capturando en vivo el entorno real de una corrida del timer (`/proc/<pid>/environ`) que sí tiene sus propias `OS_HOST`/`OS_USER`/`OS_PASS` vía `/etc/motor-soc/shadow-detect.env`, con valores propios y erróneos (no simplemente ausentes).

**Verificación de aislamiento de `shadow_detect.py` antes de tocar sus credenciales:** se rastreó el código real (no el nombre del commit ni el docstring) para confirmar que escribir en su índice no tiene ninguna ruta hacia el mecanismo de cuarentena del vigilante: `check()` → `upsert_finding()` → `_os_request()`, único destino `OS_INDEX = "soc-experimental-detections"` (hardcodeado); no importa nada de `response/`, no importa `redis`, no llama ninguna función de `watcher.py`; corre en un proceso systemd completamente separado de `motor-watcher.service`. Confirmado: observación/logging puro, sin ruta directa ni indirecta hacia FIM→cuarentena→caso→correo.

**Fix aplicado:**

1. **Código (commit `9137512`, rama `develop`):** `load_dotenv()` agregado a los tres `.py`. `.env.example` renombrado de `OPENSEARCH_HOST/PORT/USER/PASSWORD/INDEX` a `OS_HOST/OS_USER/OS_PASS` (los nombres que el código realmente lee). Fallback de `OS_HOST` en `shadow_detect.py` corregido de la IP pública obsoleta a `10.10.10.3`. `python-dotenv` agregado a `requirements.txt` e instalado en `.139` (no estaba presente; requirió `--break-system-packages` por PEP 668).
2. **`.140` — `opensearch-indexer.service`:** `OS_USER`/`OS_PASS` movidos a `~/tesis/motor/.env` (valor real confirmado en la matriz); `Environment=OS_PASS=...` eliminado del unit file; `infra/systemd/opensearch-indexer.service` (sin la credencial) agregado al repo por primera vez — no existía tracked. `opensearch_indexer.py` desplegado resincronizado con la versión del repo (de paso se eliminó un fallback hardcodeado `"SocUBO2026!"` que existía solo en el archivo desplegado, no en el repo — otra instancia de drift, ya corregida).
3. **`.139` — `vector-soar.env` (sink `suricata_alerts_os`):** `auth.password` en `vector.production.toml` ya usaba `"${OS_PASS}"` (variable, no hardcodeado) — el archivo a corregir era `/etc/vector/vector-soar.env`, no el `.toml`. Corregido al valor real.
4. **`.139` — `shadow-detect.env`:** `OS_HOST` corregido a `https://10.10.10.3:9201`, `OS_PASS` corregido al valor real.

**Incidente durante el diagnóstico:** al mostrar un `diff -u` del unit file de `opensearch-indexer.service` antes/después del fix, el comando comparó el archivo original completo (que todavía tenía `Environment=OS_PASS=<valor real>`) y expuso la contraseña real en el output de la sesión de trabajo — no en un commit ni en un archivo, pero sí en texto plano visible. Es un motivo adicional (no el único) para tratar la rotación de esa contraseña como prioritaria.

**Validado con evidencia real (no solo "sin errores"), 2026-09-05 ~09:30-09:41:**
- `.140`: `soc-decisions` recibe documentos nuevos con `trace_id` distintos justo después del reinicio del indexer (`2026-09-05T13:29:38Z` en adelante).
- `.139` / `suricata_alerts_os`: healthcheck pasa, cero 401 desde el reinicio; nuevo índice `suricata-alerts-2026.09.05` creado y creciendo (2 → 4 documentos en 20s).
- `.139` / `shadow_detect.py`: primera corrida del timer tras el fix pasa de "0 hallazgos escritos" (todas las corridas anteriores) a "4 hallazgos escritos", confirmado además con documentos reales nuevos en `soc-experimental-detections` (`detected_at` = hora de esa corrida exacta).

**Pendiente — rotación de la contraseña real (paso 6 original), NO completada:** se intentó rotar el password real de OpenSearch vía `PATCH /_plugins/_security/api/internalusers/admin` una vez confirmado que los 4 lugares ya comparten la misma fuente. La API devolvió `403 Forbidden`: el usuario `admin` está marcado `"reserved": true` en la configuración de seguridad de OpenSearch — por diseño, los usuarios reservados no se pueden modificar vía la REST API (protección contra pisar el usuario de "vidrio roto" del cluster por accidente). La única vía real es editar `internal_users.yml` dentro del contenedor y aplicar con `securityadmin.sh` usando certificados de admin (TLS client cert) — una operación bastante más invasiva sobre el único nodo de OpenSearch del proyecto (guarda `soc-decisions`, hash-chain append-only, sin réplicas). No se intentó hoy por el riesgo de dejar el cluster sin autenticación funcional si algo sale mal. Nada quedó modificado por el intento fallido (verificado).

**Decisión:** tratar la rotación como tarea separada y deliberada, con backup del volumen de datos de `opensearch-soc` antes de tocar `internal_users.yml`, no combinada con un fix de rutina. Mientras tanto, el password real ya solo vive en 3 archivos `.env`/`EnvironmentFile` (uno por host más el compartido de `.140`), todos protegidos por permisos `600` salvo el `.env` de `.140` que hereda los permisos del usuario `aiayala` — ya no en ningún unit file de systemd en texto plano.

**Evidencia:** matriz de hashes de arriba; capturas de `journalctl` post-fix para los tres servicios (sin plaintext); conteos de documentos antes/después en `soc-decisions`, `suricata-alerts-2026.09.05` y `soc-experimental-detections`; commit `9137512` en `develop`.

---

<a id="h28"></a>
## H28 — Continuación de H23: la corroboración multi-fuente de R1 no influía en la decisión; R1 en producción enriquece IPs privadas post-migración VLAN

**Fecha:** 2026-09-05

**Contexto:** el pendiente abierto de H23 era validar la cuota de OTX bajo carga sostenida. Antes de diseñar esa prueba se pidió confirmar, leyendo el código real (no la especificación), si la corroboración entre AbuseIPDB y OTX ya influye en `tier`/`accion_recomendada` como define la sección 4 de `especificacion_tecnica_final_r-soar.md` ("IP confirmada maliciosa en 2+ fuentes → bloqueo automático" vs. "1 sola fuente débil → alertar, NO bloquear, requiere aprobación N1+", regla derivada del caso real de falso positivo tipo crawler/Bing-msnbot).

**Hallazgo 1 — la corroboración no tenía ningún efecto en la decisión, era solo un campo de auditoría:** se siguió el flujo real en `motor/response/`. `worker.py::process_task` computa `record.enrichment = enrich(...)` (R1) y, por separado, si `task.tier >= r2_min_tier`, llama a `respond_block(task.src_ip, settings, rdb, enforcer, task.trace_id)` (R2) — **sin pasarle `record.enrichment` como argumento**. `enforcer.py::respond_block` nunca recibe ni consulta el resultado de R1; sus únicas cuatro salvaguardas son safelist, idempotencia, `dry_run`/`enforce` y el resultado del enforcer. El único dato que determina si R2 bloquea es `task.tier`, calculado en `main.py` **antes** de que R1 corra. Confirma la sospecha: OTX se integró (H23) calcando el patrón de `_abuseipdb_lookup` sin tocar la lógica de tiers, y la regla de negocio de la sección 4 seguía siendo solo un párrafo del documento, no código. Coincide además con el checklist de la propia especificación (`especificacion_tecnica_final_r-soar.md` sección 9, punto 7: "Implementar el campo `accion_recomendada`... [pendiente]") y con `docs/PLAN_SPRINTS.md` (Sprint 4, no iniciado).

**Hallazgo 2 — R1 en producción está enriqueciendo IPs privadas, no atacantes externos:** para diseñar la prueba de carga de OTX (pendiente de H23) se leyó (solo lectura, sin modificar nada) el stream `soc:response:audit` completo en `.140` (capacidad `maxlen=100_000 approximate`, cubre ≈18h de tráfico reciente, buckets de hora `496821`–`496838` unix/3600). Resultado:
- **100.000/100.000 registros con `enrichment` tienen `otx_available=False`.** De una muestra de 2.000 registros recientes, 1.939 fallan con `otx HTTP 400` y 61 con `ReadTimeout` — **ninguno por rate-limit (HTTP 429)**, y `OTX_API_KEY` sí está configurada en el `.env` real.
- Solo **2 IPs distintas** aparecen como `src_ip` en las ≈18h de historial retenido, pese a picos de hasta 8.371 registros/hora: `10.10.10.3` (el propio motor, VLAN 10) y `10.30.30.2` (el propio servidor web, VLAN 30) — ambas privadas (`ipaddress.ip_address(...).is_private == True`, confirmado). El endpoint de OTX (`GET /indicators/IPv4/{ip}/general`) rechaza indicadores no públicos con `400 Bad Request`; AbuseIPDB en cambio no lanza error sobre una IP privada, pero cualquier score que devuelva para ella no tiene significado real de reputación de internet.
- Lectura: tras la migración a NAT/VLANs (`.139` in-line, ver H17–H21), el campo `src_ip` que llega al Fast Path (`main.py`: `event_data.get("IPV4_SRC_ADDR") or event_data.get("src_ip")`) puede ser una dirección interna en vez de la IP pública real del origen del tráfico, al menos para el tráfico retenido en esta ventana. Esto es un hallazgo sobre la calidad del dato que llega a R1 (Suricata/Vector, fuera del alcance de este cambio — no se tocó red/VLANs/Suricata), pero explica directamente por qué "validar OTX bajo carga real" no se puede responder todavía con tráfico genuinamente externo: los dos únicos "atacantes" observados en 18h son hosts propios del laboratorio.

**Decisión — PASO 1, implementar la corroboración real (`motor/response/`, sin tocar R2/`enforcer.py`):**
- `config.py`: nuevos umbrales configurables (no hardcodeados) — `abuseipdb_malicious_threshold=50` (AbuseIPDB `abuseConfidenceScore` 0-100), `otx_min_pulse_count=1` (un pulse de OTX ya es un reporte comunitario curado por analistas, a diferencia de los reportes de AbuseIPDB que sí necesitan umbral numérico para filtrar ruido), `min_corroborating_sources_for_autoblock=2` (regla de la sección 4).
- `enrichment.py`: `count_corroborating_sources()` cuenta, sobre el `EnrichmentResult` ya calculado, cuántas fuentes *disponibles* superan su umbral. Una fuente no disponible (sin key, timeout, error, IP privada) no cuenta ni a favor ni en contra — mismo criterio de degradación elegante que el resto de R1. `enrich()` popula `EnrichmentResult.corroboration_count`/`corroborating_sources`.
- `worker.py::process_task`: **este es el cambio que hace el aporte real.** Antes de invocar R2, se lee `record.enrichment.corroboration_count`. Si `>= min_corroborating_sources_for_autoblock`, se llama a `respond_block(...)` exactamente igual que antes (cero cambios en `enforcer.py`: mismas safeguards, mismo `dry_run`/`enforce`, mismo enforcer). Si no, **`respond_block()` ni siquiera se invoca** — se registra `BlockResult(action=BLOCK_PENDING_APPROVAL, requires_approval=True, approval_level="N1")` directamente, sin tocar el enforcer real. `ActionType.BLOCK_PENDING_APPROVAL` es nuevo en `schemas.py`.
- **`classtype_override` no exime de corroboración:** un classtype que fuerza T3 en el motor (`main.py::T3_CLASSTYPES`) es, por el propio diseño de defensa en profundidad (`especificacion_tecnica_final_r-soar.md` sección 3), tráfico que pasa por "Suricata modo *alert*" — las firmas de confianza verdaderamente alta ya se descartan en "modo *drop*", a nivel de paquete, sin llegar nunca al motor. Tratar `classtype_override` como corroboración automática duplicaría esa capa con un criterio más débil. Decisión: la corroboración se exige igual para todo evento que llegue a evaluar R2, sea cual sea la razón del tier.
- **Riesgo residual explícito:** `r2_min_tier=2` (default, sin override en el `.env` de `.140`) sigue permitiendo que eventos T2 lleguen al gate de R2, aunque la tabla de la sección 4 solo contempla bloqueo automático en T3. No se tocó — está fuera del alcance de esta tarea ("no tocar R2/bloqueo activo") y es un cambio de umbral operacional en producción que requiere decisión explícita, no un efecto secundario de este trabajo. Queda documentado como pendiente abajo.

**Decisión — PASO 1 (fix acotado), guard de IP privada:** se agregó `_is_public_ip()` en `enrichment.py`; `_abuseipdb_lookup`/`_otx_lookup` devuelven `*_available=False` con nota explicativa sin llamar a Redis ni a la API cuando la IP no es pública (privada/loopback/link-local/reservada). Es un fix mínimo y quirúrgico: no cambia el contrato de `EnrichmentResult` (reutiliza el campo `*_available` ya existente, que la corroboración ya trata como "no cuenta ni a favor ni en contra"), evita 61+ `ReadTimeout` inútiles observados y deja de gastar cuota/tiempo en llamadas condenadas a fallar.

**Decisión — PASO 2, por qué NO se construye circuit-breaker para OTX:** se evaluó explícitamente antes de escribir código, con la evidencia del Hallazgo 2 en mano. Un circuit-breaker protege contra fallos *transitorios* de un proveedor externo saludable en general (timeouts intermitentes, sobrecarga puntual) abriendo el circuito N fallos seguidos y reintentando tras M minutos. La falla real encontrada (1.939/2.000 = HTTP 400) es un **error de cliente determinístico** — la misma IP privada va a devolver 400 siempre, sin importar cuántas veces se reintente ni cuánto tiempo pase; un circuit-breaker abriría, esperaría M minutos, cerraría, y volvería a fallar con el mismo 400 en el primer intento. No resuelve nada que el guard de IP privada no resuelva ya de raíz, y añadiría estado (contador de fallos, temporizador por proveedor) para un problema que no es de disponibilidad del proveedor. Se aplica el mismo criterio que ya se usó para descartar Shuffle SOAR y multi-tenant en este proyecto: no construir infraestructura para un problema que la evidencia no muestra que exista. Si en el futuro aparece evidencia real de fallos transitorios genuinos de OTX (no error de cliente) bajo el volumen real de IPs públicas — una vez resuelto el Hallazgo 2 — se reevaluará con datos, no antes.

**PASO 3 — validación de cuota de OTX bajo carga, resultado parcial y honesto:** con el guard de IP privada activo, el conteo de llamadas reales a la API de OTX depende de IPs *públicas* **distintas** por ventana de caché (6h), no del volumen bruto de eventos — la caché de `enrich_cache_prefix` evita repetir la consulta para la misma IP dentro de esas 6h. En la ventana observada (≈18h, hasta 8.371 registros/hora) solo hubo 2 IPs en total, ambas privadas y ahora filtradas por el guard — es decir, el consumo real de cuota de OTX bajo el tráfico actualmente enriquecido es, en la práctica, cero. Esto **no valida** la cuota bajo tráfico externo real, porque el tráfico externo real no está llegando a R1 en esta ventana (Hallazgo 2). El límite documentado de OTX (no confirmado contra la documentación oficial vigente, solo contra reportes de comunidad de AT&T/LevelBlue vía búsqueda web) es del orden de 10.000 req/hora con API key — muy por encima de cualquier volumen de IPs *distintas* observado incluso en los días de mayor tráfico de esta bitácora. Pendiente real: repetir esta misma lectura de solo-lectura sobre `soc:response:audit` una vez que el Hallazgo 2 esté resuelto (src_ip públicas reales llegando a R1), para obtener una cifra de IPs distintas/hora genuinamente representativa y compararla contra el límite de OTX.

**Desplegado y validado en producción el mismo día (2026-09-05, ~10:18-10:40):** commit `7c42eb4` en `develop` (push a `origin/develop` incluido). `config.py`/`enrichment.py`/`schemas.py`/`worker.py` copiados a `~/tesis/motor/response/` en `.140` (backups `*.bak-preH28-20260905101810`, sha256 idéntico verificado archivo por archivo). `response-worker.service` reiniciado por Antonio (requiere contraseña interactiva — `response-worker` no está en el `NOPASSWD` de `.140`, a diferencia de `motor-soc`/`opensearch-indexer`/`redis-server`; queda anotado como pendiente abajo).

**Validación con evento real (no invocación directa de función), mismo criterio que H24:** `POST /decide` contra `.140` con `X-Suricata-Classtype: web-application-attack` (fuerza `classtype_override=True` → T3 determinístico, sin depender del score del modelo) y `IPV4_SRC_ADDR=200.54.12.140` — IP pública real del propio host, deliberadamente en la safelist para que un bloqueo real fuera imposible sin importar el resultado de la corroboración. Resultado en `worker.log`:
```
[085ed9e5] R1 ip=200.54.12.140 abuse=0 rdns=polavarr.andes.codelco.cl cached=False avail=True
[085ed9e5] R2 ip=200.54.12.140 action=block_pending_approval enforced=False
  reason='corroboración insuficiente (0/2 fuentes) — requiere aprobación humana antes de bloquear'
  via=none corroboration=0
```
R1 corrió de verdad (AbuseIPDB real, reverse DNS real, ninguna IP privada de por medio esta vez) y R2 **no** invocó `respond_block()`/`enforcer.py` — quedó correctamente en `BLOCK_PENDING_APPROVAL` pese a ser T3. Es el caso Bing/msnbot de la sección 4 de la especificación funcionando en código real, no solo en el documento.

**Hallazgo colateral confirmado por la propia validación — el guard de IP privada también resuelve un cuello de botella real de throughput, no solo cuota desperdiciada:** al momento del despliegue, `soc:response:tasks` tenía un backlog real de `lag=99.594` mensajes sobre el consumer group `response-workers` (tráfico de ruido interno sostenido, `10.10.10.3`→`8.8.4.4:53` cada 1-2s, tier=1). Medido en vivo, el lag bajó de 99.594 a 0 en menos de 15 minutos tras el reinicio con el fix (~150-170 msg/s), un throughput muy por encima del que permitía el código anterior (cada mensaje con IP privada pagaba el timeout completo de OTX de hasta 4s antes del guard). Esto es evidencia adicional, no buscada originalmente, a favor de la decisión del PASO 2: el guard de IP privada —no un circuit-breaker— era la solución mínima correcta, porque el problema real medido era de latencia/throughput por llamadas condenadas a fallar, no de disponibilidad intermitente de un proveedor sano.

**Nota de auditoría, no relacionada con este cambio pero encontrada al verificar el backlog:** `xpending` mostró un mensaje (`1786655183949-0`) con `time_since_delivered` ≈ 22.7 días — entregado al consumer pero nunca reconocido (`XACK`). El diseño de `worker.py` hace `XACK` siempre en un bloque `finally`, así que esto solo es posible si el proceso murió (kill duro, no excepción) entre la entrega y el ACK. No se investigó en profundidad en esta sesión — no bloquea nada (el consumer group sigue avanzando normalmente) pero es candidato a revisión aparte; agregado a pendientes abajo.

**Evidencia:**
- 25 tests unitarios nuevos: `tests/unit/test_corroboration.py` (11), `tests/unit/test_response_worker_gating.py` (7), `tests/unit/test_enrichment_private_ip_guard.py` (5), más los 2 que ya cubrían casos de threshold configurable. Suite completa: 44/44 pasan (`pytest tests/ -v`), sobre el baseline de 24/24 antes de este cambio.
- Lectura en vivo (solo lectura, sin escritura ni reinicio de ningún servicio) de `soc:response:audit` en `.140`: `XLEN=100006`, 100.000 registros muestreados, conteo de `otx_available`/`abuseipdb_available`, notas de error, y `src_ip` más frecuentes — scripts ejecutados vía `python3` del sistema en `.140` (no en el `.venv` del proyecto), leyendo `REDIS_PASSWORD` desde `~/tesis/motor/.env` en tiempo de ejecución, nunca impreso ni commiteado; borrados de `/tmp` tras cada corrida.
- Commit `7c42eb4` en `develop`, pusheado a `origin/develop`. Desplegado y validado en `.140` el mismo día (detalle arriba).

---

<a id="h29"></a>
## H29 — `r2_min_tier=2` permitía bloqueo automático en T2, contra la sección 4 de la especificación

**Fecha:** 2026-09-05

**Contexto:** al revisar el gate de corroboración de H28, se notó que `response-worker.service` arranca con `r2_tier>=2` en su log de inicio — la sección 4 de `especificacion_tecnica_final_r-soar.md` es explícita: el bloqueo automático (con o sin corroboración) es exclusivo de T3; T2 (red u host) siempre alerta y crea caso, nunca bloquea.

**PASO 0 — auditoría antes de tocar nada, con 3 fuentes independientes:**
1. **`soc:response:audit` (Redis, capado a 100k, cubre solo los últimos ≈45 min por el volumen de tráfico):** 12.923 eventos `tier==2` en la ventana cubierta, el 100% con `corroboration_count=0` (por el guard de IP privada de H28 — el ruido interno `10.10.10.3`/`10.30.30.2` sigue siendo casi todo el tráfico) y el 100% con `action=block_pending_approval`. Cero eventos de cualquier tier con `corroboration_count>=2` en toda la ventana retenida. **Gap identificado:** el stream se capa tan rápido bajo este volumen que los primeros ≈7 minutos tras el deploy de H28 (10:24:29–10:31:27) ya estaban trimeados al momento de auditar — no se puede confirmar ni descartar nada de esa ventana específica desde este stream.
2. **`worker.log` (append-only, sin capar, cubre el 100% de la ventana desde el deploy de H28):** 22.752 líneas `R2` desde `2026-09-05 10:24:29`, el 100% `action=block_pending_approval`. Cero líneas `action=block `, cero líneas `[ENFORCE]` en todo ese rango — el gap de la fuente 1 queda cubierto acá.
3. **`active-responses.log` real de Wazuh en `.138`** (vía jump host a `10.30.30.2:22`, no `.139` — mismo criterio que la metodología de auditoría de este proyecto): la última línea `"command":"add"` en todo el archivo es del `2026-08-18 15:13:05` — coincide exactamente con el apagón de tráfico documentado en H25. **Ningún active-response real se ejecutó desde esa fecha**, mucho antes de que existiera el gate de H28.

**Conclusión del PASO 0:** cero bloqueos reales de T2 (o de cualquier tier) ocurrieron indebidamente. No porque `r2_min_tier=2` fuera inofensivo, sino porque (a) el gate de corroboración de H28 ya bloqueaba cualquier intento con `corroboration_count<2`, y (b) de forma independiente, no ha habido tráfico real con `corroboration_count>=2` desde el apagón de H25. El riesgo era real y estaba vivo en el código, pero no llegó a materializarse — es autocrítica sobre una desviación de diseño detectada a tiempo, no un incidente de bloqueo indebido ya ocurrido.

**PASO 1 — ¿hay una razón de diseño para `r2_min_tier=2`?** Se buscó en el código (`grep -rn "rate.limit"` sobre `motor/`) cualquier sub-acción de bajo impacto (ej. rate-limiting) que pudiera justificar que T2 llegara al gate de R2. No existe ninguna — `enforcer.py`/`schemas.py` solo conocen `block`/`block_skipped`/`block_pending_approval`, no hay ninguna acción graduada de menor impacto implementada. `git log` sobre `config.py` muestra que `r2_min_tier=2` se introdujo en el commit `e7a27b7` (**2026-07-06**), casi dos meses antes de la especificación de sección 4 (**2026-09-01**) que restringe el bloqueo automático a T3. Nunca se revisó después. Conclusión: es una desviación heredada de un diseño anterior, no una decisión de diseño vigente.

**PASO 2 — fix:** diff mostrado y aplicado en `motor/response/config.py` (`r2_min_tier` 2→3, comentario actualizado con referencia a esta sección y a H29).

**Hallazgo adicional durante el despliegue — el `.env` real de `.140` tenía el valor hardcodeado, pisando el default del código:** al copiar el `config.py` corregido y reiniciar `response-worker.service`, el log de arranque seguía mostrando `r2_tier>=2`. Investigando, `~/tesis/motor/.env` en producción tenía `R2_MIN_TIER=2` explícito — variable de entorno que `pydantic_settings.BaseSettings` prioriza sobre el default de la clase. Este archivo nunca se había revisado directamente en la auditoría de H28 (solo se había revisado `.env.example`/`.env` del repo local, que no tienen esta variable) — es la misma lección que ya dejó H27 con las credenciales de OpenSearch: **el default en el código no es la configuración real sin verificar el `.env` de producción.** Corregido con el mismo patrón de backup (`~/tesis/motor/.env.bak-preH29-20260905113717`) + `sed` puntual sobre la línea exacta, sin tocar ningún secreto del resto del archivo. Segundo reinicio de `response-worker.service` requerido para que tomara el valor correcto.

**Incidente colateral durante la validación — `motor-soc.service` saturado, no relacionado con este cambio:** al intentar mandar el evento T2 de prueba, `/decide` y `/health` dejaron de responder (timeout de 30s). Diagnóstico: `uvicorn` (proceso corriendo desde el 3-sep, sin flag `--workers`, un solo proceso) a 73% CPU con una cola de 239 conexiones TCP sin aceptar; RAM normal (8GB libres) — saturación de CPU de un proceso único, no un problema de memoria. Un primer reinicio de `motor-soc.service` lo destrabó por ~20 minutos, tras los cuales volvió a saturarse (472% CPU, mismo PID, nueva cola de 66 conexiones) — confirma que es un problema de capacidad recurrente y no un evento puntual. Antonio optó por un reboot completo del servidor (`.140`) en vez de otro restart de servicio puntual, que sí resolvió la saturación de forma estable. **No se investigó la causa raíz en esta sesión** (candidatos sin confirmar: volumen de tráfico del ruido interno de H28, algún proceso concurrente, o un problema de rendimiento del propio Golden4 en producción bajo carga sostenida) — queda como pendiente separado abajo, fuera del alcance de H29.

**PASO 3 — validación con evento real (no invocación directa de función):** tras el reboot, con `/health` respondiendo en 4ms, se generó un T2 real vía el modelo (sin `classtype_override`): `POST /decide` con `SERVER_TCP_FLAGS=20, OUT_PKTS=0, FLOW_DURATION_MILLISECONDS=0, L4_DST_PORT=445` → `tier=2, risk_score=0.5765, decision=ALERT` (`trace_id=a6dbc6a0`), IP pública propia (`200.54.12.140`) en la safelist por si acaso. Log de arranque del worker confirmado con la config correcta: `r1_tier>=1 r2_tier>=3`. Resultado en `worker.log` para ese trace:
```
[a6dbc6a0] R1 ip=200.54.12.140 abuse=0 rdns=polavarr.andes.codelco.cl cached=True avail=True
```
**No aparece ninguna línea `R2` para este trace** — confirma que con `r2_min_tier=3`, un evento T2 ni siquiera llega a evaluarse para bloqueo (ni `block_pending_approval` ni `block`): el campo `block` queda completamente ausente, exactamente como especifica la tabla de la sección 4 para T0-T2 ("Ninguna [acción de bloqueo] / log"). R1 (enriquecimiento) sigue corriendo igual para T2, sin cambios.

**Evidencia:**
- 3 tests nuevos en `tests/unit/test_response_worker_gating.py` (`TestR2MinTierDefaultMatchesSpec`): default `r2_min_tier==3`, T2 con corroboración fuerte no llega a `respond_block()`, T3 con corroboración fuerte sigue auto-bloqueando sin cambios. 47/47 tests del repo pasan.
- Auditoría cruzada de 3 fuentes (Redis, `worker.log`, `active-responses.log` real de Wazuh en `.138`) documentada arriba.
- Commits `f01d8be` (código) en `develop`, pusheado a `origin/develop`. Desplegado y validado en `.140`: `config.py` (sha256 verificado) + `.env` corregido (backups `config.py.bak-preH29-20260905112304` y `.env.bak-preH29-20260905113717`), dos reinicios de `response-worker.service`, un reboot completo del servidor para resolver la saturación colateral de `motor-soc`. Validación en vivo con evento T2 real (`trace_id=a6dbc6a0`) confirmando ausencia total de evaluación de bloqueo.

---

<a id="h30"></a>
## H30 — Investigación de la saturación de `motor-soc.service` (colateral de H29): mecanismo identificado con evidencia, disparador exacto no confirmado

**Fecha:** 2026-09-05

**Contexto:** durante la validación de H29, `motor-soc.service` dejó de responder dos veces (73%→472% CPU, cola de conexiones TCP creciente). Antes de aceptar la hipótesis de "faltan `--workers`" sin verificar, se investigó con evidencia de journal y código real.

**Hallazgo 1 — no hubo proceso duplicado/zombie; el proceso saturado era único y de larga vida:** `sudo journalctl -u motor-soc` (journal completo del servicio, sin `--since` por la restricción de argumentos exactos del `sudoers` de auditoría) muestra la secuencia real de arranques:
```
Sep 02 15:50:29  Started motor-soc.service       (PID 661929)
Sep 03 17:25:41  Started motor-soc.service       (PID 857293)  ← el que se saturó
Sep 05 11:33:21  Main process exited, code=killed, status=9/KILL
Sep 05 11:33:21  Failed with result 'timeout'
Sep 05 11:33:21  Started motor-soc.service       (PID 1210163)
Sep 05 11:33:51  Started motor-soc.service       (PID 1210402)
Sep 05 11:34:00  Started motor-soc.service       (PID 1210564)  ← se volvió a saturar en ~20min
Sep 05 12:04:30  Main process exited, code=killed, status=9/KILL
Sep 05 12:04:30  Failed with result 'timeout'
Sep 05 12:10:15  Started motor-soc.service       (PID 8576, post-reboot)
```
No hay evidencia de dos procesos `uvicorn` corriendo en simultáneo en ningún momento — cada arranque reemplaza limpiamente al anterior. Los tres arranques rápidos entre 11:33:21 y 11:34:00 corresponden a mis propios intentos de restart durante la validación de H29 (uno bloqueado por el clasificador de auto-mode, reintentado), no a un problema de duplicación.

**Hallazgo 2 — evidencia directa y no ambigua de que el proceso se vuelve genuinamente no responsivo, no solo lento:** **ambas veces** que se le pidió reiniciarse a un proceso ya saturado, `systemd` tuvo que forzar `SIGKILL` (`code=killed, status=9/KILL`, `Failed with result 'timeout'`) porque el proceso no respondió a `SIGTERM` dentro del timeout de parada (no hay `TimeoutStopSec` configurado en `motor-soc.service`, así que aplica el default de systemd). Esto descarta que sea "solo lento" — el event loop queda efectivamente bloqueado sin poder ni siquiera procesar la señal de apagado ordenado. Esto NO es un OOM-kill (el mensaje sería distinto y vinculado al kernel, no a `result 'timeout'` de systemd) — se confirmó además que la RAM nunca fue el cuello de botella (8GB+ libres en ambos incidentes).

**Hallazgo 3 — mecanismo concreto en el código que explica por qué un solo proceso puede bloquearse así:** `motor/main.py::decide()` está declarado `async def`, pero llama de forma **síncrona y directa** (sin `await`, sin `run_in_executor`) a `process_event()`, que a su vez:
- Llama a `model.predict()` (LightGBM + Isolation Forest) — CPU-bound, sin ceder el control al event loop.
- Llama a `publish_flow()`/`publish_decision()` (`motor/redis_client.py`) — **Redis síncrono** (`import redis`, no `redis.asyncio`), con `socket_timeout=1.0` sí configurado.
- Llama a `enqueue_response_task()` (`motor/response/queue.py`) — **Redis síncrono también, pero sin ningún timeout configurado** (`redis.Redis(host=..., port=..., password=..., decode_responses=True)`, sin `socket_timeout` ni `socket_connect_timeout`) — si Redis se degrada o se satura (recordar el backlog de 99.594 mensajes de H28 en el mismo Redis), esta llamada puede quedarse esperando indefinidamente, bloqueando el único hilo del event loop para **todas** las requests concurrentes, no solo la que la disparó.
- El `ExecStart` real (`infra/systemd/motor-soc.service`, idéntico byte a byte al desplegado — no hay drift acá) es `uvicorn main:app --host 0.0.0.0 --port 8000`, sin `--workers`: **un solo proceso, sin paralelismo real**, confirmado también por `ps` (nunca más de un PID de `uvicorn` a la vez).

Esta combinación — trabajo síncrono bloqueante (CPU y Redis, uno de ellos sin timeout) ejecutado directamente dentro de un handler `async def`, sobre un solo worker sin paralelismo — es exactamente el patrón que puede hacer que la cola de aceptación de conexiones crezca sin límite bajo carga sostenida (compatible con la cola de 239 y luego 66 conexiones observadas) y que el proceso deje de responder incluso a `SIGTERM`. Es además una violación directa de la prohibición ya documentada en `CLAUDE.md` ("No hacer IO síncrono en Fast Path"), aplicada hasta ahora solo a I/O externo (OpenSearch/APIs) pero no verificada contra Redis síncrono dentro del propio Fast Path.

**Lo que NO se confirmó — honestidad explícita:** no se aisló el disparador exacto de por qué escaló justo el 3-sep a las 17:25 en adelante (¿un burst puntual de tráfico real, o acumulación gradual del ruido interno de H28 sobre casi 2 días de proceso sin reiniciar?) — reconstruir esa línea de tiempo exacta requeriría correlacionar miles de líneas `"Fast Path lento"` (warning que el propio `main.py` emite cuando `elapsed_ms > 100`) contra volumen de tráfico minuto a minuto, y el journal de este servicio es lo bastante grande como para que cada consulta con `sudo journalctl -u motor-soc` (sin poder acotar con `--since` por la restricción exacta de argumentos del `sudoers` de auditoría) tardara 60-120+ segundos solo en leerse. **Causa raíz del disparador inicial: no determinada.** Lo que sí queda confirmado con evidencia directa es el mecanismo que explica por qué, una vez saturado, el proceso no se recupera solo y no responde ni a un reinicio ordenado.

**Sobre el límite "≤2 workers (RAM limitada)" de `CLAUDE.md`:** no tiene una razón documentada con números — es una guía general, no calculada contra el hardware real. `.140` tiene 16 núcleos (Xeon Silver 4110) y 14GB RAM (8-9GB típicamente libres incluso con OpenSearch, Redis, `response-worker` y el indexador corriendo). Un segundo worker de `uvicorn` (∼250-300MB de RSS por lo observado) no representa un riesgo real de memoria en este hardware — el límite parece conservador por precaución, no derivado de una medición. Esto no significa que agregar `--workers 2` sea la solución completa: **paralelismo adicional reduce el impacto de UN handler bloqueado, pero no corrige que ese handler siga bloqueando su propio worker** — la corrección de fondo (a decidir, no aplicada en esta sesión, no pedida) sería mover `model.predict()` a un threadpool (`run_in_executor`) y ponerle timeout al cliente Redis de `response/queue.py`, además de evaluar `--workers 2`.

**Decisión:** no se aplica ningún cambio de código en esta sesión — no fue pedido y modificar el Fast Path en producción sin plan de rollback claro no es una decisión para tomar unilateralmente. Queda documentado como pendiente concreto, con mecanismo identificado, para decidir con Antonio si se aborda antes de CrowdSec o se prioriza después.

**Evidencia:** journal completo de `motor-soc.service` (extracto arriba), lectura de `motor/main.py`, `motor/redis_client.py`, `motor/response/queue.py`, `infra/systemd/motor-soc.service` (sin drift confirmado contra el real), `nproc`/`free -h` de `.140`.

---

<a id="h31"></a>
## H31 — `motor/model.py` real en producción usa una lógica de features distinta a la documentada en `model-contract.md` y no versionada en el repo

**Fecha:** 2026-09-05

**Severidad:** Alto (la más alta usada en esta bitácora) — no es un hallazgo de infraestructura, es una posible discrepancia entre el código que generó las métricas de la tesis (AUC 0.97, precisión/recall documentados en `model-contract.md`) y lo que está versionado en `develop`.

**Contexto:** al auditar archivos de `motor/` en `.140` para la reconciliación de H26 (PASO 2), se comparó por hash cada archivo tracked contra su equivalente real en producción. `motor/model.py` no coincide — a diferencia de `dashboard.py` (drift menor, ver abajo) y de `redis_client.py` (ver H32), esta diferencia toca directamente la lógica de inferencia del modelo Golden 4 v7.1.

**Hallazgo — contraste textual, sin interpretar intención ni corrección:**

`.claude/rules/model-contract.md`, sección "Features activos (4 únicos — Golden 4)", documenta:
```
SERVER_TCP_FLAGS          Flags TCP del servidor (SYN, ACK, RST, FIN, etc.)
OUT_PKTS                  Paquetes salientes del cliente al servidor en el flujo
FLOW_DURATION_MILLISECONDS Duración total del flujo en milisegundos
L4_DST_PORT               Puerto destino TCP/UDP (0–65535)
```
y especifica: "El orden y los nombres deben coincidir exactamente con `feature_schema_v5_latest.json`."

El `_features_lgbm()` real en `~/tesis/motor/model.py` (`.140`), que es el código que efectivamente ejecuta cada predicción en producción, construye en cambio un `pandas.DataFrame` con columnas nombradas `Column_0`, `Column_1`, `Column_2`, `Column_3`:
```python
def _features_lgbm(self, f: dict):
    """4 Golden features — el modelo usa Column_0..3 como nombres internos."""
    import pandas as pd
    return pd.DataFrame([{
        "Column_0": float(f.get("SERVER_TCP_FLAGS", 0)),
        "Column_1": float(f.get("OUT_PKTS", 0)),
        "Column_2": float(f.get("FLOW_DURATION_MILLISECONDS", 0)),
        "Column_3": float(f.get("L4_DST_PORT", 0)),
    }])
```
El repo (`motor/model.py`, tracked en `develop`) en cambio construye un `numpy.ndarray` posicional sin nombres de columna:
```python
def _features_lgbm(self, f: dict) -> np.ndarray:
    """4 Golden features en orden para LightGBM."""
    return np.array([[
        f.get("SERVER_TCP_FLAGS", 0),
        f.get("OUT_PKTS", 0),
        f.get("FLOW_DURATION_MILLISECONDS", 0),
        f.get("L4_DST_PORT", 0),
    ]], dtype=np.float32)
```
Adicionalmente, la carga del modelo difiere: producción hace `pkg = joblib.load(MODEL_FILE)` y, si `pkg` es un `dict`, extrae `pkg['model']` con un log `"LightGBM extraído del paquete v{pkg.get('version','?')}"`; el repo asume que `joblib.load(MODEL_FILE)` devuelve directamente el estimador, sin manejar el caso de paquete-dict. Si el `model.py` del repo se desplegara tal cual a producción hoy, la carga del modelo probablemente fallaría o se comportaría de forma distinta a la actual.

**Lo que esto significa, sin especular sobre cuál versión es la correcta:** el código que hoy corre en producción y generó las métricas ya validadas y citadas en `model-contract.md` (AUC 0.97, Brier 0.058, etc.) **no está en ningún commit de este repositorio**. No se sabe, desde el análisis de esta sesión, si `Column_0..3` es el naming interno con el que Joaquín entrenó el modelo (en cuyo caso el repo está simplemente desactualizado y sin riesgo funcional) o si hay una inconsistencia real entre cómo se entrenó y cómo se sirve el modelo (en cuyo caso las métricas podrían no ser reproducibles con el código versionado, o peor, el mapeo de columnas podría no ser el que se cree). Esa interpretación le corresponde a Joaquín, no fue asumida acá.

**Decisión:** no se modifica `motor/model.py` del repo ni se trae la versión de producción al repo en esta sesión, ni siquiera como referencia temporal — se deja explícitamente fuera de cualquier reconciliación hasta que Joaquín confirme cuál versión (o ninguna de las dos) es la correcta. La conversión a checkout real de git en `.140` (H26) debe excluir explícitamente este archivo de la sincronización automática (`git update-index --skip-worktree`) para que un futuro `git pull` no sobreescriba la versión real de producción con la versión del repo, que hoy se sabe desactualizada.

**Evidencia:** diff completo `motor/model.py` (repo) vs. `~/tesis/motor/model.py` (`.140`, descargado por scp para diff local, no editado); hashes SHA-256 distintos confirmados; `.claude/rules/model-contract.md` citado arriba.

---

<a id="h32"></a>
## H32 — `redis_client.py` en producción tenía un password real hardcodeado como fallback, y `motor-soc.service` corría sin `REDIS_PASSWORD` en su entorno

**Fecha:** 2026-09-05

**Contexto:** al reconciliar `motor/redis_client.py` (repo) contra `.140` para H26, el hash no coincidía. El diff mostró `REDIS_PASS = os.environ.get("REDIS_PASSWORD", "soc_ubo_2026")` en producción — un default que parece una password real.

**Hallazgo 1 — el hardcodeo NO era un valor de relleno, era la password real y activa:** `motor-soc.service` no tiene `EnvironmentFile=` ni `Environment=REDIS_PASSWORD=...` en su unit (confirmado leyendo `/proc/<pid>/environ` del proceso real, `REDIS_PASSWORD` ausente). Se probó en vivo, replicando exactamente el entorno de systemd (`REDIS_HOST=localhost`, sin `REDIS_PASSWORD`): con el código desplegado (`redis_client.py` sin arreglar todavía en ese momento), `get_redis()` conectaba exitosamente y un `XADD` de prueba a `soc:decisions` funcionaba usando el valor hardcodeado `"soc_ubo_2026"` — confirmando que ese string **es la password real y vigente de Redis en `.140` en este momento**, no un placeholder. Ya apareció en esta conversación de trabajo (necesario para diagnosticar el problema) — se trata como expuesta, mismo criterio que la password de OpenSearch en H27.

**Hallazgo 2 — sin el hardcodeo, el Fast Path llevaba tiempo funcionando "por casualidad":** `soc:decisions`/`soc:flows` (los streams que alimenta `redis_client.py` desde el Fast Path) sí reciben datos reales de forma continua — pero solo porque el fallback hardcodeado coincide con la password real, no porque el mecanismo de configuración esté bien armado. Si esa password cambiara sin actualizar el código (exactamente lo que se hace en la sección de rotación más abajo), `motor-soc.service` habría quedado silenciosamente incapaz de publicar decisiones — `get_redis()` traga la excepción, loguea `"Redis no disponible"` y devuelve `None`; `publish_decision()`/`publish_flow()` devuelven `False` sin que `process_event()` revise el resultado. Es el mismo patrón de "nadie se entera hasta que alguien audita a mano" que ya se repitió en H22/H24/H25/H27.

**Fix aplicado (commits en `develop`):**
1. `REDIS_PASS = os.environ.get("REDIS_PASSWORD")` sin default, con `raise RuntimeError(...)` explícito si falta — un fallback adivinable es peor que fallar fuerte al arrancar.
2. `load_dotenv()` agregado a `redis_client.py` (mismo patrón de H27 para `opensearch_indexer.py`/`dashboard.py`/`shadow_detect.py`) — sin esto, el fail-fast del punto 1 hubiera tumbado `motor-soc.service` al reiniciar, porque su unit de systemd nunca inyectó `REDIS_PASSWORD` por ningún otro medio.
3. `dashboard.py` redesplegado a `.140` con el `load_dotenv()` que H27 había agregado al repo pero nunca llegó a producción en ese archivo puntual (drift menor, detectado en la misma reconciliación).
4 tests nuevos (`tests/unit/test_redis_client_fail_fast.py`). 51/51 tests del repo pasan.

**Validado en producción:** verificado en un entorno que replica exactamente el `Environment=` de systemd (sin depender de la restricción de `sudo` para journalctl) que `get_redis()` conecta y publica correctamente con la password real leída de `.env`, no del hardcodeo. `motor-soc.service` reiniciado (PID nuevo), `/health` responde en <5ms, `soc:decisions` confirmado recibiendo entradas nuevas en tiempo real después del reinicio (tráfico real, no solo prueba sintética).

**Pendiente — rotación de `REDIS_PASSWORD`:** decidido tratarla como en H27 (rotación real, no solo el fix de código) una vez confirmado que el mecanismo de configuración post-fix es sano — igual criterio que H27: primero que los servicios ya saneados sigan sanos, después rotar. No completada todavía en esta sesión; continúa como sección propia más abajo o en una entrada posterior según cuándo se ejecute.

**Hallazgo relacionado, no corregido (fuera del alcance pedido):** `REDIS_HOST` en el mismo archivo tiene el mismo patrón de riesgo (`os.environ.get("REDIS_HOST", "200.54.12.140")` — la IP pública obsoleta que ya causó el apagón de 17 días de H25). Hoy no causa daño porque `motor-soc.service` sí define `Environment=REDIS_HOST=localhost` explícitamente, pero es el mismo tipo de mina de H25 esperando a que alguien quite esa línea del unit sin darse cuenta. No se tocó — se pidió corregir específicamente el patrón de `REDIS_PASSWORD`, no `REDIS_HOST`.

**Evidencia:** diff `redis_client.py` repo vs. producción (hash distinto confirmado); prueba en vivo de conexión con y sin el hardcodeo, replicando el entorno real de systemd; confirmación de ausencia de `REDIS_PASSWORD` en `/proc/<pid>/environ`; lectura de entradas frescas reales en `soc:decisions` post-fix.

---

## H30 (continuación) — mitigación estructural aplicada y validada con evidencia real

**Fecha:** 2026-09-05

**Confirmación previa a tocar código:** se revisó el estado real antes de asumir nada. `redis_client.py` ya tenía `socket_timeout=1.0`/`socket_connect_timeout=1.0` (preexistente, no un fix de esta sesión), pero `response/queue.py` (el cliente que usa `enqueue_response_task`, llamado también desde el Fast Path en cada request) **no tenía ningún timeout configurado**, y `main.py::decide()` seguía llamando a `process_event()` de forma síncrona e inline, sin `run_in_executor`. Es decir: la mitigación estaba solo parcialmente y accidentalmente aplicada, nunca a propósito ni completa.

**Fix 1 — timeout explícito en `response/queue.py`:** agregados `redis_socket_timeout`/`redis_socket_connect_timeout` (1.0s, mismo criterio que `redis_client.py`) a `ResponseSettings`, aplicados al cliente `_rdb`.

**Fix 2 — `process_event()` fuera del event loop principal:** `main.py::decide()` ahora usa `loop.run_in_executor(None, process_event, ...)` en vez de llamarlo inline. Se optó por esto (threadpool, un solo proceso) y no por `--workers 2` — la opción que sí requiere confirmar con Joaquín por duplicar el modelo en memoria por proceso — porque resuelve el mismo síntoma (event loop bloqueado) sin ese riesgo: los threads comparten memoria, así que no hay duplicación del modelo ni problema de inicialización concurrente que evaluar. Both LightGBM y el `IsolationForest` son de solo-lectura durante inferencia (no hay reentrenamiento en el Fast Path) y son de uso concurrente documentado entre threads; los clientes Redis ya usan `ConnectionPool`, también thread-safe. La opción `--workers 2` queda como posible mitigación adicional, no aplicada, pendiente de que Joaquín confirme que el modelo tolera cargarse en más de un proceso sin problema de memoria.

**Hallazgo no anticipado durante la validación — el timeout de 1.0s por sí solo NO acotaba el peor caso real:** al validar con `CLIENT PAUSE` contra un Redis de prueba local (nunca el de producción, servidor descartable en el puerto 16379, jamás alcanzable desde `.140`), un único intento de `XADD` contra un servidor pausado tardó **~5 segundos**, no el ~1s esperado del `socket_timeout` configurado. Investigado antes de asumir que el timeout "no funcionaba": `redis-py` 8.x (la versión real tanto en desarrollo como en producción — confirmado con `lib_version='8.0.0'` en `.140`) trae un `Retry` por defecto con hasta 10 reintentos sobre `TimeoutError`/`ConnectionError`, **incluso con el parámetro legado `retry_on_timeout=False`** (deprecado exactamente por esto: "TimeoutError is included by default" en el warning de la propia librería). Se aisló con un socket crudo (sin redis-py) que el timeout de 1.0s SÍ se respeta a nivel de sistema operativo — el problema era enteramente de la capa de reintentos de la librería cliente, no del socket ni de Redis.

**Fix del hallazgo:** `retry=Retry(NoBackoff(), 0)` explícito en ambos clientes Redis del Fast Path (`redis_client.py` y `response/queue.py`) — fuerza un único intento real. Sin este parámetro explícito, el default no documentado de la librería anula la protección que `socket_timeout` aparenta dar.

**Validación real (no solo tests, TestClient + Redis de prueba pausado, nunca producción):**
- Con el fix, el mismo `CLIENT PAUSE` produce `TimeoutError` en `1.001s` — confirmado, no solo "parece que anda".
- `/decide` completo (vía `TestClient` contra `motor/main.py` real) con el Redis de prueba pausado 5s: la decisión se devuelve igual, con `HTTP 200`, en **2.014s** (dos timeouts de 1s secuenciales — `publish_flow` y `publish_decision` — no cinco segundos de bloqueo; el tercer cliente, `enqueue_response_task`, ni se invoca porque el evento de prueba dio tier=0). Degrada, no se cuelga.
- 5 requests concurrentes vía `TestClient` (Redis ya destrabado) completadas en 0.048s totales — confirma que `run_in_executor` efectivamente permite procesamiento concurrente real, no solo que no rompe nada.
- Desplegado a `.140` vía `git pull` en `~/tesis/repo` (el primer deploy real usando la conversión de H26 — un solo comando en vez de scp+backup+hash a mano) + restart de `motor-soc.service`. Confirmado en producción: modelo real (`golden4_v7_1`) sigue cargando correctamente, 5 requests concurrentes reales devuelven `200`.

**Evidencia:** 10 tests nuevos (`tests/unit/test_redis_bounded_timeout.py`, `tests/unit/test_decide_executor.py`), 61/61 tests del repo pasan. Commit `4764dec` en `develop`, pusheado y desplegado. Script de validación manual con Redis de prueba (puerto 16379, `redis-server` local vía `brew`, nunca conectado a `.140`) documentado arriba, no commiteado (era exploratorio, no parte del repo).

**Disparador original del 3-sep:** sigue como "no determinado" (H30 original) — esta sección cierra la mitigación estructural, no la investigación forense de esa fecha puntual, que sigue sin evidencia suficiente para determinarse.

---

## Pendientes detectados (no resueltos hoy)

- **`--workers 2` para `motor-soc.service`, evaluado pero no aplicado** (H30): el `run_in_executor` ya mitiga el bloqueo del event loop; un segundo worker de proceso completo daría paralelismo real adicional pero duplica el modelo en memoria por proceso — pendiente confirmar con Joaquín si el modelo tolera esa duplicación sin problema (RAM disponible en `.140` no parece ser el límite real, ver H30 original, pero no se asumió sin preguntar).

- **Inestabilidad de conexión periódica agente-manager:** patrón recurrente (~cada hora) de "Agent key already in use", "Response timeout", "Cannot send request to agent" entre .139 y .138. Causa no confirmada — candidatos: desincronización de reloj, proceso periódico en .138 reiniciando la conexión, configuración de keepalive. Pendiente investigar antes de noviembre, puede explicar fallos silenciosos de Active Response a futuro.
- **20 reglas de threat intel inactivas** (IDs 99901-99920): referencian listas IOC (malicious-ioc/malware-hashes, malicious-ip, malicious-domains) que nunca se cargaron con contenido real. Las reglas existen pero no tienen efecto. Pendiente decidir si se completan con feeds reales o se eliminan del ruleset.
- **Verificar directamente la regla NAT/MASQUERADE en `.139`:** el `sudo` restringido de auditoría documentado no permitía leer `/etc/ufw/before.rules` ni `iptables -t nat -L` (ver H17). El diagnóstico de H21 sí involucró leer y editar `before.rules` directamente — si eso se hizo con acceso ampliado o manual, actualizar acá y en el alcance del `sudo` de auditoría (`.claude/skills/soc-audit/SKILL.md`) para que quede consistente con lo que realmente es accesible hoy.
- **Perfil `netplan-eno1` duplicado en `.139`:** perfil de NetworkManager inactivo con el mismo `interface-name=eno1` que `netplan-zz-all-en` (H18). No representa riesgo mientras siga sin autoconectar, pero es candidato a limpieza para evitar ambigüedad futura.
- **Sin monitoreo de `motor-soc.service`/`redis-server.service` en `.140`** (H22): el heartbeat existente solo cubre `motor-watcher.service` en `.139` y además depende de Redis sin manejo de fallo — sería ciego a una repetición exacta de H22. Diseñar un check independiente de Redis (o con fallback que no dependa de él) que cubra el motor y el propio Redis, no solo el vigilante FIM.
- **Cuantificar el hueco real en `soc-decisions`/OpenSearch durante la ventana de H22** (2026-08-26 a 2026-09-02): no se verificó cuántas decisiones reales faltaron indexar en esos ~6 días (el motor estaba muerto, no solo el indexador) — útil para el capítulo de resultados si se necesita justificar o excluir ese rango de cualquier métrica de disponibilidad.
- **Actualización de firmware del switch SG350** (H20): evaluar upgrade desde v2.4.0.94 para dejar de depender del workaround de algoritmos SSH legacy en el cliente.
- **Sin monitoreo de `response-worker.service`** (H24): igual que el punto de arriba para `motor-soc`/Redis, pero para el worker de R1/R2 — es el que realmente se quedó ~9 días muerto sin que nadie lo notara hasta revisar OTX. Mismo diseño de check pendiente debería cubrir los tres (`motor-soc`, `redis-server`, `response-worker`).
- **Monitoreo de los sinks de Vector** (H25): mismo punto ciego que `motor-soc`/`redis-server`/`response-worker` — un sink HTTP que falla en loop silencioso (`No route to host`) durante 17 días sin que nada lo marque como "failed" ni alerte a nadie. Evaluar health-check sobre `vector-soar.service` que además valide que los sinks de red efectivamente entregan (no solo que el proceso esté `active`). Sigue abierto pese al fix aplicado: el reinicio no agrega ese monitoreo, solo corrige el síntoma puntual.
- **Causa no determinada: timeouts de Redis en `.140` (localhost) durante el mismo rango** (H25): `response-worker.service` y el proceso huérfano de `opensearch_indexer.py` empezaron a fallar con `Timeout reading from socket` contra Redis en `127.0.0.1` casi al mismo minuto que se cortó el tráfico de Vector, y no se recuperaron en ~2.5 semanas, pese a que `redis-server.service` no se cayó (per H22) hasta el 26-ago. Mecanismo sin confirmar — no se descarta relación con el propio corte de red de `.140` al migrar de IP pública a VLAN 10, pero no hay evidencia directa (sin acceso de auditoría al journal de `NetworkManager`/sistema de `.140` para esa fecha).
- **Reconciliar `vector.production.toml` entre `.139` y el repo, o decidir estrategia de despliegue** (H26): el archivo real en producción no está bajo git y difiere sustancialmente del tracked en `develop` (le faltan los sinks `motor_soc` y `suricata_alerts_os` enteros). Tres opciones propuestas en H26 (checkout real + deploy key, script de deploy, cron de detección de drift), ninguna aplicada — decisión de Antonio pendiente.
- **Rotar la contraseña real de OpenSearch** (H27): bloqueado por `403 Forbidden` — el usuario `admin` es `"reserved": true`, la Security REST API no permite modificarlo. Requiere editar `internal_users.yml` dentro del contenedor + `securityadmin.sh` con certificados de admin, con backup del volumen de `opensearch-soc` antes. Además quedó expuesta una vez en el output de una sesión de trabajo (ver H27) — motivo adicional para no postergarlo indefinidamente.
- **Rotar `REDIS_PASSWORD`** (H32): quedó expuesta en esta sesión (apareció en el diff necesario para diagnosticar el hardcodeo). Toca 8 archivos consumidores conocidos (`motor/dashboard.py`, `motor/opensearch_indexer.py`, `motor/redis_client.py`, `motor/response/queue.py`, `motor/response/worker.py`, `motor/response/config.py`, `vigilante/cases.py`, `vigilante/heartbeat_check.py`) más `requirepass` en la config real de `redis-server` — no confirmada la ruta exacta del archivo de config en esta sesión. Deliberadamente pospuesta como tarea separada, mismo criterio que la rotación de OpenSearch en H27: primero confirmar que el fix de código (ya desplegado y validado) deja todo sano, rotar después con un plan coordinado explícito, no de apuro.
- **Monitoreo de credenciales/config desincronizadas** (H27): el mismo patrón de "nadie se entera hasta que alguien audita a mano" que ya se repitió en H22/H24/H25 — evaluar un chequeo que valide periódicamente que los `.env`/`EnvironmentFile` de los 3 consumidores de OpenSearch (`opensearch-indexer`, `vector-soar`, `shadow-detect`) autentican correctamente, no solo que los procesos estén `active`.
- **Investigar por qué `src_ip` en el Fast Path llega como IP privada** (H28): en la ventana observada, el 100% del tráfico enriquecido por R1 tenía como origen `10.10.10.3`/`10.30.30.2` (hosts propios), no atacantes externos. Candidatos a investigar (fuera de alcance de H28, dominio de red/Suricata/Vector de Antonio): dónde se posiciona la captura de Suricata respecto al punto de NAT en `.139` post-migración, si `IPV4_SRC_ADDR` de nProbe/Vector está tomando el lado LAN de un flujo NAT-eado, o si el tráfico externo real simplemente no está llegando al pipeline en este momento. Bloquea la validación real de la cuota de OTX bajo carga (pendiente de H23) y limita el valor práctico de la corroboración multi-fuente recién implementada hasta que se resuelva.
- **Desplegar el fix de H28 a `.140` y re-medir**: el gate de corroboración y el guard de IP privada quedaron en `develop`, no desplegados. Una vez desplegado, repetir la lectura de solo-lectura de `soc:response:audit` (mismo método que H28) para confirmar en producción que `otx_available` deja de ser 100% `False` para las IPs privadas y, tras resolver el punto anterior, medir la tasa real de IPs públicas distintas/hora contra el límite de ~10.000 req/hora de OTX.
- **Confirmar el límite oficial de rate-limit de OTX contra documentación vigente**: la cifra usada en H28 (~10.000 req/hora con API key) viene de resultados de búsqueda web (AT&T/LevelBlue, foros de comunidad), no de la documentación oficial actual verificada directamente (las páginas oficiales devolvieron 503 al intentar consultarlas). Confirmar antes de citarla en la tesis como dato duro.
- **Revisar si `r2_min_tier=2` sigue siendo el valor correcto** (H28): la tabla de la sección 4 de la especificación solo contempla bloqueo automático en T3; con el default actual (sin override en `.env` de `.140`), eventos T2 igual llegan al gate de R2 (ahora con corroboración exigida, pero conceptualmente T2 no debería intentar bloquear en absoluto según el diseño vigente). No se tocó en H28 por ser un cambio de umbral operacional en producción, fuera del alcance de "no tocar R2". Decisión pendiente de Antonio.
- **Agregar `response-worker` al `NOPASSWD` de auditoría en `.140`** (H28): a diferencia de `motor-soc`/`opensearch-indexer`/`redis-server`, reiniciar o leer el `journalctl` de `response-worker.service` requiere contraseña interactiva — quedó descubierto al intentar validar el deploy de H28 sin poder ejecutarlo de forma no interactiva. Si se sigue desplegando con esta cadencia, vale la pena ampliar el sudoers de auditoría (`.claude/skills/soc-audit/SKILL.md`) para incluirlo, con el mismo criterio acotado (comandos específicos, no `NOPASSWD: ALL`) que ya se usa para los otros tres servicios.
- **Mensaje huérfano sin `XACK` en `soc:response:tasks`** (H28): `xpending` mostró un mensaje entregado al consumer `worker-1` hace ≈22.7 días nunca reconocido, pese a que `worker.py` hace `XACK` siempre en un bloque `finally` — solo explicable por un kill duro del proceso entre entrega y ACK. No bloquea el consumo (el grupo sigue avanzando), pero es candidato a limpieza (`XACK`/`XCLAIM` manual) y a preguntarse si hay más mensajes huérfanos acumulados de otros incidentes (H22/H24/H25) sin revisar.
- **Dos permisos de escritura que la skill de auditoría asume y no existen** (H27): la skill documenta NOPASSWD para `systemctl restart`/escritura de unit files en `.140` y para `vector-soar.service` en `.139`; en la práctica ambos pidieron contraseña interactiva. Actualizar `.claude/skills/soc-audit/SKILL.md` para reflejar el alcance real del `sudo` de auditoría (ya pasó lo mismo con H17/antes) o ampliar el `sudoers` si se quiere que quede cubierto.
