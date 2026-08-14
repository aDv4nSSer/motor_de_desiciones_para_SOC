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

---

## H9 — Cowrie caído 3 días por PATH faltante en servicio systemd

**Fecha:** 2026-06-18
**Contexto:** Al revisar el estado de Cowrie el 18 de junio, se detectó que llevaba inactivo desde el 15 de junio a las 23:17 — exactamente después de la sesión de ataques controlados y el reinicio de UFW.

**Hallazgo:** El servicio systemd de Cowrie no tenía configurada la variable de entorno PATH del virtualenv. Al intentar iniciar, Cowrie ejecuta `os.execvp("twistd", ...)` pero systemd no incluye el directorio `cowrie-env/bin/` en el PATH del proceso, causando `FileNotFoundError`.

**Decisión:** Agregar `Environment=PATH=/home/cowrie/cowrie/cowrie-env/bin:...` al archivo cowrie.service. Cowrie reiniciado exitosamente.

**Impacto:** 3 días sin captura de sesiones SSH reales (15-18 junio). El corpus perdió aproximadamente 3-4 días de sesiones Cowrie estimadas en 50-100 sesiones adicionales.

**Lección:** Los servicios systemd que usan virtualenvs de Python deben declarar explícitamente el PATH del virtualenv en la configuración del servicio, ya que systemd no hereda el PATH del usuario.

---

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

## H12 — FIM ampliado a WordPress + bugs de sintaxis restrict y limitación de tiempo real

**Fecha:** 2026-07-05
**Contexto:** El análisis de "qué pasa si un atacante traspasa el perímetro" llevó a auditar el alcance real del FIM de Wazuh en .138 (servidor web). Se encontró que syscheck solo vigilaba rutas del sistema operativo (/etc, /usr/bin, etc.), dejando el webroot completo de WordPress/educasex sin ningún tipo de monitoreo de integridad.

**Hallazgo:** Se amplió syscheck para cubrir wp-admin, wp-includes, wp-content/plugins, wp-content/themes (vigilancia completa) y wp-content/uploads (vigilancia restringida solo a ejecutables vía atributo restrict, dado que ahí hay escritura legítima constante de WordPress). Surgieron dos problemas reales:
1. La sintaxis inicial del restrict (`\.(php|phtml|phar|php[0-9])$`, con grupo de alternancia entre paréntesis) es sintaxis PCRE no soportada por el motor sregex de Wazuh — el filtro coincidía con cero archivos en vez de fallar visiblemente. Corregido a `.php$|.phtml$|.phar$|.php[0-9]$` (patrones repetidos, sin paréntesis, sin escapar el punto), siguiendo el ejemplo oficial de Wazuh.
2. Tras corregir el restrict, el escaneo por lotes detecta y filtra correctamente (validado: 471 archivos en uploads/, solo 4 .php capturados). Pero la detección en tiempo real (realtime, basada en inotify) no procesa archivos nuevos en ninguna carpeta agregada — confirmado que el kernel entrega los eventos correctamente (probado con pyinotify de forma aislada), así que el problema está específicamente en cómo wazuh-syscheckd consume esos eventos. Sospecha no confirmada: relacionada a los ciclos de reconexión agente-manager (ver Pendientes).

**Decisión:** Mitigación mientras se investiga la causa raíz del bug de realtime: frecuencia del escaneo programado bajada de 12h a 5 minutos para syscheck (rootcheck se mantuvo en 12h). Acota la ventana de exposición de "hasta 12 horas sin detectar un webshell" a "hasta 5 minutos", con el restrict funcionando correctamente en modo batch.

**Evidencia:** 471 archivos totales bajo uploads/, 4 correctamente capturados con el restrict corregido (3 pruebas .php + 1 index.php legítimo de plugin). pyinotify confirmó entrega de eventos IN_CREATE/IN_CLOSE_WRITE del kernel en <1s. auditd/whodata evaluado como alternativa pero no instalado — queda para noviembre.

---

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

## H14 — Timeout de systemd insuficiente en wazuh-manager.service

**Fecha:** 2026-07-05
**Contexto:** Un `systemctl restart wazuh-manager` (necesario para cargar el comando de H13) falló con timeout, marcando el servicio como failed pese a que los daemons reales (incluidos wazuh-analysisd y wazuh-remoted) seguían arrancando y terminaban operativos como procesos huérfanos.

**Hallazgo:** El unit de systemd de Wazuh trae TimeoutSec=45, insuficiente para un arranque completo bajo carga real (~40-50s medidos, margen ajustado). systemd mata el proceso ExecStart al cumplirse el timeout, pero los daemons ya lanzados sobreviven como huérfanos y siguen funcionando — generando un falso "failed" que no refleja el estado real del servicio.

**Decisión:** Override permanente vía drop-in de systemd (/etc/systemd/system/wazuh-manager.service.d/override.conf), sin modificar el unit file del paquete. TimeoutStartSec=180, TimeoutStopSec=60.

**Evidencia:** Tras el override, `systemctl restart wazuh-manager` completa limpio (active (running), status=0/SUCCESS) sin intervención manual con wazuh-control.

**Lección de diseño:** un estado "failed" de systemd no siempre significa que el servicio esté caído — puede ser un falso negativo de monitoreo. Verificar el estado funcional real (agent_control -l, API respondiendo) antes de asumir una falla real.

---

## H15 — Caída de Redis expone falta de supervisión de proceso en response.worker

**Fecha:** 2026-08-11

**Contexto:** `redis-server.service` (`.140`) dejó de estar disponible entre las 06:49 y las 22:34 (~15.5h). `motor-soc` (FastAPI, Fast Path) degradó con gracia como estaba diseñado — decisiones provisionales continuaron sin bloquear por IO externo. `response.worker`, en cambio, corría en ese momento como proceso sin supervisión de systemd (lanzado manualmente, sin unit propio), sin `Requires=redis-server.service` ni política de `Restart=`.

**Hallazgo:** Al perder la conexión a Redis, `response.worker` no terminó ni entró en un ciclo de retry visible — quedó como proceso vivo pero funcionalmente muerto (zombie): sin consumir la stream `soc:response:tasks`, sin nuevas líneas `[ENFORCE]` en `worker.log`, sin excepción no capturada que un supervisor pudiera detectar. Cuando `redis-server.service` volvió a las 22:34, el worker **no** retomó el consumo por sí solo — siguió colgado en el mismo estado hasta que se lo mató manualmente (`kill`/`pkill`) y se relanzó a mano. El motor (FastAPI) sí se recuperó automáticamente al reconectar con Redis, confirmando que la degradación con gracia funciona correctamente en el Fast Path — el punto ciego era exclusivamente el worker.

**Causa raíz:** Evento de reinicio masivo de servicios a las 06:49:02, patrón consistente con `unattended-upgrades`/`needrestart` tras la actualización de una librería compartida (121 actualizaciones pendientes, flag "system restart required" confirmado en el sistema). Docenas de servicios no relacionados se reiniciaron limpio en esa misma ventana; `redis-server` fue de los pocos en fallar el reinicio automático — exit-code 1, 5 intentos agotados antes de que systemd desistiera con "Start request repeated too quickly for redis-server.service".

**Factor contribuyente:** `vm.overcommit_memory=0` en el host. El propio log de Redis advierte explícitamente que este valor puede causar fallos de arranque incluso sin baja memoria real (Redis necesita poder hacer `fork()` para el guardado en background del RDB; con overcommit=0 el kernel puede rechazar esa asignación bajo ciertas condiciones de memoria virtual comprometida). **Recomendación pendiente de aplicar** — al 2026-08-12 el valor sigue en `0`; no se cambió a `vm.overcommit_memory=1` (sin acceso SSH a `.140` para ejecutarlo o confirmarlo; ver bloqueo de acceso registrado en la sesión de auditoría del 2026-08-12).

**Decisión:** Diseñar `response-worker.service` (systemd) con `Requires=redis-server.service`, `Restart=on-failure`, `RestartSec=5`, y `StartLimitIntervalSec=300`/`StartLimitBurst=6` calibrados para tolerar una reconexión breve pero no una caída sostenida — tras agotar el burst, el servicio queda en `failed` de forma visible en lugar de reintentar indefinidamente en silencio, forzando intervención humana ante un corte largo de Redis en vez de repetir el zombie de hoy en otra forma. Logging mantenido en `worker.log` (vía `StandardOutput=append:`) para no romper el paso 1 de la metodología de auditoría del skill `soc-audit`, que cuenta líneas `[ENFORCE]` ahí.

**Evidencia:** Ventana de caída confirmada 06:49–22:34 (2026-08-11) en `journalctl -u redis-server` / ausencia de `[ENFORCE]` nuevos en `worker.log` durante ese rango. Proceso `response.worker` confirmado vivo pero sin actividad (`ps aux` mostraba PID activo sin avance de logs) antes del kill manual. El log específico de `redis-server` para la ventana del incidente (11 de agosto) ya no existe por rotación semanal — la causa raíz se reconstruyó vía `journalctl` del sistema (timestamps, exit codes y unidades reiniciadas), no del log de Redis mismo.

**Nota metodológica — impacto en auditorías futuras:** el paso 1 de la metodología de `soc-audit` (comparar 1:1 líneas `[ENFORCE]` de `worker.log` contra `"command":"add"` en `active-responses.log` de `.138`) **debe excluir o marcar por separado la ventana 06:49–22:34 del 2026-08-11** al calcular cualquier discrepancia de conteo que abarque este día. Durante esa ventana el worker no procesó tareas por el zombie documentado acá, no por pérdida o duplicación real del pipeline — cualquier auditoría que cubra este rango sin anotar la exclusión reportaría una discrepancia inexplicada que en realidad ya está explicada y resuelta en este hallazgo.

---

## H16 — Punto ciego estructural: Suricata no ve tráfico directo al uplink ISP de .138

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

---

## Pendientes detectados (no resueltos hoy)

- **Inestabilidad de conexión periódica agente-manager:** patrón recurrente (~cada hora) de "Agent key already in use", "Response timeout", "Cannot send request to agent" entre .139 y .138. Causa no confirmada — candidatos: desincronización de reloj, proceso periódico en .138 reiniciando la conexión, configuración de keepalive. Pendiente investigar antes de noviembre, puede explicar fallos silenciosos de Active Response a futuro.
- **20 reglas de threat intel inactivas** (IDs 99901-99920): referencian listas IOC (malicious-ioc/malware-hashes, malicious-ip, malicious-domains) que nunca se cargaron con contenido real. Las reglas existen pero no tienen efecto. Pendiente decidir si se completan con feeds reales o se eliminan del ruleset.
