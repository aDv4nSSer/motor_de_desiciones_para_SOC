# Gestión interna de casos y correcciones de Alertas (H60)

Trabajo del 10-oct, de 12:15 a 14:00 -03, en la rama local `feature/casos-ui` (sobre `feature/explicabilidad`, `9a01771`). Se hizo en un `git worktree` aparte (`../motor_soc_casos_ui`), así que los 4 archivos sin versionar del directorio principal no se movieron. No hubo push, deploy, restart ni escrituras en producción. Sobre producción hubo solo lecturas, en tres conexiones SSH (ver H60 en la bitácora).

## Ramas y tests

| Commit | Contenido | Tests |
|---|---|---|
| `55f4b7b` | Backend de casos: permisos por rol, transiciones, `soc:cases:worked` con tope de 5.000, página con filtros, detalle, CSV de cierres | 856 passed (27 nuevos); foto fija de R2 sin cambios |
| `e95ec4b` | Frontend: Casos, correcciones de Alertas, traza v1 | 56 passed (8 nuevos), `tsc` limpio |
| `b5b79a7` | Ajustes de layout y textos del backend sin guiones largos | 56 passed |
| (este) | Análisis de solo lectura (`scripts/metrics/analisis_h60.py`), H60, PENDIENTES, ROADMAP_2027, este informe y capturas | **860 passed** (4 nuevos del análisis) |

Pre-commit (bandit, detect-secrets, ruff) limpio en cada commit. `oxlint` sin advertencias nuevas.

**Lo que no cambia:** ningún archivo del camino de decisión. El diff contra producción (`43a62bd`) no toca `motor/response/worker.py`, `enforcer.py`, `enrichment.py`, `approvals.py`, la corroboración, `motor/model.py` ni `campana_automatica.sh`. El único cambio en `motor/response/` es el campo `organizacion_es_oiv` de H57, que lee solo la vista de Cumplimiento.

## 1. Casos

| Pieza | Estado |
|---|---|
| Lista | Paginada por cursor, filtros de estado y ventana (24 h, 72 h, 7 días), solo IPs públicas por defecto, agrupación por /24. Columnas: IP o /24, tier, riesgo, primera y última vez, ocurrencias, estado, fuentes de TI y trace_id |
| Tier | Derivado del `kind` (`network_t2_unconfirmed` es T2); el caso no guarda el tier. No hay filtro por tier: hoy todos los casos son T2 |
| Fuentes de TI | Desde `POST /responses/lookup` con el trace_id de apertura, una consulta por página |
| Detalle | Línea de tiempo (actor, hora, nota), traza explicativa v1, TI (AbuseIPDB y OTX con motivo si no se consultó), ATT&CK si hay mapeo, evidencia por referencia (trace_id de apertura y último, documento de respuesta, eslabones de la cadena con `chain_seq` y hash). Sin adjuntos |
| Acciones | N1: abierto a en investigación. N2 y CISO: cerrar como confirmado o falso positivo, con nota obligatoria. El backend valida; la UI muestra el rechazo (403, 409, 422) sin cambiar el estado |
| CSV | `GET /cases/closures.csv`, N2 y CISO: case_id, IP, /24, estado, hora, actor, trace_id. Para la muestra manual de precisión |
| Iris | Ninguna mención en la UI. La vista se llama "Gestión interna de casos" |

## 2. Alertas

| # | Corrección | Resultado |
|---|---|---|
| 1 | Acción recomendada | Hoy sale "Sin acción" en T3 que R2 resolvió porque `worker.py:302-305` guarda `ninguna` para todo resultado de `respond_block` que no sea un bloqueo nuevo. Ahora se deriva de `block.action` y `block.reason`: "Ya bloqueada (TTL extendido)", "Bloqueo automático", "Pendiente de aprobación N1" (nivel del registro), "Infra propia, sin caso" |
| 2 | TI | "AbuseIPDB no consultada (política de cuota, solo caché)" para `r2_min_tier`, throttling y "no decisiva"; "no disponible (error)" solo para HTTP, timeout o negative cache. "1 fuente corrobora", "2 fuentes corroboran" |
| 3 | Modelo | Versión de LightGBM (`model_version`). Hash de LightGBM, versión y hash del Isolation Forest, `policy_version` y `regime_id`: "sin dato", porque `soc-decisions-*` no los guarda. El campo salía vacío: con `??`, solo una cadena vacía en `model_version` deja la celda en blanco (inferencia por el código; el indexador escribe `""` cuando el mensaje no trae la versión), así que ahora se usa `||` |
| 4 | Reglas y razonamiento | Traza v1 con "Reglas explicativas v1; SHAP pendiente." (N2; N1 ve que requiere N2) |
| 5 | Contadores de 60 min | Rótulo "Decisiones T3/T2/totales" y la aclaración de la unidad. IPs distintas e infra propia, en el análisis C (offline), sin tocar `get_stats` |

## 3. Análisis de solo lectura para la tesis

Extracción vigente en `.140` el 10-oct de 13:50:31 a 13:53:17 -03 (versión con flujos de A y análisis D): una conexión, 282 consultas paginadas, sin abortos por heap ni latencia. Las cifras de B y C de abajo son de la corrida de 13:30:53; la de 13:50 las reproduce con 20 minutos más de datos. Ventana desde el 3-oct 00:00Z hasta la extracción, en días UTC. **Es preliminar:** el período 2 cierra el 12-oct 11:21 y el corte de datos es el 14-oct 21:00; las corridas finales usan el mismo comando con `--hasta`. **Salidas fuera de git:** los CSV y la extracción cruda están en `~/tesis_archivo/metricas_h60/h60_2026-10-10T165031/`, con el sha256 de cada archivo y del script en `reports/metricas/2026-10-10/manifiesto_h60.md` (versionado). El resumen `analisis_h60.md` sí va al repo. La corrida final usa `--archivar`; el script se niega a archivar dentro de un repositorio git. Retención: los índices diarios de `soc-responses-*` y `soc-decisions-*` tienen política ISM (90 días según el código; el valor efectivo en `.140` no se leyó). **TTL del bloqueo verificado:** `BLOCK_TTL_SECONDS=1800` en el `.env` real de `.140` (se leyó solo esa clave).

**Muestra.** Los conteos, las IPs y los pares origen y puerto son exactos. Solo la unión de A con `soc-decisions-*` (ml_score y anomaly_score) usa 1 de cada 10 respuestas, con paso fijo: 14.541 en la muestra, 13.439 unidas (92,4%). Las 1.102 restantes no tienen decisión en `soc-decisions-*`; la causa no se investigó.

### A) Infra propia como benigno conocido

> **No es una tasa de falsos positivos sobre tráfico externo.** Mide cuánto tráfico propio, benigno y conocido, el modelo lleva a T2/T3. No sirve para estimar falsos positivos sobre Internet.

| Medida | Valor |
|---|---|
| Decisiones T2/T3 de infra propia | **145.409 de 1.061.696 (13,7%)**, 5 IPs |
| Por tier y día | T2: entre 8,7% y 19% de los T2 (43% el 3-oct); T3: entre 1,4% y 4,3% |
| Pares dominantes | `10.10.10.1` a 6379 (Redis, 26,9%) y a 9201 (OpenSearch, 18,8%); `10.10.10.3` a 55000 (API de Wazuh, 13,2%) y a 443 (10,5%); `10.30.30.2` a 53 (8,6%); `200.54.12.139` a 53 y 443 |
| Flujos distintos (origen, destino, puerto) | **555** en la ventana; entre 82 y 88 flujos T2 por día contra ~13.000 decisiones T2 de infra por día (unas 160 decisiones por flujo). Los 5 principales concentran el 73,8% |
| Flujos principales | `10.10.10.1` a `10.10.10.3`:6379 (Redis, 26,9%) y :9201 (OpenSearch, 18,8%); `10.10.10.3` a `200.54.12.139`:55000 (API de Wazuh, 13,2%); `10.30.30.2` a un resolver externo :53 (8,6%); `200.54.12.139` a un resolver externo :53 (6,4%) |
| ml_score (muestra) | 65,9% entre 0,6 y 0,7; 30,6% entre 0,7 y 0,8; 3,6% sobre 0,9 |
| anomaly_score (muestra) | 48,5% entre 0,6 y 0,7; 33,6% entre 0,4 y 0,5; 14,6% entre 0,8 y 0,9 (el 0,865 del ejemplo es el p90) |

La unidad comparable es el flujo, no la decisión: un mismo flujo repetido genera cientos de decisiones por día y no son eventos independientes. Lectura: el LightGBM asigna entre 0,6 y 0,8 de probabilidad de ataque a tráfico propio rutinario (Redis, OpenSearch, API de Wazuh, DNS), y eso basta para T2. Toda decisión T2/T3 de infra propia es un falso positivo del umbral de T2. La tasa sobre todo el tráfico propio no es medible: las decisiones T0/T1 no guardan `src_ip`. **Salvedad:** es benigno conocido de un tipo muy particular; no representa tráfico externo benigno ni sirve para estimar falsos positivos sobre Internet.

### B) T2 con dos o más fuentes corroborando (incluida la caché)

| Medida | Valor |
|---|---|
| Cobertura | Desde el 8-oct: `corroboration_count` es buscable en `soc-responses-*` desde H52 (`fe58bdb`) |
| Decisiones, IPs, redes /24 | 75.325 decisiones, **763 IPs**, 262 redes /24; **61 /24 con 2 o más IPs** (campaña candidata) |
| IPs por día | 658 (8-oct), 393 (9-oct), 313 (10-oct, parcial) |
| Campaña principal | `91.92.42.0/24`: **256 IPs**, 38.310 decisiones, todas al puerto 443. Le siguen `85.217.140.0/24` (39 IPs) y `85.217.149.0/24` (37), con puertos dispersos, y `185.148.0.0/24` (8 IPs, 12.048 decisiones a 443 y 8080) |
| Puertos | 443 domina (289 de las 763 IPs como puerto principal); después 2223 (honeypot), 8080 y 3389 |
| Si hubieran sido T3 | **443 IPs** habrían sido bloqueo automático nuevo y **320** ya estaban bloqueadas (TTL extendido); se excluyen las IPs con todos sus eventos más viejos que 3.600 s |
| La ola de `91.92.42.0/24` | Las 256 IPs tuvieron su **primer bloqueo el 4-oct entre 00:00 y 01:25 UTC** (es el pico de 271 primeros bloqueos de ese día). **Ninguno de los 85 primeros bloqueos del 10-oct es de esa red**: están repartidos en muchos /24 (como máximo 4 en `85.217.140.0/24`) y a lo largo del día |
| Los dos ejemplos | `91.92.42.173` y `91.92.42.80` (AbuseIPDB 100; OTX 26 y 50 pulsos) ya habían sido bloqueadas automáticamente antes de su primer T2 corroborado: como T3 habrían sido TTL extendido, no bloqueo nuevo |

Lectura: la brecha se concentra antes de R4. En el día UTC del 10-oct, **las 313 IPs T2 corroboradas ya habían sido bloqueadas automáticamente al menos una vez** en la ventana, y ninguna IP que apareció por primera vez en R4 habría sido un bloqueo nuevo. Es cota superior: supone que la corroboración observada en T2 se habría repetido en T3. Es análisis de sensibilidad, no un cambio de política; el hallazgo va a ROADMAP_2027.

### C) Autonomía: bloqueos nuevos y TTL extendidos (IPs distintas, sin infra propia)

| Día UTC | IPs T3 | Con bloqueo ejecutado | Primera vez en la ventana | Re-bloqueo tras vencer el TTL | Pendientes de aprobación |
|---|---|---|---|---|---|
| 3-oct | 503 | 17 | 17 | 0 | 486 |
| 4-oct | 538 | 276 | 271 | 5 | 262 |
| 5-oct | 659 | 254 | 5 | 249 | 405 |
| 6-oct | 478 | 264 | 4 | 260 | 214 |
| 7-oct | 525 | 287 | 21 | 266 | 212 |
| 8-oct | 555 | 284 | 19 | 265 | 271 |
| 9-oct | 500 | 287 | 15 | 272 | 211 |
| 10-oct (parcial, R4) | 407 | 360 | 85 | 275 | 45 |

Hallazgo: **"bloqueo nuevo" por día no mide amenazas nuevas.** El TTL del bloqueo es de 30 minutos (`BLOCK_TTL_SECONDS=1800`, verificado en el `.env` de `.140`). Unas 260 a 275 IPs recurrentes se re-bloquean todos los días cuando vence; las IPs bloqueadas por primera vez son entre 4 y 21 por día (85 el 10-oct, ya en R4). En total, 2.029 IP-día con bloqueo: 437 primeros bloqueos y 1.592 re-bloqueos. Además, 1.838 IP-día tuvieron TTL extendido, siempre junto con un re-bloqueo el mismo día (0 IP-día solo con extensión). El 10-oct bajan las pendientes de aprobación (45 contra 211 a 486), coherente con R4. La autonomía sobre amenazas nuevas debe reportarse con la columna de primeros bloqueos; la de bloqueos ejecutados la infla con los re-bloqueos.

`c_ips_por_hora.csv` complementa los contadores de 60 min del dashboard: por hora y tier, decisiones e IPs distintas, con la infra propia aparte (solo T2/T3).

### D) Cola de aprobaciones desde el corte de R4 (9-oct 14:21:00Z)

Solo lectura: `soc-responses-*` paginado y el estado actual de `soc:approvals:*` en Redis (SCARD y SSCAN acotado; nunca SMEMBERS). No se consultó AbuseIPDB: "qué fuente falta" sale de lo que R1 registró. Umbrales de R1 en el código: AbuseIPDB corrobora con 50 o más, OTX con 1 pulso o más.

| Medida | Valor |
|---|---|
| Registros T3 pendientes de aprobación | 3.206, de **356 IPs** en 83 redes /24 |
| Pendientes en Redis al extraer | 15 |
| Resoluciones desde el corte (eventos, no IPs) | 372 de expiración y 13 aprobaciones manuales. Los rechazos se registran como `access_event` y este filtro no los cuenta: no medidos acá |
| Los 5 /24 principales | **259 de 356 IPs en cola (72,8%)** y **11 de 15 pendientes actuales (73,3%)** |
| `91.92.42.0/24` | **238 IPs en cola (66,9%), 2.738 registros (85,4%), 10 de las 15 pendientes actuales.** Sus 256 IPs hermanas fueron todas bloqueadas automáticamente alguna vez |
| `198.235.24.0/24`, `147.185.132.0/24`, `65.49.1.0/24` | 6, 6 y 5 IPs en cola; 111, 145 y 99 IPs hermanas, casi todas solo T2 (escaneo amplio de baja intensidad) |
| `45.198.224.0/24` | 4 IPs en cola, 10 hermanas (3 bloqueadas) |

**Qué fuente falta (último registro de cada IP):**

| Causa | IPs |
|---|---|
| AbuseIPDB no consultada: **presupuesto de la ventana agotado (6 de 6 en 600 s)**, con OTX corroborando | **280 (78,7%)**; 224 son de `91.92.42.0/24` (OTX entre 23 y 50 pulsos) |
| AbuseIPDB < 50 (consultada o en caché), con OTX corroborando | 33 |
| AbuseIPDB no consultada por no decisiva y OTX sin dato | 19 |
| OTX sin dato (no disponible), con AbuseIPDB corroborando | 15 |
| AbuseIPDB no consultada por no decisiva y OTX sin pulsos | 9 |

Lectura: la cola no es diversa. Casi 4 de cada 5 IPs esperan aprobación porque se agotó el presupuesto por ventana de AbuseIPDB, no porque una fuente las contradiga, y la mayoría es una sola campaña que R2 ya había bloqueado el 4-oct. Vuelven a la cola cuando vence el TTL del bloqueo (30 min) y la caché de AbuseIPDB del 4-oct ya expiró. **Es evidencia directa para la decisión de D2 de las 21:00:** la ráfaga apunta exactamente a este caso. No es una recomendación de cambiar la política dentro del período 2; el criterio de las 21:00 sigue siendo la regla de H59.

Archivos: `d_cola_por_red24.csv`, `d_cola_ips.csv`, `d_hermanas_top5.csv`.

## 4. Plan de deploy (no ejecutado; cada paso con tu OK)

**Cuándo:** el 11-oct después de verificar el reentrenamiento del IF de las 04:00 (corpus `2026-06-20 13:52`, hash `4958eb4b`), si a mediodía la revisión de `55f4b7b` está aprobada. Si no, todo el paquete el 12-oct antes de las 18:00. Es un **evento**, no un corte de régimen: no cambia ninguna decisión.

**Qué entra:** `develop` pasa de `43a62bd` a la punta de `feature/casos-ui` (fast-forward). Incluye cumplimiento (H57 a H59), explicabilidad (H59) y casos (H60). 51 archivos, +5.357 / −172.

**Diff exacto** (reproducible; no se versiona como `.patch` porque el pre-commit le quitaría los espacios finales):
- Backend contra producción: `git diff 43a62bd..feature/casos-ui -- motor/` (8 archivos: `audit_gaps.yaml`, `compliance.py`, `dashboard.py`, `explain.py`, `main.py`, `regimes.py`, `response/config.py`, `users.py`; 1.728 líneas de diff).
- Solo H60: `git diff 9a01771..feature/casos-ui -- motor/` (`dashboard.py` y `main.py`, 366 líneas).
- Frontend: `git diff 9a01771..feature/casos-ui -- frontend/`.

**Comandos, en orden:**

```bash
# 0. Mac, worktree de casos-ui
cd ~/DevProjects/motor_soc_casos_ui
git fetch origin && git log --oneline -1 origin/develop        # 43a62bd; si D2 entró (27830f2): git rebase origin/develop y repetir 1
# 1. suites
../motor_de_desiciones_para_SOC/.venv/bin/python -m pytest -q   # 860 passed esperados
(cd frontend/operativo && npx tsc -b && npm test)               # 56 passed
# 2. push (fast-forward, sin merge)
git push origin feature/casos-ui:develop
# 3. .140, UNA conexión: anotar el bundle vigente y traer el código
ssh motor140 'cd ~/tesis/repo && ls motor/static/operativo/assets/index-*.js && git status -sb && git pull --ff-only && git log --oneline -1'
# 4. .140: restart PRIMERO (lo ejecutás vos). ~15 s sin Fast Path
date '+%F %T %z'; sudo systemctl restart motor-soc; date '+%F %T %z'
# 5. comprobar el backend nuevo antes del bundle (sin SSH)
curl -s https://motor-soc-ubo.duckdns.org/health
curl -s -o /dev/null -w '%{http_code}\n' https://motor-soc-ubo.duckdns.org/api/v1/dashboard/cases/page   # 401 (existe), no 404
# 6. Mac: recién ahora el bundle (tests, build y copia atómica; deja operativo.prev). UNA conexión
scripts/deploy_operativo.sh
```

**Orden: backend primero, bundle después** (corregido por la revisión independiente). El backend nuevo es compatible hacia atrás: el bundle de `43a62bd` no llama a ningún endpoint nuevo de casos y `GET /cases` no cambió. Al revés no: con el bundle nuevo sobre el backend viejo, Casos, la traza y el CSV darían 404 hasta el restart, y Cumplimiento probablemente no calzaría con el `compliance_report` viejo.

`response-worker` y los indexadores **no** se reinician. El `.env` no cambia.

**Verificaciones (+2 min, una conexión SSH más el dominio público):**
1. `curl -s https://motor-soc-ubo.duckdns.org/health`: `status` ok y el modelo real cargado.
2. En `.140`: `ps -o lstart= -p $(systemctl show -p MainPID --value motor-soc)` posterior al restart; `git log --oneline -1` es la punta de casos-ui; `INFO stats` de Redis: `evicted_keys` sigue en 72.205.
3. En el navegador, como `aiayala` (CISO): Casos carga la lista (índice de recientes alrededor de 12.000), el detalle muestra la traza y Alertas muestra "Ya bloqueada (TTL extendido)" en algún T3. No cerrar casos de prueba: un cierre es evidencia permanente.
4. Fast Path: en la hora siguiente, decisiones por hora y tier sin salto (`extraer_metricas.py`); sin decisiones solo durante el restart. Registrar la hora real y los segundos sin Fast Path en PENDIENTES §6.

**Rollback:**
- Solo frontend: `scripts/deploy_operativo.sh --rollback` (vuelve a `operativo.prev`, sin restart). `operativo.prev` guarda una sola versión: un segundo deploy la pisa.
- Backend: en `.140`, `git switch --detach 43a62bd` y `sudo systemctl restart motor-soc`. El destino es el último commit con el formato de cadena vigente; los indexadores no cambiaron. Los casos tocados después del deploy conservan su estado (mismo esquema) y `soc:cases:worked` queda sin lector, sin efecto. Después, `git switch develop` antes del próximo `git pull` (en HEAD desacoplado, el pull falla). Volver a `43a62bd` quita el control de rol de los casos.
- Ambos: **primero el bundle y después el backend** (al revés quedaría el bundle nuevo contra el backend viejo).

## 5. Revisión independiente de `55f4b7b` (agente sin contexto de la implementación)

Leyó el diff, corrió los 38 tests del commit y escribió tests propios fuera del repo para reproducir cada problema. Confirmé por mi cuenta los puntos 2 y 11. **No apliqué ningún arreglo al backend:** cambiarían lo que vas a revisar. Mi propuesta está en la última columna.

| # | Sev. | Hallazgo (verificado salvo que se diga) | Propuesta |
|---|---|---|---|
| 1 | Alta | **Carrera worker/analista y analista/analista.** Los dos lados hacen GET, modifican y SET sin WATCH. A: el worker suma una ocurrencia a la vez que un N2 cierra, y el caso vuelve a `abierto`, pierde la nota y recupera el TTL de 7 días (la evidencia expira). B: un N1 y un N2 a la vez, y el `en_investigacion` pisa el cierre. La UI ya mostró "cerrado" | Ahora, solo en `motor-soc`: WATCH/MULTI con reintento en `update_case_state` (resuelve B y valida contra el estado real al escribir). El lado del worker (A) exige reiniciar `response-worker` y eso es un corte de régimen: después del 12-oct 11:21, ya en ROADMAP |
| 2 | Media | **El CSV convierte los campos vacíos en `'`** (`""[:1] in "=+-@"` es True). Lo confirmé | Ahora: escapar solo si el valor no está vacío y pasar None a `""` antes |
| 3 | Media | **Faltan prefijos de inyección:** `\t`, `\r`, `\n` y `＝`; con espacio o comilla al inicio, la evaluación depende de la planilla (sospecha). `host` puede venir de Vector sin validar como IP. IPv6, fechas y UUID no se alteran | Ahora: prefijar si `v[:1]` o `v.lstrip(" \"'")[:1]` está en `=+-@\t\r\n＝`, siempre después de convertir a str |
| 4 | Media | Los cierres exitosos no quedan en la cadena hash, aunque CLAUDE.md pide registrar cada acción restringida por rol; se resuelve con una línea de `log_access_event` | **Decisión tuya.** Me pediste dejarlo como limitación y no cambiarlo; el revisor argumenta que es una línea y que lo exige CLAUDE.md |
| 5 | Media | **El dashboard legado (`/dashboard`) cierra con notas fijas** ("Confirmado como amenaza real desde el panel"), que pasan el mínimo de 3 caracteres. Mitigante: `/dashboard` exige un bearer token, así que desde el navegador no carga | Ahora: pedir la nota con `prompt()` en el legado, o quitar sus botones de cierre |
| 6 | Media | **El orden de deploy era incorrecto** (bundle antes que el backend) | **Corregido en el plan (§4):** backend primero, con el rollback ajustado |
| 7 | Baja | El cursor por offset más el refresco de la página 1 genera duplicados (la UI los filtra) y casos que dejan de verse hasta cambiar de filtro | Documentar. Cursor por clave (score, id) después del 12-oct |
| 8 | Baja | SET, ZADD y ZREMRANGEBYRANK no son atómicos; con Redis caído, detalle, CSV y POST dan 500 en vez de 503 | Ahora: pipeline transaccional (va junto con el 1) y 503 explícito |
| 9 | Baja | El tope de 5.000 recorta primero los `en_investigacion` más viejos, que quedan sin TTL y fuera de todo listado | Documentar; recortar solo cerrados después del 12-oct |
| 10 | Baja | `closures.csv` lee hasta 5.000 casos en el proceso del Fast Path (estimado, no medido); "Cargar más" da 422 pasado el cursor 100.000 | Documentar; medir en el deploy |
| 11 | Baja | **Un N1 que intenta cerrar sin nota recibe 422 y el intento no queda como `action_denied_role`,** porque la nota se valida antes que el rol. Lo confirmé | Ahora: validar la nota dentro del endpoint, después del rol |
| | Info | Bien: orden de rutas, autorización sin forma de saltearla, entradas acotadas, Redis sin lecturas masivas, TTL de los casos sin cambios respecto de H57 | |

**Si das el OK a "ahora"** (1 del lado del endpoint, 2, 3, 5, 8 y 11): es un commit chico solo en `motor-soc` y en el legado, con tests de cada caso (los que el revisor marcó como faltantes) y otra pasada del revisor sobre ese commit. Eso suma unas 2 h a tu revisión antes del mediodía del 11-oct.

## 6. Capturas

En `reports/capturas_casos_ui/`. **Son con un backend simulado y datos ficticios** (IPs de documentación y las dos IPs citadas en el pedido), porque los endpoints nuevos no están en producción. Después del deploy hay que repetirlas con datos reales.

| Archivo | Muestra |
|---|---|
| `casos_lista_n2.png` | Lista de abiertos, solo IPs públicas, botón de exportación (N2) |
| `casos_agrupado_24.png` | Agrupación por /24 con IPs, ocurrencias y fuentes |
| `casos_detalle_n2.png` | Detalle: línea de tiempo, acciones, TI, evidencia por referencia, traza v1 |
| `casos_cierre_con_nota.png` | Cierre como confirmado con la nota obligatoria |
| `casos_cerrado_linea_de_tiempo.png` | Caso cerrado: abierto (sistema), investigación (N1), cierre (N2) con nota |
| `casos_detalle_n1.png` | N1: solo "Pasar a investigación"; la traza y los eslabones requieren N2 |
| `alertas_n2.png` | Contadores en "decisiones" y acciones derivadas de R2 |
| `alertas_detalle_t3_ttl_extendido.png` | T3 ya bloqueada: modelo con "sin dato" explícito, traza y eslabones |

## 7. Ambigüedades y lectura conservadora

1. **"Respetá los permisos del backend":** no había ninguno. Los agregué en el endpoint existente (tu OK de la decisión 1) y la UI solo refleja lo que el servidor aplica.
2. **Transiciones:** N2 y CISO pueden cerrar desde abierto o desde en investigación. Los cerrados son finales; no hay reapertura (no se pidió). Volver a "abierto" no es un destino válido.
3. **Filtro por tier:** omitido. Todos los casos son T2 y derivarlo del classtype no aporta: el classtype casi siempre llega vacío (H50).
4. **"Pendiente de aprobación N1":** el nivel sale del registro (`block.approval_level`); si falta, la UI dice "nivel sin dato" en lugar de suponer.
5. **Hashes de modelo, `policy_version` y `regime_id`:** no existen por decisión. Muestro "sin dato" en vez de calcularlos en el frontend.
6. **Guiones largos:** algunos textos del backend los traen (por ejemplo, el motivo de R2 que separa "ya bloqueada" de "TTL extendido"). La UI los muestra con coma; el dato guardado no cambia.
7. **Exportación:** cuenta como acceso y queda en la cadena de accesos (`cases_closures_exported`), igual que `audit_trace_viewed`. Los cambios de estado en sí siguen fuera de la cadena, como pediste.
8. **Infra propia:** uso la misma definición que la safelist de R2 (toda IP privada, loopback o link-local, más `RESPONSE_SAFELIST_EXTRA`), aplicada por `src_ip` y no por la acción, para que valga también antes del régimen R2 (H54).
9. **Análisis sobre un período abierto:** la corrida de hoy es preliminar. La final va después del 12-oct 11:21 (fin del período 2) y otra al corte del 14-oct 21:00, con el mismo comando y `--hasta`.
