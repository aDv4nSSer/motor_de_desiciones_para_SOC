# Roadmap 2027 (trabajo futuro de R-SOAR)

Lo que quedó fuera del congelamiento de código del 12-oct-2026, con su diseño o su punto de partida. Cada ítem remite al hallazgo de `docs/BITACORA_TECNICA.md` que lo origina.

## Cumplimiento y reportes (Ley 21.663, DS 295/2024)

- **Reloj de plazos del Art. 9.** El "conocimiento" del incidente lo fija una persona, con el primer T3 corroborado como aproximación. Contadores:
  - 3 h y 72 h desde el conocimiento (DS 295 arts. 9 y 10);
  - 24 h y 7 días solo si la organización es OIV (`organizacion_es_oiv`);
  - 15 días corridos desde la alerta enviada (Art. 9 c; DS 295 art. 12), con informes parciales cada 15 días (art. 13).
  - Origen: H57.
- **Registro de incidentes candidatos** (estado, responsable, marcas de tiempo) y **exportación** CSV, JSON y HTML con hora y hash. Origen: H57.
- **Reporte en PDF y envío a la ANCI.** R-SOAR no envía nada a la ANCI; el reporte lo hace la organización. Origen: H43 y H57.

## Respuesta y política de TI

- **D2, bucket diario de AbuseIPDB con ráfaga.** Rama `feature/d2-bucket-rafaga` (`a2afcac`): Lua atómico, arranque conservador, techo de 864/día con reserva de cola. Origen: H56.
- **Cola de aprobaciones sin operador:** 31.559 de 31.560 aprobaciones expiraron. Origen: H52.
- **Cola de aprobaciones por presupuesto de AbuseIPDB.** Desde R4, el 78,7% de las IPs en cola espera porque se agotó el presupuesto por ventana (6/6 en 600 s) con OTX ya corroborando, y el 66,9% es una sola campaña (`91.92.42.0/24`) ya bloqueada el 4-oct que vuelve al vencer el TTL. Evaluar D2, caché de AbuseIPDB por /24 para campañas confirmadas y aprobación agrupada por /24. Origen: H60, análisis D.
- **TTL del bloqueo y re-bloqueos.** Con 30 minutos, unas 270 IPs recurrentes se re-bloquean cada día (análisis C de H60). Evaluar TTL escalonado por reincidencia. Origen: H60.
- **Falsos positivos sobre infra propia.** El 13,7% de los T2/T3 es tráfico propio (Redis, OpenSearch, API de Wazuh) con ml_score entre 0,6 y 0,8. La safelist evita la acción, pero no la decisión: evaluar excluirlo antes del modelo o reentrenar con ese tráfico como benigno. Origen: H60.
- **Rate-limiting y cuarentena por VLAN** (switch SG350 con Netmiko). Origen: especificación ampliada, sección 9.
- **T2 con dos o más fuentes corroborando.** IPs con AbuseIPDB alto (caché) y OTX con pulsos quedan en T2 con "Alertar y crear caso", porque el tier solo depende del score del Fast Path. Evaluar que la corroboración de R1 pueda subir un T2 a la regla de bloqueo de T3. Estimación preliminar (análisis B de `reports/metricas/2026-10-10/analisis_h60.md`, 8 al 10-oct): 763 IPs, 443 serían bloqueos nuevos y 320 TTL extendidos; en R4 la brecha casi desaparece, porque esas IPs ya se bloquean cuando llegan a T3. La campaña `91.92.42.0/24` (256 IPs a 443) sugiere además bloqueo por /24. No se cambia en esta tesis: cambiaría la política de decisión dentro del período 2. Origen: H60.

## Gestión de casos

- **Notas de casos en la cadena hash.** Los cambios de estado ya emiten `case_state_changed` (actor, caso, de, a y sha256 de la nota, sin el texto; fa273ad). El texto de la nota queda solo en el caso; si la auditoría debe conservarlo, persistirlo cifrado o en un índice propio. Origen: H60.
- **Deduplicación durante la investigación.** Un caso en investigación deja de recibir ocurrencias: las repeticiones de la IP abren un caso nuevo. Reutilizar el caso mientras no esté cerrado. Origen: H60.
- **Carrera del lado del worker.** El endpoint ya usa WATCH/MULTI (fa273ad), pero `response/cases.py:_add_occurrence` hace GET y SET sin WATCH: si el worker leyó antes del cambio de estado y escribe después, pisa el cierre (el caso vuelve a `abierto`, pierde la nota y recupera el TTL de 7 días). Ventana de milisegundos, verificada con un test que intercala las operaciones. Arreglarlo exige reiniciar `response-worker` (corte de régimen), por eso va después del período 2: Lua que escriba solo si `state` sigue `abierto`. Origen: H60, revisión independiente.
- **`soc:cases:index` y `vigilante/cases.py:list_cases`.** El SET histórico tiene ~700.000 ids y crece ~12.000/día solo por compatibilidad; `vigilante/cases.py:list_cases` todavía hace `SMEMBERS` sobre él (sin llamadores hoy). Retirar ambos. Origen: H60, patrón de H54.
- **Casos en `soc-responses-*`.** El indexador no extrae `detail.case_id` de los eventos `access` (`case_state_changed`): la historia de un caso no es consultable por caso. Extraerlo en `build_content`. Menores de la segunda revisión de H60: `csv_safe` con blancos Unicode, JSON corrupto en un caso (500 y 400), notas de ancho cero, WATCH probado contra Redis real. Origen: H60.
- **Más de 5.000 casos trabajados.** `soc:cases:worked` recorta por rango: un cierre más antiguo sale del listado y del CSV (el caso sigue en Redis, sin TTL). Persistir los cierres en OpenSearch. Origen: H60.

## Datos y modelo

- **Trazabilidad del modelo por decisión.** `soc-decisions-*` guarda `model_version` pero no el hash de LightGBM ni del Isolation Forest, ni `policy_version`, ni `regime_id`, ni `src_ip`: el detalle muestra "sin dato" y las métricas por IP o de infra propia sobre T0/T1 no son medibles. Origen: H60.
- **Etiquetador de `.139` sin scores de AbuseIPDB desde agosto**, y flujos de honeypot etiquetados como benignos en el corpus. Origen: H55 y H56.
- **Isolation Forest de comportamiento de host.** Origen: `CLAUDE.md`, prohibición 13.

## Operación

- **`campana_automatica.sh`:** nmap `-sS` sin root y hydra sin diccionario desde junio. Repararlo o eliminarlo. Origen: H56.
- **ISM** para `suricata-alerts-*`, `security-auditlog-*` y el índice legado `soc-decisions`; **logrotate** para `/var/log/suricata` y `worker.log`. Origen: H57.
- **`maxmemory` de Redis** (`CONFIG` deshabilitado: `redis.conf` con sudo) y política de desalojo. Origen: H57.
