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
- **TTL del bloqueo y re-bloqueos.** Con 30 minutos, unas 270 IPs recurrentes se re-bloquean cada día (análisis C de H60). Evaluar TTL escalonado por reincidencia. Origen: H60.
- **Falsos positivos sobre infra propia.** El 13,7% de los T2/T3 es tráfico propio (Redis, OpenSearch, API de Wazuh) con ml_score entre 0,6 y 0,8. La safelist evita la acción, pero no la decisión: evaluar excluirlo antes del modelo o reentrenar con ese tráfico como benigno. Origen: H60.
- **Rate-limiting y cuarentena por VLAN** (switch SG350 con Netmiko). Origen: especificación ampliada, sección 9.
- **T2 con dos o más fuentes corroborando.** IPs con AbuseIPDB alto (caché) y OTX con pulsos quedan en T2 con "Alertar y crear caso", porque el tier solo depende del score del Fast Path. Evaluar que la corroboración de R1 pueda subir un T2 a la regla de bloqueo de T3. Estimación preliminar (análisis B de `reports/metricas/2026-10-10/analisis_h60.md`, 8 al 10-oct): 763 IPs, 443 serían bloqueos nuevos y 320 TTL extendidos; en R4 la brecha casi desaparece, porque esas IPs ya se bloquean cuando llegan a T3. La campaña `91.92.42.0/24` (256 IPs a 443) sugiere además bloqueo por /24. No se cambia en esta tesis: cambiaría la política de decisión dentro del período 2. Origen: H60.

## Gestión de casos

- **Cambios de estado y notas dentro de la cadena hash.** Hoy quedan en el caso (actor, hora, nota) pero no en `soc-responses-*`; el intento denegado por rol sí queda. Emitir un evento `case_state_changed` al stream de auditoría. Origen: H60.
- **Deduplicación durante la investigación.** Un caso en investigación deja de recibir ocurrencias: las repeticiones de la IP abren un caso nuevo. Reutilizar el caso mientras no esté cerrado. Origen: H60.
- **Carrera entre el worker y un analista.** El worker reescribe el caso al sumar una ocurrencia (lectura y escritura sin transacción); si coincide en el mismo instante con un cambio de estado, el cambio del analista puede perderse. Lua o WATCH/MULTI en `response/cases.py`. Origen: H60.
- **`soc:cases:index` y `vigilante/cases.py:list_cases`.** El SET histórico tiene ~700.000 ids y crece ~12.000/día solo por compatibilidad; `vigilante/cases.py:list_cases` todavía hace `SMEMBERS` sobre él (sin llamadores hoy). Retirar ambos. Origen: H60, patrón de H54.
- **Más de 5.000 casos trabajados.** `soc:cases:worked` recorta por rango: un cierre más antiguo sale del listado y del CSV (el caso sigue en Redis, sin TTL). Persistir los cierres en OpenSearch. Origen: H60.

## Datos y modelo

- **Trazabilidad del modelo por decisión.** `soc-decisions-*` guarda `model_version` pero no el hash de LightGBM ni del Isolation Forest, ni `policy_version`, ni `regime_id`, ni `src_ip`: el detalle muestra "sin dato" y las métricas por IP o de infra propia sobre T0/T1 no son medibles. Origen: H60.
- **Etiquetador de `.139` sin scores de AbuseIPDB desde agosto**, y flujos de honeypot etiquetados como benignos en el corpus. Origen: H55 y H56.
- **Isolation Forest de comportamiento de host.** Origen: `CLAUDE.md`, prohibición 13.

## Operación

- **`campana_automatica.sh`:** nmap `-sS` sin root y hydra sin diccionario desde junio. Repararlo o eliminarlo. Origen: H56.
- **ISM** para `suricata-alerts-*`, `security-auditlog-*` y el índice legado `soc-decisions`; **logrotate** para `/var/log/suricata` y `worker.log`. Origen: H57.
- **`maxmemory` de Redis** (`CONFIG` deshabilitado: `redis.conf` con sudo) y política de desalojo. Origen: H57.
