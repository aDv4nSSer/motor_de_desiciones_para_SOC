# Backlog — infraestructura (no dashboard)

Hallazgos operativos detectados durante trabajo de otro alcance, documentados
para no perderlos pero sin actuar sobre ellos hasta que se pidan explícitamente.

## `eve.json` de Suricata (.139) sin rotar — 14.6 GB y creciendo

Detectado 2026-08-12 durante la investigación de detección L7/DNS experimental.

`/var/log/suricata/eve.json` pesa 14.6 GB (`ls -la /var/log/suricata/`) y no
tiene entrada en `/etc/logrotate.d/` — no hay `logrotate.d/suricata` en el
host. El archivo crece sin límite desde mayo 2026.

**Riesgo:** agotamiento de disco en `.139` sin aviso previo (no hay alerta de
espacio configurada que se haya confirmado en esta sesión). También hace más
lenta cualquier lectura secuencial completa del archivo (mitigado para
`vigilante/shadow_detect.py` porque lee de forma incremental por offset, nunca
el archivo completo).

**Propuesta (no implementada):** agregar `/etc/logrotate.d/suricata` con
rotación diaria + compresión + retención acotada (ej. 14 días), y usar
`copytruncate` o `postrotate` con `kill -USR2` a Suricata (soporta reapertura
de log sin reiniciar el proceso, ver docs de Suricata) para no perder eventos
durante el corte.

**Prioridad:** media — no es urgente hoy (hay margen de disco visto en la
sesión), pero crece sin freno y afecta a cualquier consumidor futuro de
`eve.json`, no solo a `shadow_detect.py`. No tocar sin confirmar espacio libre
real en el host primero.

## `soc-events-*` documentado en `CLAUDE.md` pero nunca implementado

Detectado 2026-08-13 diseñando el panel "Detección Experimental" del
dashboard (Parte C), al buscar dónde viven las alertas L7 de Suricata en
OpenSearch.

La tabla de índices OpenSearch en `CLAUDE.md` lista `soc-events-*` con
propósito "Flows Suricata", pero no hay ninguna implementación real detrás:
`grep -rn "soc-events"` en todo el repo (código, configs `.toml`/`.yaml`) no
encuentra nada fuera de esa mención en la documentación. El pipeline de
Vector en producción (`infra/vector/vector.production.toml:31-33`) descarta
explícitamente (`abort`) cualquier evento que no sea `event_type == "flow"`
y no tiene ningún sink hacia OpenSearch — solo hacia `motor-soc:8000/decide`
y a archivos JSONL locales. Los flows nunca llegaron a `soc-events-*` por
ningún camino que exista en el código.

**No es un bug operativo** — nada se rompió, es una inconsistencia entre lo
documentado y lo implementado. Pero puede inducir a error a futuro (a
cualquiera, incluyendo asistentes que lean `CLAUDE.md`, asumiendo que ese
índice existe y tiene datos).

**Propuesta (no implementada):** en la próxima limpieza general de
`CLAUDE.md`, o (a) quitar `soc-events-*` de la tabla de índices si no está
en el roadmap real, o (b) si sigue siendo parte del plan, marcarla
explícitamente como "planeado, no implementado" hasta que exista el sink
real hacia OpenSearch.

**Prioridad:** baja — solo documentación, sin impacto funcional. Corregir
junto con otras inconsistencias que se encuentren en la misma limpieza.

## Falta puerto espejo (SPAN/mirror) hacia `eno2` de `.139` — punto ciego de Suricata

Detectado 2026-08-13 verificando end-to-end la Parte A de detección L7
experimental. Detalle completo del mecanismo, evidencia y reproducción en
`docs/BITACORA_TECNICA.md` → **H16**.

Resumen: `.138` tiene dos interfaces con rutas independientes — `eno1`
(`200.54.12.138/29`, uplink directo al ISP) y `eno2` (`192.168.153.41/24`,
LAN interna). `eno2` de `.139` (la interfaz que Suricata captura) está en el
mismo `/29` que `eno1` de `.138`, pero en una red conmutada eso no implica
visibilidad — sin un puerto espejo explícito en el switch físico, Suricata
solo ve tráfico donde `.139` mismo es origen o destino. Tráfico dirigido
directo a la IP pública de `.138` (el camino más realista de un atacante)
es invisible para Suricata hoy.

**Riesgo:** cualquier detección L7 o de futuros sensores de red pasivos en
`.139` tiene este mismo punto ciego para tráfico que entra directo por el
uplink ISP de otro host del laboratorio, no solo `.138`.

**Propuesta concreta (no implementada, trabajo post-defensa):** configurar
un puerto espejo (SPAN/mirror) en el switch físico que conecta el segmento
`200.54.12.136/29`, replicando hacia el puerto de `eno2` de `.139` todo el
tráfico entrante/saliente del puerto de `eno1` de `.138` (y, si el switch lo
permite, de los demás hosts del mismo segmento). Alternativas si el switch
no soporta SPAN: TAP de red físico inline en el uplink de `.138`, o mover a
un modelo donde `.138` reenvíe una copia de su tráfico HTTP a `.139` a nivel
de aplicación (menos fiel que un mirror real, pero no requiere acceso físico
al switch).

**Prioridad:** media para la tesis (afecta la validez de la Parte A como
prueba de concepto), pero explícitamente **fuera de alcance esta semana** —
requiere acceso físico a un switch que no es del proyecto, y no hay tiempo
de validarlo con seguridad antes de la próxima sesión. No intentar sin
acceso físico confirmado y ventana de mantenimiento (tocar el switch puede
afectar tráfico real de producción de `.138`/`.139`/`.140`).
