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
- **Rate-limiting y cuarentena por VLAN** (switch SG350 con Netmiko). Origen: especificación ampliada, sección 9.

## Datos y modelo

- **Etiquetador de `.139` sin scores de AbuseIPDB desde agosto**, y flujos de honeypot etiquetados como benignos en el corpus. Origen: H55 y H56.
- **Isolation Forest de comportamiento de host.** Origen: `CLAUDE.md`, prohibición 13.

## Operación

- **`campana_automatica.sh`:** nmap `-sS` sin root y hydra sin diccionario desde junio. Repararlo o eliminarlo. Origen: H56.
- **ISM** para `suricata-alerts-*`, `security-auditlog-*` y el índice legado `soc-decisions`; **logrotate** para `/var/log/suricata` y `worker.log`. Origen: H57.
- **`maxmemory` de Redis** (`CONFIG` deshabilitado: `redis.conf` con sudo) y política de desalojo. Origen: H57.
