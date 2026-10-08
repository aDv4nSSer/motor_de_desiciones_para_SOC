"""
constants.py — Constantes compartidas entre el Fast Path (main.py) y la capa
de respuesta (response/), para no duplicarlas ni importar main.py (que carga
FastAPI y el modelo) desde el worker.

Valores operacionales ajustables por entorno van en response/config.py
(Settings); acá solo lo que es parte del diseño y no se configura por .env.
"""
from __future__ import annotations

# ── Override a T3 por classtype de Suricata (nombre corto) ──────────────────
# Antes vivía en main.py. Lo usan el Fast Path (override de tier cuando llega
# el header X-Suricata-Classtype) y el grupo `signature` del score de
# corroboración (classtype correlacionado desde suricata-alerts-*, H53).
T3_CLASSTYPES: frozenset[str] = frozenset({
    "trojan-activity", "shellcode-detect", "web-application-attack",
    "attempted-admin", "attempted-user", "successful-admin", "policy-violation",
})

# ── Correlación flow -> alerta Suricata (grupo `signature`, H53) ────────────
# Las alertas las indexa Vector directo en OpenSearch (.140), no Wazuh:
# soc-alerts-* no existe (verificado 2026-10-07).
SURICATA_ALERTS_INDEX_PATTERN = "suricata-alerts-*"
# Ventana asimétrica alrededor del momento en que el flow llegó al motor
# (task.ts). Suricata emite el registro de flow al CERRAR el flujo, después
# de la alerta: medido en .140 (2026-10-07, n=6 matches sobre 100 T2+), la
# alerta precede al flow entre 36 y 68 s. Una ventana simétrica de ±30 s no
# encontraba ninguna. 300 s hacia atrás cubre flujos de varios minutos con
# margen; 30 s hacia adelante cubre desfasajes de reloj/indexado.
ALERT_CORRELATION_LOOKBACK_SECONDS = 300
ALERT_CORRELATION_LOOKAHEAD_SECONDS = 30
# Timeouts cortos: corre en el worker (Enrichment Path), pero el worker ya
# va justo de capacidad (H38) -- un OpenSearch lento no puede frenarlo.
ALERT_LOOKUP_CONNECT_TIMEOUT_SECONDS = 1.0
ALERT_LOOKUP_READ_TIMEOUT_SECONDS = 1.5
# Tras una falla, no se reintenta el lookup durante este tiempo (todas las
# tareas quedan "unavailable" sin esperar el timeout cada una).
ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS = 60

# ── Acumulador de recidivismo por entidad (grupo `context`, H53) ────────────
# risk:{entity_type}:{entity_id} -- sorted set, miembro = inicio del bucket
# horario (epoch), score = el mismo epoch. Cuenta HORAS distintas con un
# incidente T2+, no eventos: un scanner genera cientos de flows por hora
# (p90 = 162 eventos T2+/IP/día medido en .140) y contar eventos saturaría
# el grupo con una sola ráfaga.
RISK_KEY_PREFIX = "risk:"
RECIDIVISM_BUCKET_SECONDS = 3600
RECIDIVISM_WINDOW_SECONDS = 30 * 86400
# Tope de miembros por clave: el score satura mucho antes
# (corr_context_recidivism_saturation) y Redis en .140 corre con
# maxmemory 1 GB + allkeys-lru (805 MB usados, 2026-10-07).
RECIDIVISM_MAX_MEMBERS = 64

# ── Reparto de la cuota diaria de AbuseIPDB (H52, token bucket de security.md) ─
# La cuota (ResponseSettings.abuseipdb_daily_quota, 1.000/día en el plan
# gratuito) se agotaba ~50 min después de cada reset de las 00:00 UTC: 157
# consultas en los primeros 8 min del 2026-10-08. Se reparte en ventanas fijas
# `ti:rate:abuseipdb:{inicio de ventana}`: presupuesto por ventana =
# floor(cuota * ventana / 86400). Con 1.000/día y 600 s: 6 por ventana
# (~0,6/min, 864/día, margen de 136 contra el 429). Ventana de 10 min y no de
# 1 min porque la tasa (~0,69/min) es menor a 1 token por minuto.
SECONDS_PER_DAY = 86400
ABUSEIPDB_RATE_WINDOW_SECONDS = 600
ABUSEIPDB_RATE_KEY_PREFIX = "ti:rate:abuseipdb:"
# H55: el bucket solo cuenta lo que ESTE proceso gastó; la cuota real vive en
# AbuseIPDB (headers X-RateLimit-*). Último estado visto, para ajustar el ritmo
# a lo que de verdad queda hasta el reset de las 00:00 UTC.
ABUSEIPDB_QUOTA_GAUGE_KEY = "ti:quota:abuseipdb:gauge"
# Un solo worker consulta con esta key: entre dos respuestas seguidas el
# remaining baja ~1 por consulta propia. Una caída mayor a este umbral es
# consumo de otro cliente de la misma cuenta (p. ej. un cron de etiquetado).
ABUSEIPDB_EXTERNAL_DROP_WARN = 5
# Fracción del presupuesto de cada ventana que pueden usar las consultas que
# NO pueden cambiar la decisión de R2 (OTX no corrobora: AbuseIPDB llevaría
# count como máximo a 1). El resto queda reservado para las decisivas (OTX
# corrobora: AbuseIPDB puede llevar count de 1 a 2 y habilitar el bloqueo).
ABUSEIPDB_NON_DECISIVE_SHARE = 0.5
