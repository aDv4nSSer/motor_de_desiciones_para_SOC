# Análisis H60 (solo lectura): infra propia, T2 corroboradas y autonomía

Extraído 2026-10-10T16:30:54+00:00 UTC, ventana desde 2026-10-03T00:00:00Z hasta la extracción. Días UTC. Reproducir: ver el docstring de scripts/metrics/analisis_h60.py.

Exclusiones: hueco de H54 (8-oct 03:32:41 a 03:32:45Z, a lo sumo 5 registros) y restart del 9-oct (14:27:00,8Z a 14:27:14,6Z, 13,8 s sin decisiones). La ventana H25 (18-ago a 04-sep) queda fuera del rango.

## A) Infra propia

- Decisiones T2/T3 de infra propia: 145409 de 1061696 T2/T3 (13.7%), 5 IPs.
- Tasa de falsos positivos del modelo sobre ese conjunto: toda decisión T2/T3 de infra propia es un falso positivo del umbral de T2 (tráfico propio conocido como benigno). Las decisiones T0/T1 de infra no tienen src_ip en soc-decisions-*, así que la tasa sobre todo el tráfico propio no es medible con estos índices.
- Conteos, IPs y pares origen y puerto: exactos, sobre todas las respuestas. Percentiles e histograma de ml_score y anomaly_score: muestra de 1 de cada 10 respuestas (paso fijo en orden de tiempo), 13439 decisiones unidas por trace_id.
- Salvedad: la infra propia es benigno conocido de un tipo muy particular (API de Wazuh, gestión, bastion); no representa tráfico externo benigno y no sirve para estimar la tasa de falsos positivos sobre Internet.

- `a_infra_por_dia.csv`: 16 filas
- `a_infra_histograma.csv`: 20 filas
- `a_infra_pares.csv`: 30 filas

## B) T2 con >= 2 fuentes

- T2 con >= 2 fuentes corroborando: 75325 decisiones, 763 IPs, 262 redes /24, 61 /24 con 2 o más IPs (campaña candidata).
- Si hubieran sido T3 (regla R2-CORROBORADO, mínimo 2 fuentes): 443 IPs serían bloqueo automático nuevo y 320 ya estaban bloqueadas (TTL extendido). Se excluyen las IPs con todos sus eventos más viejos que 3600 s (R2 no actúa sobre eventos antiguos).
- Cobertura: corroboration_count es buscable en soc-responses-* desde H52 (fe58bdb, 7-oct); antes no hay datos para B.
- Es análisis de sensibilidad sobre lo registrado, no un cambio de política: la regla de tier no se toca en esta tesis. Cota superior: supone que la corroboración observada en T2 (incluida la caché) se habría repetido en T3.

- `b_t2_corroboradas_por_dia.csv`: 3 filas
- `b_t2_corroboradas_ips.csv`: 763 filas
- `b_t2_corroboradas_redes24.csv`: 262 filas

## C) Autonomía

- Autonomía (IPs distintas por día UTC, sin infra propia): 2029 IP-día con al menos un bloqueo ejecutado; de ellas, 437 son la primera vez que la IP se bloquea en la ventana y 1592 son re-bloqueos de IPs ya bloqueadas otro día, después de vencer el TTL del bloqueo. 1838 IP-día tuvieron además TTL extendido y 0 solo TTL extendido.
- Lectura: la IP que sigue atacando se re-bloquea cuando vence el TTL, así que los bloqueos ejecutados por día no miden IPs nuevas. Para autonomía sobre amenazas nuevas usar ips_primer_bloqueo_en_ventana; el primer día de la ventana incluye IPs que ya venían bloqueadas de antes del 3-oct.
- ips_por_hora complementa los contadores de 60 min del dashboard (que cuentan decisiones): por hora y tier, decisiones e IPs distintas, con la infra propia aparte. Solo T2/T3: T0/T1 no tienen src_ip registrado.
- Cardinalidades con precision_threshold 40000 (exactas en estos volúmenes por IP y hora).

- `c_autonomia_por_dia.csv`: 8 filas
- `c_ips_por_hora.csv`: 429 filas
