# Análisis H60 (solo lectura): infra propia, T2 corroboradas y autonomía

Extraído 2026-10-10T16:50:31+00:00 UTC, ventana desde 2026-10-03T00:00:00Z hasta la extracción. Días UTC. Reproducir: ver el docstring de scripts/metrics/analisis_h60.py.

Exclusiones: hueco de H54 (8-oct 03:32:41 a 03:32:45Z, a lo sumo 5 registros) y restart del 9-oct (14:27:00,8Z a 14:27:14,6Z, 13,8 s sin decisiones). La ventana H25 (18-ago a 04-sep) queda fuera del rango.

## A) Infra propia

- NO ES UNA TASA DE FALSOS POSITIVOS SOBRE TRÁFICO EXTERNO: mide cuánto tráfico propio, benigno y conocido, el modelo lleva a T2/T3.
- Flujos distintos (origen, destino, puerto): 555; los 5 principales concentran 73.8% de las decisiones de infra. Una decisión por flujo repetido no es un evento independiente: la vista por flujo es la unidad comparable.
- Decisiones T2/T3 de infra propia: 145591 de 1063428 T2/T3 (13.69%), 5 IPs.
- Tasa de falsos positivos del modelo sobre ese conjunto: toda decisión T2/T3 de infra propia es un falso positivo del umbral de T2 (tráfico propio conocido como benigno). Las decisiones T0/T1 de infra no tienen src_ip en soc-decisions-*, así que la tasa sobre todo el tráfico propio no es medible con estos índices.
- Conteos, IPs y pares origen y puerto: exactos, sobre todas las respuestas. Percentiles e histograma de ml_score y anomaly_score: muestra de 1 de cada 10 respuestas (paso fijo en orden de tiempo), 13458 decisiones unidas por trace_id.
- Salvedad: la infra propia es benigno conocido de un tipo muy particular (API de Wazuh, gestión, bastion); no representa tráfico externo benigno y no sirve para estimar la tasa de falsos positivos sobre Internet.

- `a_infra_por_dia.csv`: 16 filas
- `a_infra_histograma.csv`: 20 filas
- `a_infra_pares.csv`: 30 filas
- `a_infra_flujos.csv`: 555 filas
- `a_infra_flujos_por_dia.csv`: 16 filas

## B) T2 con >= 2 fuentes

- T2 con >= 2 fuentes corroborando: 75436 decisiones, 764 IPs, 262 redes /24, 61 /24 con 2 o más IPs (campaña candidata).
- Si hubieran sido T3 (regla R2-CORROBORADO, mínimo 2 fuentes): 443 IPs serían bloqueo automático nuevo y 321 ya estaban bloqueadas (TTL extendido). Se excluyen las IPs con todos sus eventos más viejos que 3600 s (R2 no actúa sobre eventos antiguos).
- Cobertura: corroboration_count es buscable en soc-responses-* desde H52 (fe58bdb, 7-oct); antes no hay datos para B.
- Es análisis de sensibilidad sobre lo registrado, no un cambio de política: la regla de tier no se toca en esta tesis. Cota superior: supone que la corroboración observada en T2 (incluida la caché) se habría repetido en T3.

- `b_t2_corroboradas_por_dia.csv`: 3 filas
- `b_t2_corroboradas_ips.csv`: 764 filas
- `b_t2_corroboradas_redes24.csv`: 262 filas

## C) Autonomía

- Autonomía (IPs distintas por día UTC, sin infra propia): 2032 IP-día con al menos un bloqueo ejecutado; de ellas, 440 son la primera vez que la IP se bloquea en la ventana y 1592 son re-bloqueos de IPs ya bloqueadas otro día, después de vencer el TTL del bloqueo. 1838 IP-día tuvieron además TTL extendido y 0 solo TTL extendido.
- Lectura: la IP que sigue atacando se re-bloquea cuando vence el TTL, así que los bloqueos ejecutados por día no miden IPs nuevas. Para autonomía sobre amenazas nuevas usar ips_primer_bloqueo_en_ventana; el primer día de la ventana incluye IPs que ya venían bloqueadas de antes del 3-oct.
- ips_por_hora complementa los contadores de 60 min del dashboard (que cuentan decisiones): por hora y tier, decisiones e IPs distintas, con la infra propia aparte. Solo T2/T3: T0/T1 no tienen src_ip registrado.
- Cardinalidades con precision_threshold 40000 (exactas en estos volúmenes por IP y hora).

- `c_autonomia_por_dia.csv`: 8 filas
- `c_ips_por_hora.csv`: 429 filas

## D) Cola de aprobaciones desde R4

- Desde el corte de R4 (2026-10-09T14:21:00Z): 3206 registros T3 pendientes de aprobación, 356 IPs, 83 redes /24. Pendientes en Redis al extraer: 15.
- Los 5 /24 principales concentran 259 de 356 IPs en cola (72.8%) y 11 de 15 pendientes actuales (73.3%): 91.92.42.0/24 (238), 198.235.24.0/24 (6), 147.185.132.0/24 (6), 65.49.1.0/24 (5), 45.198.224.0/24 (4).
- Fuente que falta, por IP (último registro): AbuseIPDB no consultada (presupuesto de la ventana agotado): 280; AbuseIPDB < 50: 33; AbuseIPDB no consultada (no decisiva: OTX no corrobora) y OTX sin dato (no disponible): 19; OTX sin dato (no disponible): 15; AbuseIPDB no consultada (no decisiva: OTX no corrobora) y OTX sin pulsos: 9.
- IPs hermanas: otras IPs del mismo /24 con T2 o T3 desde el corte, con su desenlace (autobloqueo, TTL extendido, solo T2). Sin consultar AbuseIPDB: lo que se ve es lo que R1 registró.

- `d_cola_por_red24.csv`: 83 filas
- `d_cola_ips.csv`: 356 filas
- `d_hermanas_top5.csv`: 621 filas

Salidas CSV archivadas fuera de git en `~/tesis_archivo/metricas_h60/h60_2026-10-10T165031`; hashes en `manifiesto_h60.md`.
