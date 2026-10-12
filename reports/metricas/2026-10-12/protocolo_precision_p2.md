# Protocolo: precisión del auto-bloqueo en el período 2

Estado: **rúbrica y reglas para OK de Antonio; la ficha no se entrega para etiquetar hasta ese OK.** Extraído 2026-10-12T16:42:52.370228+00:00 UTC. Este documento no contiene listas de IPs (el repo es público): ficha, clave y salida cruda están en `~/tesis_archivo/precision_p2/20261012T164252/`.

## 1. Pregunta y alcance

¿Qué fracción de las IPs que R2 bloqueó **automáticamente** en el período 2 fue un bloqueo justificado? Se mide con etiquetado humano ciego sobre una muestra aleatoria de IPs; no mide sensibilidad (no se sabe cuánto malicioso quedó sin bloquear) ni la precisión del tier. Política del ciclo (decisión de Antonio, 8-oct, H56): bloquear un escáner de investigación **no** cuenta como falso positivo; por eso se reportan siempre dos cifras, la estricta y la ampliada.

## 2. Marco muestral

- **Ventana:** 2026-10-09T14:21:00Z a 2026-10-12T14:21:00Z (9-oct 11:21 a 12-oct 11:21 -03).
- **Unidad:** IP distinta con al menos un bloqueo automático ejecutado (`soc-responses-*`, `event_type = response`, `block_action = block`, `block_enforced = true`). Por IP se usa su **primer** bloqueo automático dentro de la ventana.
- **Exclusiones**, en este orden: safelist de 13 IPs, RFC1918, otras direcciones no globales, e IPs con cualquier aprobación manual (`manual_approval` con `approved_by`) en la ventana.
- **Resultado:** 579 IPs con bloqueo automático; excluidas por safelist 0, por RFC1918 0, por otra no global 0, por aprobación manual 37 (de 65 IPs con aprobación manual en la ventana, las que además tenían un bloqueo automático). **N del marco = 542** (≥ 100, cumple). Que safelist y RFC1918 den 0 es esperable: R2 no bloquea infra propia (se verifica, no se asume).

## 3. Muestra

Aleatoria simple de 100 IPs, sin reemplazo, **semilla 20261012**. Algoritmo: `random.Random(semilla).sample(marco, 100)` con el marco ordenado por dirección IP numérica; el orden de salida es el orden aleatorio de la muestra. Se calculó en `.140` (Python 3.14.4) y se reprodujo en el Mac (Python 3.13) con el mismo resultado; `construir_ficha.py` aborta si no coincide. Los ids de la ficha son opacos (`random.Random(semilla + 1)`), no derivan de la IP ni del orden.

## 4. Fuentes del comportamiento por IP

- **Puertos, flujos, primera y última vista:** `soc-responses-*` (decisiones T2/T3 con `src_ip`, desde 2026-10-03T00:00Z hasta la extracción). El puerto destino sale de `_source.payload.dst_port`, que se lee con un scroll de 89610 documentos (los campos `payload.*` no están indexados, así que no se agregan en el servidor). Se eligió porque da el comportamiento de las 100 IPs en una sola lectura; la alternativa (`soc-decisions-*`) no tiene `src_ip`.
- **Firmas y categorías de Suricata:** `suricata-alerts-*` (74 índices), agregación por `src_ip` con las 5 firmas y 5 categorías más frecuentes por IP.
- **DNS inverso, FCrDNS, ASN, organización y país:** resueltos desde el Mac con `dig` y el whois masivo de Team Cymru (nada se consulta desde producción).

## 5. Rúbrica (cuatro etiquetas)

Todo se verifica con las columnas de la ficha. **No se consultan** AbuseIPDB, OTX, CrowdSec ni ninguna reputación (circularidad con R1); sí se permiten páginas oficiales de proyectos de censo (listas de IP, páginas de exclusión) citadas en `evidencia`. El etiquetador no abre la clave hasta terminar. Se escribe en `evidencia` el id del criterio y el dato (por ejemplo `M1: 22:340`).

**Definiciones.**
- *Puertos sensibles:* 21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017 y 2222 (SSH de administración).
- *Puertos de autenticación:* 21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900 y 2222.
- *Flujo:* decisión T2/T3 registrada para la IP (los flujos T0/T1 no guardan `src_ip`), así que los conteos son un piso.
- *Firma de ataque:* contiene EXPLOIT, MALWARE, TROJAN, BRUTE, SHELLCODE, "Privilege Gain" o "Web Application Attack". Las firmas de reputación o listas (CINS, DROP, "Poor Reputation", "Known Malicious") **no bastan solas**: son evidencia de apoyo.

**Orden de evaluación:** M1/M2, luego FP, luego ER, luego M3/M4, y si nada aplica, I.

| Etiqueta | Criterio | Condición verificable en la ficha |
|---|---|---|
| **malicioso** | M1, intentos repetidos de autenticación | `top5_puertos` trae un puerto de autenticación con ≥ 20 flujos |
| | M2, explotación o intrusión | `suricata_firmas` o `suricata_categorias` con una firma de ataque (definición arriba) |
| | M3, barrido amplio sin identificación | `puertos_distintos` ≥ 50 y `flujos_t2_t3` ≥ 50 y sin pre-etiqueta ni proyecto identificado (ER2) |
| | M4, sondeo sostenido de puertos sensibles | ≥ 3 de los 5 puertos de `top5_puertos` son sensibles y `flujos_t2_t3` ≥ 20 |
| **escáner de investigación** | ER1 | la pre-etiqueta se confirma (la regla aplicó y la revisión humana la valida) y no hay M1 ni M2 |
| | ER2 | la organización o el DNS inverso identifican un proyecto de censo o medición no incluido en las reglas, con la fuente citada en `evidencia`, y no hay M1 ni M2 |
| **falso positivo** | FP1, servicio legítimo verificado | FCrDNS **confirmado** bajo un dominio de la lista cerrada: googlebot.com, search.msn.com, applebot.apple.com, crawl.yahoo.net, yandex.com, yandex.ru, yandex.net, baidu.com, baidu.jp, duckduckgo.com; con `puertos_distintos` ≤ 3 en 80/443 y sin M1–M4 |
| | FP2, servicio propio o contratado | el dueño del ASN/dominio es un servicio que el laboratorio usa (validación de certificados, monitoreo de disponibilidad) y se cita en `evidencia`; ≤ 3 puertos (80/443) y sin firmas de ataque |
| **indeterminado** | I1 | ningún criterio anterior aplica y `flujos_t2_t3` < 10 sin firmas de ataque ni identificación de proyecto |
| | I2 | la evidencia es contradictoria o falta (por ejemplo una regla de escáner que choca con M2 y el etiquetador no puede decidir) |

Una IP con pre-etiqueta que además cumple M1 o M2 se etiqueta `malicioso`; eso cuenta como corrección de la regla.

## 6. Reglas de preetiquetado

Solo usan DNS inverso con FCrDNS confirmado, ASN u organización (Team Cymru). Nunca el score, el tier ni la TI de R-SOAR. El resultado es la columna `pre_etiqueta` = `escáner de investigación` y la columna `regla` con la condición exacta. El etiquetador humano revisa cada una y puede corregirla; no se aplica nada sin revisión. Lista cerrada, generada desde `REGLAS` de `construir_ficha.py`:

| Regla | Proyecto | Señal | Condición exacta |
|---|---|---|---|
| R01 | Censys | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.censys-scanner.com` |
| R02 | Censys | ASN / organización | el nombre del AS (Team Cymru) contiene `CENSYS` (sin distinguir mayúsculas) |
| R03 | Shodan | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.shodan.io` |
| R04 | Shadowserver | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.shadowserver.org` |
| R05 | Shadowserver | ASN / organización | el nombre del AS (Team Cymru) contiene `SHADOWSERVER` (sin distinguir mayúsculas) |
| R06 | Onyphe | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.onyphe.net` |
| R07 | Onyphe | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.onyphe.io` |
| R08 | Onyphe | ASN / organización | el nombre del AS (Team Cymru) contiene `ONYPHE` (sin distinguir mayúsculas) |
| R09 | Modat | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.modat.io` |
| R10 | Stretchoid | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.stretchoid.com` |
| R11 | Criminal IP | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.criminalip.com` |
| R12 | Driftnet | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.driftnet.io` |
| R13 | BitSight | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.bitsight.com` |
| R14 | BitSight | ASN / organización | el nombre del AS (Team Cymru) contiene `BITSIGHT` (sin distinguir mayúsculas) |
| R15 | TUM (Technische Universität München) | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.in.tum.de` |
| R16 | Internet Measurement | DNS inverso (FCrDNS) | DNS inverso con FCrDNS confirmado y que termina en `.internet-measurement.com` |

Proyectos sin regla por no tener un patrón verificable en el repo: Silent Push y otros. Aplicaron las reglas a 19 de las 100 IPs.

## 7. Entregables y verificación de la ficha ciega

- **Ficha ciega** (`ficha_ciega.csv`): id, ip, /24, DNS inverso, FCrDNS, ASN, organización, país, puertos distintos, 5 puertos más frecuentes, flujos, primera y última vista, alertas, firmas y categorías de Suricata, pre_etiqueta, regla, y las columnas vacías etiqueta, evidencia y notas. No lleva score, tier, resultado de AbuseIPDB u OTX ni hora del bloqueo.
- **Clave sellada** (`clave_sellada.csv`): id, ip, score, tier, tipo de fuentes de TI, resultados de AbuseIPDB y OTX, hora del bloqueo, trace_id. Su sha256 se registró **antes** de entregar la ficha.
- **Ficha del segundo etiquetador** (`ficha_segundo_etiquetador.csv`): los 30 primeros ids del orden aleatorio, **sin** pre_etiqueta ni regla.

| Archivo | sha256 |
|---|---|
| `clave_sellada.csv` | `c869fc311e22b7ed9b676f6d3aa19692ccd1b7d7bef0186b60cf807fd1b5cbd4` |
| `ficha_ciega.csv` | `0a80289f82a4ad9a0d052ee07b74e342dc9990ae92aa73df79bb8b70d810fc15` |
| `ficha_segundo_etiquetador.csv` | `1f08ed6cada01904ec7497cab03a97851b80d99e20609a639b2202bfbf2e54af` |

## 8. Análisis posterior al etiquetado

`scripts/metrics/precision_p2/analizar_etiquetado.py` (probado con datos sintéticos; no se ha ejecutado con datos reales) calcula: precisión estricta (malicioso / n) y ampliada ((malicioso + escáner) / n) con intervalo de Clopper-Pearson al 95 %; tasa de falsos positivos; indeterminados aparte con cotas pesimista y optimista; precisión con el mismo peso por /24 y número de /24 distintos; acuerdo y kappa de Cohen con el segundo etiquetador sobre los 30 ids; y la tasa de corrección de las pre-etiquetas.

## 9. Límites

- **Etiqueta humana, no verdad:** la precisión es la fracción de bloqueos que un etiquetador, con la evidencia de la ficha, considera justificados. No hay confirmación externa de intención.
- **Piso de evidencia:** los flujos solo cuentan decisiones T2/T3 y solo 16 de las 100 IPs tienen alertas de Suricata; muchas IPs tienen 1 o 2 puertos y pocos flujos, lo que empuja a `indeterminado`. 61 de las 100 IPs no tienen DNS inverso.
- **Agrupación:** las 100 IPs están en 61 /24 distintos; el intervalo de Clopper-Pearson supone independencia, por eso se reporta también la precisión con peso igual por /24.
- **Tiempo:** el comportamiento incluye lo visto hasta la extracción (12-oct 16:42Z) y desde el 3-oct, no solo hasta el bloqueo; la primera y última vista no son la hora del bloqueo.
- **Marco:** excluye las 37 IPs con aprobación manual; no extrapola a ellas ni a la infra propia.
- **Umbrales de la rúbrica** (20 flujos, 50 puertos, etc.) son convenciones del protocolo, no estándares; se fijan antes de ver la ficha etiquetada.
