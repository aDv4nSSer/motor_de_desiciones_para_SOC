# Seguimiento: período de modo sombra del score de corroboración ponderado

**Creado:** 2026-10-07 (H52). **Dueño de las decisiones:** Antonio.
**Estado:** ▶️ **PERÍODO EN CURSO.** Inicio formal **2026-10-07 20:40 -03** (`2026-10-07T23:40:00Z`) · fin **2026-10-10 20:40 -03** (`2026-10-10T23:40:00Z`). P1 cerrado (key rotada, `200` a las 21:07 -03); P2 pasó a medirse dentro de la ventana (criterio de salida 4, decisión de Antonio del 7-oct); P3 y P4 hechos en H53.

El score de corroboración ponderado (`motor/scoring/corroboration.py`), con sus 4 grupos instrumentados desde H53 (`signature` por correlación con `suricata-alerts-*`, ~1% de los T3; `context` por recidivismo acotado), corre en **modo sombra** en `response-worker` desde el 2026-10-07 15:24:49 -03: se calcula y se audita en `soc-responses-*` (`corroboration_score/_band/_ambiguous/_count`), pero **no decide nada**. El gate real de R2 sigue siendo `corroboration_count >= 2` (`motor/response/worker.py`). Este archivo define cuándo los datos de la sombra sirven para decidir si se reemplaza el gate. Contexto completo: `docs/BITACORA_TECNICA.md`, H52.

---

## 1. Prerrequisitos

Mientras alguno siga abierto, lo que acumule la sombra es evidencia del problema, no validación. **`band == "high"` no puede usarse como gate de R2** (condición formal, `docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md` sección 9 punto 14).

| # | Prerrequisito | Estado (2026-10-07) | Cómo se verifica |
|---|---|---|---|
| P1 | **Rotar la API key de AbuseIPDB** (marcada "OBLIGATORIO rotar (estuvo expuesta)" en `config.py` desde 2026-07-06) | ✅ **Cerrado 2026-10-07:** rotada 20:48–20:49 -03 (huella `0170c4a5f8` → `e7ebe17561`), `response-worker` reiniciado 20:49:22, **`200` verificado a las 21:07:48 -03** (1 llamada, `Remaining: 843/1000`). Falta revocar la vieja en el panel (Antonio) | Bitácora H52, "Rotación de la key de AbuseIPDB" |
| P2 | **TI disponible de verdad.** Redefinido el 7-oct: deja de ser prerrequisito y pasa a **criterio de salida medido dentro de la ventana** (criterio 4 de la sección 2), sobre T3 **no-stale con IP pública** fuera de la safelist, no sobre el total (el atraso del worker hacía ver como "TI caída" lo que era modo solo-caché). Variante "OTX solo con saturación calibrada" sigue disponible si AbuseIPDB no alcanza | ⏳ Se mide en cada checkpoint | `shadow_period_checkpoint.py`, fila P2 (meta ≥ 95%) **Ojo (2026-10-07):** el token bucket de AbuseIPDB (`5114223`, H52) reparte la cuota en todo el día (6 consultas cada 10 min, prioridad a las que pueden llevar `count` a 2) en vez de agotarla ~50 min después del reset. Debería aportar disponibilidad de AbuseIPDB durante más horas, pero solo ~6 IPs nuevas cada 10 min: **confirmarlo en el próximo checkpoint, no asumirlo** (fila OTX / AbuseIPDB por separado). |
| P3 | Decidir qué hace el score cuando el grupo `ti` no está disponible (antes se renormalizaba a ML solo y un T3 típico daba `high`) | ✅ **Implementado y verificado (H53, 2026-10-07):** `"high"` exige ≥ 2 familias de evidencia (`ml`+`context` cuentan como una). En producción: 199 docs con solo la familia `ml`, los 199 en `"medium"` | `corr_min_evidence_families_for_high` en `config.py`; tests en `test_corroboration_scoring.py` y `test_recidivism_context.py` |
| P4 | Decidir si `context` (recidivismo bajo) y `signature` (alertas no críticas) salen del chequeo de desacuerdo | ✅ **Resuelto (H53, `a90df02`, 2026-10-07):** solo `ml` y `ti` marcan `ambiguous`. Mismo tráfico: T3 `ambiguous` 53,1% → 39,2%; en vivo post-restart: 1,8% | `is_ambiguous()` en `corroboration.py`; fixture de regresión con 306 casos reales |

---

## 2. Período formal y criterios de salida

**Ventana:** 2026-10-07 20:40 -03 → 2026-10-10 20:40 -03 (`2026-10-07T23:40:00Z` → `2026-10-10T23:40:00Z`), 72 h continuas: tres ciclos día/noche y tres resets de cuota de AbuseIPDB (00:00 UTC). Corre con todo lo de H53 desplegado (P3, `signature`, `context`, P4), en modo sombra: el gate de R2 no cambia durante el período.

El período es **válido para decidir** si al cierre se cumplen todos estos:

1. **≥ 100 bloques /24 distintos con T3 puntuado.** La unidad es la /24 y no el evento, porque una sola campaña domina el volumen (`91.92.42.0/24` fue el 78% de los T3 en la primera ventana). Con 0 problemas en 100 entidades independientes, la cota superior al 95% de la tasa es ≈ 3% (regla de tres, 3/N).
2. **≥ 20 T3 con `corroboration_count >= 2`**, para poder medir la celda `¬high & corroborado`. **Si no se llega:** revisión humana de **50 IPs `high & ¬corroborado`** (distintas, de /24 distintas cuando se pueda), para estimar cuántas serían bloqueos correctos.
3. **Invariancia sostenida contra el gate binario durante toda la ventana:** 0 discrepancias (el score no cambia ninguna decisión real).
4. **P2 cumplido:** TI disponible (OTX o AbuseIPDB) en **≥ 95% de los T3 no-stale con IP pública** fuera de la safelist, medido sobre la ventana completa, no sobre el total de eventos.
5. Excluir siempre la ventana sin datos reales del Fast Path de H25 (2026-08-18 a 2026-09-04). Los scripts ya lo hacen.

**Corte dentro de la ventana:** el deploy del token bucket de AbuseIPDB (H52) cambia cuándo hay segunda fuente y, con eso, la distribución de autobloqueos reales. La invariancia sigue siendo válida (se recalcula por doc), pero las distribuciones de antes y después del corte no se comparan entre sí. La hora de corte queda registrada en la sección 6.

**Si no se llegan las 72 h o algún criterio no se cumple** (caída, cambio de infraestructura, lo que sea): el gate binario sigue como está y se reporta como limitación en la tesis (sección 5). No se extiende ni se reinterpreta la ventana para forzar un resultado.

## 3. Checkpoints diarios y comparación final

**Checkpoint (una vez por día, ~20:40 -03, y al cierre).** En `.140`, desde `~/tesis/repo/motor`:

```bash
python3 ../scripts/shadow_period_checkpoint.py                                  # desde el inicio del período hasta ahora
python3 ../scripts/shadow_period_checkpoint.py --until 2026-10-10T23:40:00Z     # cierre
```

Una pasada de solo lectura con `_source` filtrado, que alcanza para todo el período. Devuelve un bloque markdown con los criterios 1-4 y las horas transcurridas. **El bloque se anexa a la sección 6 de este archivo desde el repo local y se commitea** (`docs: modo sombra — checkpoint día N`), nunca editando el repo de `.140`. Así el seguimiento queda versionado y el working tree de `.140` sigue limpio para los `git pull`.

**Comparación final (al cierre):**

```bash
python3 ../scripts/corroboration_shadow_report.py --since 2026-10-07T23:40:00Z --until 2026-10-10T23:40:00Z --max-list 50
```

Da la contingencia T3 `band × (corroboration_count >= 2)` con las discrepancias `high & ¬corroborado` y `¬high & corroborado` por `trace_id`, que son el insumo de la revisión humana. Trae el payload completo, así que con ~600k docs es pesado: correrlo una sola vez, al cierre. Resultado → entrada nueva en la bitácora; la decisión de wirear el gate la toma Antonio.

---

## 4. Primera ventana (2026-10-07, NO válida para decidir)

~9,5 min post-deploy, con AbuseIPDB sin cuota: invariancia 1.090/1.090, T3 pendiente 98,7% (línea base 98,3%), T3 `high` 206/231 (89%), 0 T3 con count ≥ 2, 132 IPs pero solo 8 /24. Sirve como evidencia de la condición formal, no como validación. Detalle en H52.

## 5. Si no se llega antes del cierre del documento (16-oct-2026)

El gate binario queda como está. En la tesis se reporta el modo sombra como resultado parcial y la condición formal como limitación del enfoque en este entorno (Resultados o Discusión): plan gratuito de TI, y grupos de firma y de contexto sin instrumentar. No se fuerza ningún cambio del gate para tener un resultado antes de la defensa.

---

## 6. Checkpoints del período

_(Se anexan acá, uno por día, con la salida de `shadow_period_checkpoint.py`.)_

| Momento | Evento | Efecto en la medición |
|---|---|---|
| 2026-10-07 20:40 -03 (`2026-10-07T23:40:00Z`) | Inicio formal del período | — |
| 2026-10-07 21:07 -03 | P1 cerrado: key de AbuseIPDB rotada y `200` verificado | — |
| **2026-10-07 21:56:08 -03 (`2026-10-08T00:56:08Z`)** | **CORTE DE RÉGIMEN:** deploy del token bucket de AbuseIPDB (6 cada 10 min, OTX primero, prioridad a decisivas; `5114223`, H52) | **P2 y la disponibilidad de AbuseIPDB se evalúan solo desde el corte:** `shadow_period_checkpoint.py --since 2026-10-08T00:56:08Z`. Antes y después no son comparables. Los criterios 1-3 (/24, count ≥ 2, invariancia) siguen usando la ventana completa desde 23:40Z, pero el conteo de T3 con count ≥ 2 se reporta también separado por tramo |
| **2026-10-08 00:54:49 -03 (`2026-10-08T03:54:49Z`)** | **CORTE DE RÉGIMEN (solo T2):** restart de `response-worker` con `3243c0d` (H54). Una T2 no stale cuyo origen está en `config.OWN_INFRA` registra `ninguna_infra_propia` y no abre caso, en lugar de `alertar_crear_caso` | **No toca T3, R2, el gate ni el score de corroboración.** El criterio 3 (invariancia) recalcula cada doc con la regla de su tramo: `expected_r2()` aplica la regla nueva solo si `payload.processed_at >= T2_OWN_INFRA_CUT` (`corroboration_shadow_report.py`). Antes del corte, una T2 de infra propia sigue esperando `alertar_crear_caso`. Una discrepancia en esas T2 **no** es una ruptura real de invariancia si el checkpoint corre con el script de `3243c0d` o posterior: verificar la versión antes de interpretarla. Las distribuciones de T2 por acción de antes y después del corte no se comparan |
| **2026-10-08 00:32:41–00:32:45 -03 (`03:32:41,987Z`–`03:32:45,538Z`)** | **INCIDENTE (H54):** desalojo masivo de Redis (72.205 claves) causado por una consulta de diagnóstico. Se perdió el stream `soc:response:audit` con su consumer group. Indexador recuperado a las 01:20:46 -03 y `verify_chain` íntegra | **Para el checkpoint de hoy (~20:40 -03), antes de interpretar nada:** (1) **invariancia:** faltan de 0 a ~5 registros R1/R2 de esos 3,55 s, que nunca se indexaron. No es una ruptura de invariancia: esos docs no existen en `soc-responses-*` y el conteo total es menor, nada más. (2) **Grupo `context`:** 235 IPs perdieron su acumulador `risk:ip:*` (recidivismo de 9 a 0, por ejemplo). A las 13:57 -03, 36 seguían por debajo de su valor previo. El score de sombra subestima `context` para esas IPs hasta que acumulen 5 horas distintas de actividad. Las bandas posteriores a 03:32Z no son estrictamente comparables con las anteriores para esas IPs. (3) **P2:** a las 13:57 -03 estaba activa `abuseipdb:quota_exhausted` hasta 00:00 UTC. No viene del desalojo, pero baja la disponibilidad de TI medida hoy. **Causa confirmada (H55, `worker.log` de `.140`):** el motor gastó **716** de las 1.000 en los 56 min previos al deploy del bucket (21:00–21:56 -03: 695 OK + 20 timeouts que también cobran + 1 verificación manual de P1). El bucket gastó las **284** restantes a 36/h, y el primer `429` llegó a las **05:40:28 -03 (`08:40:28Z`)**. Suma: 1.000 exactas. El cron de `.139` (03:42 -03) cobró 0 de esta cuenta (otra key). Ni el desalojo de H54 ni otro consumidor agregaron nada. **Para el P2 de hoy:** AbuseIPDB se sostuvo por caché hasta ~11:00 -03 y está en 0 desde las 12:00 -03. Es un artefacto del **día del deploy**, no el régimen estacionario del bucket: no leerlo como falla del bucket ni de la TI. El P2 comparable es el del 9-oct UTC (desde las 21:00 -03 de hoy), donde se espera 0 `429`. Si el 9-oct se agota, H55 se reabre |
| **2026-10-08 23:42:16 -03 (`2026-10-09T02:42:16Z`); restart efectivo 23:42:54 -03 (`02:42:54Z`)** | **CORTE DE RÉGIMEN (nominal): deploy de H55** (`d0c8f93`, `git pull --ff-only` a las 23:42:05). Gauge de la cuota real (`X-RateLimit-*`): el ritmo por ventana pasa a `min(presupuesto local, restante real / ventanas hasta el reset)`. Fueron dos restarts seguidos de `response-worker` (PID 340219, 38 s; y PID 340252, el vigente). Un solo proceso consumiendo | En régimen normal no cambia nada respecto del bucket de H52 (el ritmo nunca baja de 7 > 6 por ventana), así que P2 y los autobloqueos siguen comparables con el tramo anterior del día. Antes del restart, desde el reset de las 21:00 -03: 96 consultas `200 OK`, 6 timeouts, **0 respuestas 429**. Verificación de las líneas `AbuseIPDB cuota real` y de la ausencia de `consumo externo`: ver H57 |
| **2026-10-09 21:00 -03 (`2026-10-10T00:00:00Z`) — PLANIFICADO; registrar la hora real del restart** | **CORTE DE RÉGIMEN + CIERRE DEL PERÍODO 1 + APERTURA DEL PERÍODO 2 (H56):** deploy de la Fase 3 A (`724cbb8`). AbuseIPDB solo para T3 con OTX corroborando (T2 lee solo caché, cupo no decisivo en 0), TTL de caché 24 h si score ≥ 50 y 6 h si no (requiere editar `ABUSEIPDB_CACHE_TTL` en el `.env` de `.140`), y log `AbuseIPDB API tier=N`. Gate de R2 sin cambios. Cowrie sin cambios. **Cambio de DEFINICIÓN de métrica del dashboard (`917abc5`):** desde esta hora el puerto 2223 cuenta como `honeypot` y no como `external` en el panel de puertos. Es un cambio de clasificación, no de los datos. Si D2 entra en este corte: bucket diario con ráfaga, **sin ráfaga el primer día** (arranque conservador) | **Período 1** (7-oct 20:40 → 9-oct 21:00, ~49 h): no llega al mínimo de 72 h de la sección 2, así que **no es válido para decidir el gate**. Es coherente con la decisión de H56 de mantener el gate binario, y queda como evidencia de diagnóstico (TI sin cuota). **Período 2:** 72 h con TI disponible, hasta el **2026-10-12 21:00 -03**. P2, `count ≥ 2` y los autobloqueos solo se comparan dentro del período 2. Predicciones a falsar (H56): T2 = 0 llamadas; ≤ ~500 consultas/día sin 429; TI en ≥ 95% de las horas; IPs T3 sin campaña auto-bloqueadas ≥ 50% (piso medido 21%; reportar siempre observados contra imputados); pendientes/día a la baja. Si alguna falla, se reabre H56 |
| **2026-10-11 04:00 -03 (`07:00Z`) — EVENTO PROGRAMADO (no es corte si el hash no cambia)** | Reentrenamiento semanal del IF (cron de `.140`): si lo aprueba, sobrescribe `isolation_forest.pkl` y reinicia `motor-soc` (~15 s sin Fast Path) | **Antes del domingo:** `stat -c %y ~/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv` en `.140` debe seguir siendo **2026-06-20 13:52**; si cambió, el modelo del domingo va a ser distinto. **Después:** registrar la hora real del restart y verificar que `sha256sum ~/tesis/motor-runtime/models/isolation_forest.pkl` empiece con `4958eb4b`: igual = mismo modelo, solo evento. **Distinto = CORTE DE RÉGIMEN** (cambia `anomaly_score`, el `risk_score`, los tiers y el grupo `ml` de C): se anota acá y las métricas del período 2 se separan por tramo. Ver H56 |

**Para el checkpoint de mañana (~20:40 -03):** correr el script dos veces. Una con la ventana completa (default) para los criterios 1-3 y las horas, y otra con `--since 2026-10-08T00:56:08Z` para P2 (fila "TI disponible" y "OTX / AbuseIPDB por separado"). Anotar las dos.
