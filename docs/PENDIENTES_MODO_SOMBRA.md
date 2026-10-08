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
| P2 | **TI disponible de verdad.** Redefinido el 7-oct: deja de ser prerrequisito y pasa a **criterio de salida medido dentro de la ventana** (criterio 4 de la sección 2), sobre T3 **no-stale con IP pública** fuera de la safelist, no sobre el total (el atraso del worker hacía ver como "TI caída" lo que era modo solo-caché). Variante "OTX solo con saturación calibrada" sigue disponible si AbuseIPDB no alcanza | ⏳ Se mide en cada checkpoint | `shadow_period_checkpoint.py`, fila P2 (meta ≥ 95%) |
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
