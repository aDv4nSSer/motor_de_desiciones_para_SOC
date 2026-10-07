# Seguimiento: período de modo sombra del score de corroboración ponderado

**Creado:** 2026-10-07 (H52). **Dueño de las decisiones:** Antonio.
**Estado:** prerrequisitos **NO cumplidos** (P1, P2 y P4 abiertos; P3 hecho en H53): el período válido todavía no empezó.

El score de corroboración ponderado (`motor/scoring/corroboration.py`), con sus 4 grupos instrumentados desde H53 (`signature` por correlación con `suricata-alerts-*`, ~1% de los T3; `context` por recidivismo acotado), corre en **modo sombra** en `response-worker` desde el 2026-10-07 15:24:49 -03: se calcula y se audita en `soc-responses-*` (`corroboration_score/_band/_ambiguous/_count`), pero **no decide nada**. El gate real de R2 sigue siendo `corroboration_count >= 2` (`motor/response/worker.py`). Este archivo define cuándo los datos de la sombra sirven para decidir si se reemplaza el gate. Contexto completo: `docs/BITACORA_TECNICA.md`, H52.

---

## 1. Prerrequisitos (se cumplen ANTES; el período no corre en paralelo)

Mientras alguno siga abierto, lo que acumule la sombra es evidencia del problema, no validación. **`band == "high"` no puede usarse como gate de R2** (condición formal, `docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md` sección 9 punto 14).

| # | Prerrequisito | Estado (2026-10-07) | Cómo se verifica |
|---|---|---|---|
| P1 | **Rotar la API key de AbuseIPDB** (marcada "OBLIGATORIO rotar (estuvo expuesta)" en `config.py` desde 2026-07-06) | ❌ No rotada: misma huella sha256 en el `.env` y en los 6 backups de `.140` desde 2026-09-03 | Huella del `.env` distinta de `0170c4a5f8` + entrada en la bitácora |
| P2 | **TI disponible de verdad** en una de dos variantes: **(a)** AbuseIPDB con cuota suficiente para el volumen, o **(b)** OTX solo con `corr_otx_pulse_saturation` calibrada con datos (hoy 5, valor inicial) y decisión explícita de aceptar bloquear sin redundancia de proveedor | ❌ AbuseIPDB: 1.000/día, se agota ~2 h después del reset de 00:00 UTC. OTX: no disponible en ~16% de los T3 de la primera ventana | (a) `abuseipdb_available = true` en ≥ 95% de los T3 de una ventana de 24 h; (b) `otx_available = true` en ≥ 95% de los T3 + calibración documentada |
| P3 | Decidir qué hace el score cuando el grupo `ti` no está disponible (antes se renormalizaba a ML solo y un T3 típico daba `high`) | ✅ **Implementado y verificado (H53, 2026-10-07):** `"high"` exige ≥ 2 familias de evidencia (`ml`+`context` cuentan como una). En producción: 199 docs con solo la familia `ml`, los 199 en `"medium"` | `corr_min_evidence_families_for_high` en `config.py`; tests en `test_corroboration_scoring.py` y `test_recidivism_context.py` |
| P4 | Decidir si `context` (recidivismo bajo) y `signature` (alertas no críticas) salen del chequeo de desacuerdo: hoy generan `ambiguous` contra ML/TI altos (154 + 3 en los primeros 13 min, H53) | ❌ Abierto, decisión de Antonio | Decisión registrada en la bitácora; si cambia `corroboration.py`, con sus tests |

---

## 2. Criterio del período (una vez cumplidos P1-P4)

Todo sobre una ventana que **empieza después** de cumplir P1-P4:

1. **≥ 72 h continuas:** tres ciclos día/noche y tres resets de cuota de AbuseIPDB (00:00 UTC).
2. **≥ 100 bloques /24 distintos con T3 puntuado.** La unidad es la /24 y no el evento, porque una sola campaña domina el volumen (`91.92.42.0/24` fue el 78% de los T3 en la primera ventana). Con 0 problemas en 100 entidades independientes, la cota superior al 95% de la tasa es ≈ 3% (regla de tres, 3/N).
3. **≥ 20 T3 con `corroboration_count >= 2`**, para poder medir la celda `¬high & corroborado`. Si no se alcanza, la comparación contra el gate binario no es informativa y se pasa al punto 4.
4. **Revisión humana de ≥ 50 IPs `high & ¬corroborado`** (distintas, de /24 distintas cuando se pueda), para estimar cuántas serían bloqueos correctos. Es lo único que separa "el gate binario es demasiado estricto" de "el score es demasiado laxo".
5. **Invariancia sostenida:** 0 discrepancias en la sección 1 del reporte durante todo el período (el score no debe cambiar ninguna decisión real).
6. Excluir siempre la ventana sin datos reales del Fast Path de H25 (2026-08-18 a 2026-09-04). El script ya lo hace.

## 3. Cómo se corre la comparación

En `.140`, desde `~/tesis/repo/motor` (toma el `.env`):

```bash
python3 ../scripts/corroboration_shadow_report.py --since <inicio del período, ISO UTC> --max-list 50
```

En una sola corrida de solo lectura, el script da: (1) invariancia contra la rama R2 recalculada, (2) distribución tier × acción × bloqueo, (3) contingencia T3 `band × (corroboration_count >= 2)` con las discrepancias `high & ¬corroborado` y `¬high & corroborado` por `trace_id`. Las condiciones 1, 2 y 4 se miden aparte (ver la consulta de IPs y /24 en H52). Resultado → entrada nueva en la bitácora; la decisión de wirear el gate la toma Antonio.

---

## 4. Primera ventana (2026-10-07, NO válida para decidir)

~9,5 min post-deploy, con AbuseIPDB sin cuota: invariancia 1.090/1.090, T3 pendiente 98,7% (línea base 98,3%), T3 `high` 206/231 (89%), 0 T3 con count ≥ 2, 132 IPs pero solo 8 /24. Sirve como evidencia de la condición formal, no como validación. Detalle en H52.

## 5. Si no se llega antes del cierre del documento (16-oct-2026)

El gate binario queda como está. En la tesis se reporta el modo sombra como resultado parcial y la condición formal como limitación del enfoque en este entorno (Resultados o Discusión): plan gratuito de TI, y grupos de firma y de contexto sin instrumentar. No se fuerza ningún cambio del gate para tener un resultado antes de la defensa.
