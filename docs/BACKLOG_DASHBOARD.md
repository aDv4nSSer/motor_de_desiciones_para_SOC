# Backlog — mejoras futuras del dashboard

Mejoras identificadas pero no urgentes, sin riesgo para el path crítico del motor
(son endpoints de solo lectura en `motor/dashboard.py` / `motor/dashboard.html`).

## Latencia mediana real (p50) en el tile de latencia

Hoy el tile "Latencia promedio" (`motor/dashboard.html:267`) muestra
`stats.latencia_avg_ms`, que en el backend es un promedio (`avg` sobre
`latency_ms`, `motor/dashboard.py:80`) — no una mediana. El label ya se
corrigió para reflejar esto (2026-08-12).

Si en algún momento se quiere una mediana real, agregar `percents: [50]` a la
agregación `latencia_p95` existente (`motor/dashboard.py:81`, que ya usa
`percentiles`) y exponer el valor como `latencia_p50_ms` junto a `latencia_avg_ms`.
Mismo patrón que `latencia_p95_ms`, cambio de bajo riesgo — no requiere tocar
el Fast Path ni ningún índice nuevo.

**Prioridad:** baja, no urgente. Diferido post-defensa.
