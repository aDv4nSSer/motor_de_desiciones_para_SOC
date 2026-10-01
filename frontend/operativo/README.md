# Dashboard Operativo (N1/N2)

Consola de operador de R-SOAR: alertas T2/T3, aprobaciones pendientes y casos
(pendiente de Iris Web). React + Vite + TypeScript, sin librería de UI: tokens
CSS propios (modo claro/oscuro), íconos Phosphor, fuentes Fira autoalojadas.

## Cómo se sirve

`motor-soc` (FastAPI) monta el bundle en `/operativo` con `StaticFiles`
(`motor/main.py:mount_operativo`). Mismo origen que la API: sin CORS y con el
JWT solo en memoria (nunca `localStorage`; se pierde al recargar).

## Comandos

```bash
npm ci
npm test            # vitest: sesión 401/503, aprobaciones sin optimistic update, join de alertas
npm run build       # escribe en ../../motor/static/operativo (gitignored)
../../scripts/deploy_operativo.sh   # tests + build + copia a .140 (una sola conexión ssh)
```

El build nunca corre en `.140` (RAM limitada).

## Dev server

`npm run dev` arranca SIN proxy a propósito: apuntarlo al motor real expondría
botones que ejecutan bloqueos reales (`RESPONSE_MODE=enforce`). Para un backend
local: `VITE_DEV_API_TARGET=http://127.0.0.1:8000 npm run dev`.

## Contrato con el backend

| Vista | Endpoints |
|---|---|
| Login | `POST /api/v1/auth/login` |
| Alertas | `GET /api/v1/dashboard/decisions?tier_min=2&before=…` unido por `trace_id` con `GET /api/v1/dashboard/blocks/recent` (últimas 200 respuestas), contadores de `GET /api/v1/dashboard/stats` |
| Aprobaciones | `GET /api/v1/dashboard/approvals`, `POST /api/v1/dashboard/approvals/{trace_id}/resolve` |
| Casos | ninguno: Iris Web no está integrado todavía |

Sesión: 401 en cualquier llamada protegida vuelve al login; 503 (Redis no pudo
verificar el usuario) muestra "reintentando" y conserva la sesión.
