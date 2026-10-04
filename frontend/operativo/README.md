# Dashboard R-SOAR: Operativo (N1/N2) y Gerencial/CISO

Consola única de R-SOAR con shell compartido (header + sidebar) y menú armado
según el rol del JWT. Operación: alertas T2/T3, aprobaciones, casos (pendiente
de Iris Web) y estado de nodos. Gobierno: historial/auditoría (N2 parcial,
CISO completo), usuarios y sesiones (N2+), cumplimiento Ley 21.663 y
tendencias (solo CISO). React + Vite + TypeScript, sin librería de UI: tokens
CSS propios (modo claro/oscuro), íconos Phosphor, IBM Plex autoalojada,
gráficos SVG propios (`src/components/charts`).

## Roles y rutas

`src/app/routes.ts` es la única tabla de qué ve cada rol: la usan el menú y el
guardia de ruta (una ruta prohibida muestra "Acceso restringido" y no monta la
vista ni llama a su endpoint). El backend aplica las mismas reglas
(`require_role` / `require_ciso` en `motor/main.py`); el frontend es UX.

## Identidad visual

- Logo: `src/assets/brand/ubo-logo-provisional.png`, logo oficial de la
  Universidad Bernardo O'Higgins de **uso provisional** hasta que R-SOAR tenga
  marca propia. Mostrarlo a un cliente externo requiere autorización explícita
  de la universidad.
- Paleta de marca (Brandfetch, no el manual oficial de UBO; si aparece el
  manual, prima): #004696 primario, #7FBBE3 secundario, #212529 texto.
- Severidad T0-T3 y estados usan una paleta semántica aparte (verde, ámbar,
  naranja, rojo), nunca el azul institucional, y siempre con texto o ícono.
  Detalle y validación en el encabezado de `src/index.css`.

## Cómo se sirve

`motor-soc` (FastAPI) monta el bundle en `/operativo` con `StaticFiles`
(`motor/main.py:mount_operativo`). Mismo origen que la API: sin CORS y con el
JWT solo en memoria (nunca `localStorage`; se pierde al recargar).

## Comandos

```bash
npm ci
npm test            # vitest: sesión 401/503, aprobaciones, alertas, rol-gating, vistas H43
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
| Estado de nodos (N1+) | `GET /api/v1/dashboard/nodes` |
| Historial y auditoría (N2+) | `GET /api/v1/dashboard/audit/chain`, `GET /api/v1/dashboard/audit/trace/{trace_id}`; CISO además `GET /api/v1/dashboard/audit/access` |
| Usuarios y sesiones (N2+) | `GET/POST /api/v1/dashboard/users`, `PATCH /api/v1/dashboard/users/{u}`, `POST /api/v1/dashboard/users/{u}/password`, `GET /api/v1/dashboard/sessions`, `DELETE /api/v1/dashboard/sessions/{u}/{jti}`, `DELETE /api/v1/dashboard/users/{u}/sessions` |
| Cumplimiento (CISO) | `GET /api/v1/dashboard/compliance?window_minutes=` |
| Tendencias (CISO) | `GET /api/v1/dashboard/trends?days=1\|7\|30` |
| Cerrar sesión | `POST /api/v1/auth/logout` (revoca el `jti` en el servidor) |

Sesión: 401 en cualquier llamada protegida vuelve al login; 503 (Redis no pudo
verificar el usuario) muestra "reintentando" y conserva la sesión.
