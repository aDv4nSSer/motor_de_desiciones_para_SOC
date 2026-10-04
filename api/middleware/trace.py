"""
api/middleware/trace.py — X-Trace-Id en TODA respuesta de la API de
inferencia (main.py de la raíz). Copia de motor/trace_middleware.py: los dos
paquetes no se importan entre sí (motor/ corre con cwd=motor e imports
planos). Mantener ambos iguales; ver el docstring de allí y H45.

Contrato (CLAUDE.md, .claude/rules/observability.md "trace_middleware").

Mismo contrato que el patrón documentado: toma X-Trace-Id del request o
genera un uuid4, lo devuelve en el header de respuesta junto con
X-Duration-Ms y loguea `request_completed`. Diferencias deliberadas:

- Middleware ASGI puro en vez de `@app.middleware("http")`: con
  BaseHTTPMiddleware, si el endpoint lanza una excepción no controlada,
  `call_next` la propaga y la respuesta 500 la arma ServerErrorMiddleware
  por fuera, SIN el header. Acá se intercepta y se responde el 500 con el
  header y el error uniforme de CLAUDE.md; después se re-lanza para que
  uvicorn la siga registrando como siempre. Además evita el costo extra de
  BaseHTTPMiddleware en el Fast Path.
- El X-Trace-Id entrante es input externo: solo se acepta si cumple
  TRACE_ID_PATTERN (mismo formato que valida /audit/trace). Si no, se
  genera uno nuevo — nunca se refleja un valor arbitrario en headers ni logs.
- logging de la stdlib (structlog no está instalado en .140, ver H41).

El trace_id queda en `request.state.trace_id` para quien lo necesite.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("api.trace")

TRACE_HEADER = "X-Trace-Id"
DURATION_HEADER = "X-Duration-Ms"
TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")


def resolve_trace_id(incoming: str | None) -> str:
    """Devuelve el trace_id entrante si es válido, o uno nuevo (uuid4).

    Args:
        incoming: valor crudo del header X-Trace-Id (puede faltar).

    Returns:
        trace_id seguro para headers y logs.
    """
    if incoming and TRACE_ID_PATTERN.fullmatch(incoming):
        return incoming
    return str(uuid.uuid4())


class TraceIdMiddleware:
    """Agrega X-Trace-Id y X-Duration-Ms a toda respuesta HTTP, incluidas
    las de error (401/403/422 y 500 no controlado)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw = None
        for name, value in scope.get("headers", []):
            if name == b"x-trace-id":
                raw = value.decode("latin-1")
                break
        trace_id = resolve_trace_id(raw)
        scope.setdefault("state", {})["trace_id"] = trace_id
        t0 = time.monotonic()
        status = 500
        started = False

        async def send_with_trace(message: Message) -> None:
            nonlocal status, started
            if message["type"] == "http.response.start":
                started = True
                status = message["status"]
                duration_ms = round((time.monotonic() - t0) * 1000, 2)
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"x-trace-id", b"x-duration-ms")]
                headers.append((TRACE_HEADER.encode(), trace_id.encode()))
                headers.append((DURATION_HEADER.encode(), str(duration_ms).encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_trace)
        except Exception:
            # Fallback documentado: si todavía no salió nada, responder el 500
            # acá (con header y error uniforme) y re-lanzar para que uvicorn lo
            # registre con traceback. Si la respuesta ya había empezado, no se
            # puede corregir: solo se re-lanza.
            log.error(f"request_failed trace_id={trace_id} method={scope.get('method')} "
                      f"path={scope.get('path')} response_started={started}")
            if not started:
                body = json.dumps({"error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Error interno de la API",
                    "trace_id": trace_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }}).encode()
                await send_with_trace({"type": "http.response.start", "status": 500, "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ]})
                await send({"type": "http.response.body", "body": body})
            raise
        finally:
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            log.info(f"request_completed trace_id={trace_id} method={scope.get('method')} "
                     f"path={scope.get('path')} status={status} duration_ms={duration_ms}")
