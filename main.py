from __future__ import annotations

import logging
import logging.config
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.endpoints.predict import router as predict_router

# ---------------------------------------------------------------------------
# Logging estructurado (JSON) para integración con pipelines de observabilidad
# ---------------------------------------------------------------------------
_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","message":"%(message)s"}',
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        }
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        }
    },
    "root": {"handlers": ["stdout"], "level": _LOG_LEVEL},
})

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuración de la aplicación desde variables de entorno
# ---------------------------------------------------------------------------
_API_TITLE = os.getenv("API_TITLE", "Motor de Decisiones SOC")
_API_VERSION = os.getenv("API_VERSION", "0.1.0")
_API_DEBUG = os.getenv("FASTAPI_DEBUG", "false").lower() == "true"
_ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("api_startup", extra={"version": _API_VERSION, "debug": _API_DEBUG})
    yield
    logger.info("api_shutdown")


app = FastAPI(
    title=_API_TITLE,
    version=_API_VERSION,
    description=(
        "API de inferencia para el motor de decisiones del SOC. "
        "Expone clasificación supervisada y detección de anomalías sobre flujos de red "
        "usando el Golden Subset v4 (11 features)."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    debug=_API_DEBUG,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.include_router(predict_router)


@app.get("/health", tags=["health"], summary="Health check")
def health() -> dict[str, str]:
    return {"status": "ok", "version": _API_VERSION}


# ---------------------------------------------------------------------------
# Punto de entrada directo: python main.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _host = os.getenv("FASTAPI_HOST", "0.0.0.0")
    _port = int(os.getenv("FASTAPI_PORT", "8000"))

    logger.info("starting_uvicorn", extra={"host": _host, "port": _port})
    uvicorn.run(
        "main:app",
        host=_host,
        port=_port,
        reload=_API_DEBUG,
        log_config=None,  # usa nuestro logging ya configurado
    )
