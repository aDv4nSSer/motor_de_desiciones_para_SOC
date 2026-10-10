"""
regimes.py — Regímenes de decisión y versión de política (H57).

Un régimen es un tramo de tiempo con la misma política de entrada a las
decisiones: cada corte registrado en docs/PENDIENTES_MODO_SOMBRA.md abre uno
nuevo. Las métricas de antes y después de un corte no se comparan como si
fueran el mismo sistema; por eso cada métrica del dashboard lleva su
`regime_id`.

`policy_version` es el hash de la configuración efectiva de R1/R2 (sin
secretos): si dos reportes tienen el mismo `policy_version`, decidieron con
los mismos umbrales, tiers y gates.

Para agregar un corte: una entrada nueva al final de REGIMES, en el mismo
commit que lo despliega, con la hora real del restart.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

# (id, desde (UTC), descripción). Orden cronológico. Fuente: sección 6 de
# docs/PENDIENTES_MODO_SOMBRA.md.
REGIMES: tuple[tuple[str, datetime, str], ...] = (
    ("R0", datetime(2026, 10, 7, 23, 40, tzinfo=timezone.utc),
     "Inicio del período de sombra 1 (H52): AbuseIPDB sin control de cuota"),
    ("R1", datetime(2026, 10, 8, 0, 56, 8, tzinfo=timezone.utc),
     "Token bucket de AbuseIPDB (H52, 5114223)"),
    ("R2", datetime(2026, 10, 8, 3, 54, 49, tzinfo=timezone.utc),
     "T2 de infraestructura propia sin caso (H54, 3243c0d)"),
    ("R3", datetime(2026, 10, 9, 2, 42, 16, tzinfo=timezone.utc),
     "Gauge de la cuota real de AbuseIPDB (H55, d0c8f93)"),
    ("R4", datetime(2026, 10, 9, 14, 21, 0, tzinfo=timezone.utc),
     "Fase 3 A: AbuseIPDB solo para T3 decisivos, caché 24 h/6 h, casos T2 con dedup; período 2 (H56/H58, 43a62bd)"),
)

# Campos de la configuración que nunca entran al hash ni se muestran.
_SECRET_MARKERS = ("key", "pass", "secret", "token", "credential")


def regime_at(ts: datetime) -> dict[str, str] | None:
    """Régimen vigente en `ts`, o None si es anterior al primero registrado."""
    current = None
    for rid, since, desc in REGIMES:
        if ts >= since:
            current = {"id": rid, "desde": since.isoformat(), "descripcion": desc}
    return current


def regimes_between(start: datetime, end: datetime) -> list[dict[str, str]]:
    """Regímenes que tocan [start, end], en orden (incluye el vigente al inicio)."""
    out = []
    first = regime_at(start)
    if first:
        out.append(first)
    for rid, since, desc in REGIMES:
        if start < since <= end:
            out.append({"id": rid, "desde": since.isoformat(), "descripcion": desc})
    return out


def effective_policy(settings: Any) -> dict[str, Any]:
    """Configuración efectiva sin secretos (pydantic BaseSettings)."""
    data = settings.model_dump() if hasattr(settings, "model_dump") else dict(settings)
    clean = {}
    for k, v in sorted(data.items()):
        if any(m in k.lower() for m in _SECRET_MARKERS):
            continue
        clean[k] = getattr(v, "value", v)
    return clean


def policy_version(settings: Any) -> str:
    """Hash corto (sha256, 12 hex) de la configuración efectiva sin secretos."""
    blob = json.dumps(effective_policy(settings), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]
