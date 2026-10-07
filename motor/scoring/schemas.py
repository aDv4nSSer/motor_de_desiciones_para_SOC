"""
scoring/schemas.py — Contrato de datos del score de corroboración ponderado.

Reemplaza la semántica de `EnrichmentResult.corroboration_count` (conteo
binario de fuentes) por un score 0-100 fusionado por GRUPO de evidencia
(firma/ATT&CK, TI externa, ML/anomalía, contexto histórico), ponderado por
cuánta evidencia está REALMENTE disponible para el evento — ver
`corroboration.py` para la fórmula y la justificación (reporte de
investigación `reports/Corroboracion ponderada para respuesta autonoma
SOAR.md`, aprobado 7-oct-2026).

Distinción central: un grupo "no disponible" (`available=False`) significa
que hoy no hay ningún instrumento que produzca esa señal para este evento
(ej. `classtype` nunca llega del Fast Path, o el acumulador de contexto
histórico todavía no existe) — NO significa "evidencia negativa". Un grupo
no disponible se excluye del denominador de la normalización, no se cuenta
como 0. Esto es el mismo principio que ya aplica `enrichment.py` a nivel de
fuente individual ("una fuente no disponible no cuenta ni a favor ni en
contra"), extendido a nivel de grupo.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class GroupScore(BaseModel):
    """Score normalizado [0,1] de un grupo de evidencia, o `available=False`
    si hoy no hay ningún instrumento que lo alimente para este evento."""
    name: str
    available: bool
    score: float = 0.0          # solo significativo si available=True
    weight: float = 0.0         # peso máximo configurado del grupo (0-100)
    detail: str = ""            # explicación corta, para reasoning[]/logs


class CorroborationResult(BaseModel):
    """
    Resultado de `compute_corroboration()`.

    `score`: 0-100, fusión ponderada SOLO de los grupos disponibles,
    renormalizada sobre el peso de esos grupos (ver corroboration.py).
    `band`: "low" | "medium" | "high" | "ambiguous" — ver
    `motor/response/config.py` para los umbrales configurables.
    `ambiguous`: True si los grupos disponibles discrepan fuertemente entre
    sí (no es lo mismo un score=75 con todos los grupos de acuerdo que uno
    con un grupo en 1.0 y otro en 0.0) — ver `corroboration.py`.
    """
    score: float
    band: str
    ambiguous: bool
    groups: list[GroupScore] = Field(default_factory=list)
    weight_available: float = 0.0   # suma de pesos de los grupos disponibles
    reasoning: list[str] = Field(default_factory=list)
