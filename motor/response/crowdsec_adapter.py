"""
response/crowdsec_adapter.py — R1: cliente de SOLO LECTURA hacia la LAPI
local de CrowdSec en .139 (bouncer registrado como "r-soar-reader").

Restricción de diseño no negociable (H37): este módulo NUNCA aplica ningún
bloqueo por su cuenta — no importa subprocess, os.system, ni ningún binario
de firewall (iptables/nftables). Solo lee /v1/decisions/stream y traduce las
decisiones de CrowdSec a un formato simple (IP, escenario, duración, tipo)
que el motor puede sumar a su lógica de corroboración — la integración a
`count_corroborating_sources()`/`enrich()` es Fase 3, no implementada
todavía (ver H37 en docs/BITACORA_TECNICA.md).

El único punto de bloqueo real del sistema sigue siendo R2 (Wazuh Active
Response, ver enforcer.py).
"""
from __future__ import annotations

import logging

import httpx

from response.config import ResponseSettings
from response.schemas import CrowdSecDecision

log = logging.getLogger("response.crowdsec")


def fetch_decisions_stream(
    settings: ResponseSettings, startup: bool = False
) -> list[CrowdSecDecision]:
    """
    Consulta GET /v1/decisions/stream de la LAPI local de CrowdSec.

    startup=True pide el dump completo de decisiones activas (uso típico al
    arrancar el proceso); startup=False pide solo el delta de altas/bajas
    desde la última consulta (uso típico en polling periódico).

    Degradación elegante, mismo criterio que enrichment.py (OTX/AbuseIPDB):
    si CrowdSec no está configurado, no responde, o devuelve un error, se
    retorna una lista vacía — nunca lanza excepción hacia arriba.
    """
    if not settings.crowdsec_lapi_url or not settings.crowdsec_api_key:
        log.info("CrowdSec no configurado (lapi_url/api_key faltante) — degradación elegante")
        return []

    url = settings.crowdsec_lapi_url.rstrip("/") + "/v1/decisions/stream"
    try:
        resp = httpx.get(
            url,
            headers={"X-Api-Key": settings.crowdsec_api_key},
            params={"startup": "true" if startup else "false"},
            timeout=settings.crowdsec_timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning(f"CrowdSec LAPI no disponible: {type(e).__name__}: {e}")
        return []

    decisions: list[CrowdSecDecision] = []
    for raw in (payload.get("new") or []):
        try:
            decisions.append(CrowdSecDecision(
                ip=raw["value"],
                scenario=raw.get("scenario", ""),
                duration=raw.get("duration", ""),
                decision_type=raw.get("type", ""),
                origin=raw.get("origin"),
            ))
        except (KeyError, TypeError) as e:
            log.warning(f"decisión de CrowdSec con formato inesperado, omitida: {e}")

    return decisions
