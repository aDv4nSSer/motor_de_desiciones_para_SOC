"""
response/enrichment.py — R1: Acción pasiva (enriquecimiento).

Para eventos de tier >= r1_min_tier, agrega contexto al evento SIN actuar
sobre la red:
  - reverse DNS (PTR)
  - reputación AbuseIPDB (con cache Redis para respetar el límite de 900/día)

Principio de degradación elegante: si AbuseIPDB falla o no está configurada,
R1 NO falla — devuelve el enriquecimiento parcial marcando la fuente como
no disponible. R1 nunca debe romper el pipeline de respuesta.
"""
from __future__ import annotations

import json
import logging
import socket
from typing import Optional

import httpx
import redis

from response.config import ResponseSettings
from response.schemas import EnrichmentResult

log = logging.getLogger("response.r1")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _abuseipdb_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis
) -> EnrichmentResult:
    """
    Consulta AbuseIPDB con cache. Devuelve EnrichmentResult parcial.
    Nunca lanza excepción hacia arriba — degradación elegante.
    """
    result = EnrichmentResult(src_ip=ip)

    # Sin API key configurada -> degradación elegante
    if not settings.abuseipdb_api_key:
        result.abuseipdb_available = False
        result.notes.append("abuseipdb_api_key no configurada")
        return result

    cache_key = f"{settings.enrich_cache_prefix}{ip}"

    # 1) Cache hit
    try:
        cached = rdb.get(cache_key)
        if cached:
            data = json.loads(cached)
            result.abuseipdb_score = data.get("score")
            result.abuseipdb_total_reports = data.get("reports")
            result.abuseipdb_country = data.get("country")
            result.cached = True
            return result
    except (redis.RedisError, json.JSONDecodeError) as e:
        log.warning(f"cache read fallida para {ip}: {e}")

    # 2) Cache miss -> consulta API
    try:
        resp = httpx.get(
            ABUSEIPDB_URL,
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=settings.abuseipdb_timeout,
        )
        resp.raise_for_status()
        payload = resp.json().get("data", {})
        result.abuseipdb_score = payload.get("abuseConfidenceScore")
        result.abuseipdb_total_reports = payload.get("totalReports")
        result.abuseipdb_country = payload.get("countryCode")

        # cachear
        try:
            rdb.setex(
                cache_key,
                settings.abuseipdb_cache_ttl,
                json.dumps({
                    "score": result.abuseipdb_score,
                    "reports": result.abuseipdb_total_reports,
                    "country": result.abuseipdb_country,
                }),
            )
        except redis.RedisError as e:
            log.warning(f"cache write fallida para {ip}: {e}")

    except httpx.HTTPStatusError as e:
        result.abuseipdb_available = False
        code = e.response.status_code
        result.notes.append(f"abuseipdb HTTP {code}")
        if code == 429:
            log.warning("AbuseIPDB rate limit (900/día) alcanzado")
    except (httpx.HTTPError, ValueError) as e:
        result.abuseipdb_available = False
        result.notes.append(f"abuseipdb error: {type(e).__name__}")
        log.warning(f"AbuseIPDB no disponible para {ip}: {e}")

    return result


def enrich(
    src_ip: Optional[str], settings: ResponseSettings, rdb: redis.Redis
) -> EnrichmentResult:
    """
    Punto de entrada de R1. Enriquece una IP de origen con DNS + reputación.
    Siempre devuelve un EnrichmentResult, nunca lanza excepción.
    """
    if not src_ip:
        r = EnrichmentResult()
        r.notes.append("sin src_ip")
        return r

    result = _abuseipdb_lookup(src_ip, settings, rdb)
    result.reverse_dns = _reverse_dns(src_ip)
    return result
