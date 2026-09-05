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

import ipaddress
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
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _is_public_ip(ip: str) -> bool:
    """
    True solo si `ip` es una dirección enrutable públicamente. Una IP
    privada/loopback/link-local nunca puede tener reputación real en TI
    externa — consultarla desperdicia cuota y, en el caso de OTX, el
    endpoint la rechaza con HTTP 400 (ver hallazgo de continuación de H23:
    tras la migración a NAT/VLANs, `src_ip` en el Fast Path puede llegar
    como IP interna, ej. `10.10.10.3`/`10.30.30.2`).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def _abuseipdb_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis
) -> EnrichmentResult:
    """
    Consulta AbuseIPDB con cache. Devuelve EnrichmentResult parcial.
    Nunca lanza excepción hacia arriba — degradación elegante.
    """
    result = EnrichmentResult(src_ip=ip)

    if not _is_public_ip(ip):
        result.abuseipdb_available = False
        result.notes.append("abuseipdb: IP no pública, TI externa no aplica")
        return result

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


def _otx_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis
) -> EnrichmentResult:
    """
    Consulta OTX/AlienVault con cache. Devuelve EnrichmentResult parcial.
    Nunca lanza excepción hacia arriba — degradación elegante.
    """
    result = EnrichmentResult(src_ip=ip)

    if not _is_public_ip(ip):
        result.otx_available = False
        result.notes.append("otx: IP no pública, TI externa no aplica")
        return result

    # Sin API key configurada -> degradación elegante
    if not settings.otx_api_key:
        result.otx_available = False
        result.notes.append("otx_api_key no configurada")
        return result

    cache_key = f"{settings.enrich_cache_prefix}otx:{ip}"

    # 1) Cache hit
    try:
        cached = rdb.get(cache_key)
        if cached:
            data = json.loads(cached)
            result.otx_pulse_count = data.get("pulse_count")
            result.cached = True
            return result
    except (redis.RedisError, json.JSONDecodeError) as e:
        log.warning(f"cache read fallida (otx) para {ip}: {e}")

    # 2) Cache miss -> consulta API
    try:
        resp = httpx.get(
            OTX_URL.format(ip=ip),
            headers={"X-OTX-API-KEY": settings.otx_api_key},
            timeout=settings.otx_timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        result.otx_pulse_count = payload.get("pulse_info", {}).get("count")

        # cachear
        try:
            rdb.setex(
                cache_key,
                settings.otx_cache_ttl,
                json.dumps({"pulse_count": result.otx_pulse_count}),
            )
        except redis.RedisError as e:
            log.warning(f"cache write fallida (otx) para {ip}: {e}")

    except httpx.HTTPStatusError as e:
        result.otx_available = False
        code = e.response.status_code
        result.notes.append(f"otx HTTP {code}")
    except (httpx.HTTPError, ValueError) as e:
        result.otx_available = False
        result.notes.append(f"otx error: {type(e).__name__}")
        log.warning(f"OTX no disponible para {ip}: {e}")

    return result


def count_corroborating_sources(
    result: EnrichmentResult, settings: ResponseSettings
) -> tuple[int, list[str]]:
    """
    Cuenta cuántas fuentes de R1 corroboran, de forma independiente, que la
    IP es maliciosa — es el insumo real que R2 usa para decidir entre
    bloqueo automático y aprobación humana (ver worker.py y sección 4 de
    `especificacion_tecnica_final_r-soar.md`).

    Criterio por fuente (umbrales en ResponseSettings, no hardcodeados):
      - AbuseIPDB: abuseConfidenceScore >= abuseipdb_malicious_threshold.
      - OTX: pulse_count >= otx_min_pulse_count (un pulse ya es un reporte
        comunitario curado por analistas, no autogenerado — distinto del
        conteo de reportes de AbuseIPDB, que sí necesita umbral numérico
        para filtrar ruido).

    Una fuente NO disponible (sin API key, timeout, error HTTP, cuota
    agotada) no cuenta ni a favor ni en contra — mismo criterio de
    degradación elegante que el resto de R1. Ausencia de dato no es
    evidencia de nada.
    """
    sources: list[str] = []

    if result.abuseipdb_available and result.abuseipdb_score is not None:
        if result.abuseipdb_score >= settings.abuseipdb_malicious_threshold:
            sources.append("abuseipdb")

    if result.otx_available and result.otx_pulse_count is not None:
        if result.otx_pulse_count >= settings.otx_min_pulse_count:
            sources.append("otx")

    return len(sources), sources


def enrich(
    src_ip: Optional[str], settings: ResponseSettings, rdb: redis.Redis
) -> EnrichmentResult:
    """
    Punto de entrada de R1. Enriquece una IP de origen con DNS + reputación
    (AbuseIPDB + OTX/AlienVault) y calcula la corroboración multi-fuente que
    consume R2 (ver `count_corroborating_sources`).
    Siempre devuelve un EnrichmentResult, nunca lanza excepción.
    """
    if not src_ip:
        r = EnrichmentResult()
        r.notes.append("sin src_ip")
        return r

    result = _abuseipdb_lookup(src_ip, settings, rdb)
    otx_result = _otx_lookup(src_ip, settings, rdb)
    result.otx_pulse_count = otx_result.otx_pulse_count
    result.otx_available = otx_result.otx_available
    result.notes.extend(otx_result.notes)
    result.cached = result.cached or otx_result.cached
    result.reverse_dns = _reverse_dns(src_ip)

    count, names = count_corroborating_sources(result, settings)
    result.corroboration_count = count
    result.corroborating_sources = names
    return result
