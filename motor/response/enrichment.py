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
import ssl
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import redis

from attck_mapping import AttckMappingLoadError, lookup
from constants import (
    ABUSEIPDB_NON_DECISIVE_SHARE,
    ABUSEIPDB_RATE_KEY_PREFIX,
    ABUSEIPDB_RATE_WINDOW_SECONDS,
    ALERT_CORRELATION_LOOKAHEAD_SECONDS,
    ALERT_CORRELATION_LOOKBACK_SECONDS,
    ALERT_LOOKUP_CONNECT_TIMEOUT_SECONDS,
    ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS,
    ALERT_LOOKUP_READ_TIMEOUT_SECONDS,
    SECONDS_PER_DAY,
    SURICATA_ALERTS_INDEX_PATTERN,
    T3_CLASSTYPES,
)
from response.config import ResponseSettings
from response.crowdsec_adapter import fetch_decisions_stream
from response.schemas import AlertLookupResult, AlertMatch, EnrichmentResult

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


STALE_NOTE = "no disponible (evento stale, solo caché)"


QUOTA_MIN_SECONDS = 60
QUOTA_MAX_SECONDS = 86400


def _neg_key(settings: ResponseSettings, provider: str, ip: str) -> str:
    return f"{settings.enrich_cache_prefix}neg:{provider}:{ip}"


def _abuseipdb_quota_key(settings: ResponseSettings) -> str:
    return f"{settings.enrich_cache_prefix}abuseipdb:quota_exhausted"


def _negative_reason(rdb: redis.Redis, key: str) -> Optional[str]:
    """Motivo cacheado de un fallo reciente, o None. Un error de Redis acá
    no bloquea: se sigue como si no hubiera negative cache."""
    try:
        raw = rdb.get(key)
    except redis.RedisError as e:
        log.warning(f"negative cache no legible ({key}): {e}")
        return None
    return raw if raw else None


def _set_negative(rdb: redis.Redis, key: str, ttl: int, reason: str) -> None:
    try:
        rdb.setex(key, ttl, reason)
    except redis.RedisError as e:
        log.warning(f"negative cache no escribible ({key}): {e}")


def quota_reset_seconds(resp: httpx.Response, now: float | None = None) -> int:
    """Segundos hasta que se repone la cuota de AbuseIPDB tras un 429:
    Retry-After; si falta, X-RateLimit-Reset (epoch); si falta, la próxima
    medianoche UTC. Acotado a [1 min, 24 h]."""
    now = now if now is not None else time.time()
    seconds: float | None = None
    try:
        seconds = float(resp.headers["Retry-After"])
    except (KeyError, ValueError):
        try:
            seconds = float(resp.headers["X-RateLimit-Reset"]) - now
        except (KeyError, ValueError):
            today = datetime.fromtimestamp(now, timezone.utc).date()
            midnight = datetime.combine(today + timedelta(days=1), datetime.min.time(), timezone.utc)
            seconds = midnight.timestamp() - now
    return int(min(QUOTA_MAX_SECONDS, max(QUOTA_MIN_SECONDS, seconds)))


def abuseipdb_window_budget(settings: ResponseSettings) -> int:
    """Consultas a la API de AbuseIPDB permitidas por ventana del token
    bucket, derivadas de la cuota diaria configurada (ver constants.py)."""
    return max(1, (settings.abuseipdb_daily_quota * ABUSEIPDB_RATE_WINDOW_SECONDS) // SECONDS_PER_DAY)


def _abuseipdb_rate_key(now: float) -> str:
    start = int(now // ABUSEIPDB_RATE_WINDOW_SECONDS) * ABUSEIPDB_RATE_WINDOW_SECONDS
    return f"{ABUSEIPDB_RATE_KEY_PREFIX}{start}"


def _take_abuseipdb_token(
    rdb: redis.Redis, settings: ResponseSettings, decisive: bool, now: float,
) -> str | None:
    """Intenta gastar un cupo de la ventana actual del token bucket.

    Las consultas decisivas (OTX corrobora, AbuseIPDB puede llevar count de
    1 a 2) pueden usar todo el presupuesto de la ventana; las no decisivas
    solo la fracción ABUSEIPDB_NON_DECISIVE_SHARE, para dejar cupo reservado
    a las que pueden cambiar la decisión de R2.

    Returns:
        None si hay cupo (y lo consume); si no, el motivo para la nota de
        auditoría. Si Redis falla, no consulta: proteger la cuota es más
        barato que un 429 que corta la fuente hasta el día siguiente.
    """
    budget = abuseipdb_window_budget(settings)
    limit = budget if decisive else int(budget * ABUSEIPDB_NON_DECISIVE_SHARE)
    key = _abuseipdb_rate_key(now)
    try:
        used = int(rdb.get(key) or 0)
        if used >= limit:
            kind = "presupuesto de la ventana agotado" if decisive else "cupo no decisivo de la ventana agotado"
            return f"{kind} ({used}/{budget} en {ABUSEIPDB_RATE_WINDOW_SECONDS}s)"
        rdb.incr(key)
        rdb.expire(key, 2 * ABUSEIPDB_RATE_WINDOW_SECONDS)
        return None
    except (redis.RedisError, ValueError, TypeError) as e:
        log.warning(f"token bucket de AbuseIPDB no disponible, sin consultar: {type(e).__name__}")
        return "token bucket no disponible (Redis)"


def _abuseipdb_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis, cache_only: bool = False,
    decisive: bool = True, now: float | None = None,
) -> EnrichmentResult:
    """
    Consulta AbuseIPDB con cache. Devuelve EnrichmentResult parcial.
    Nunca lanza excepción hacia arriba — degradación elegante.

    La consulta a la API (no la caché) gasta un cupo del token bucket
    (H52): sin cupo se omite para ESTE evento, sin esperar ni reintentar.
    `decisive` = OTX ya corrobora, así que AbuseIPDB puede cambiar la
    decisión de R2 (ver _take_abuseipdb_token).
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

    # 2) Cuota de la cuenta agotada: corte global hasta el reset (no por IP)
    quota = _negative_reason(rdb, _abuseipdb_quota_key(settings))
    if quota:
        result.abuseipdb_available = False
        result.notes.append("abuseipdb: cuota diaria agotada, sin consultar hasta el reset")
        return result

    # 3) Fallo reciente para esta IP (negative cache)
    neg = _negative_reason(rdb, _neg_key(settings, "abuseipdb", ip))
    if neg:
        result.abuseipdb_available = False
        result.notes.append(f"abuseipdb no disponible (negative cache: {neg})")
        return result

    # 4) Evento stale (H38): solo caché, sin gastar cuota de API en tiempo real
    if cache_only:
        result.abuseipdb_available = False
        result.notes.append(f"abuseipdb {STALE_NOTE}")
        return result

    # 5) Token bucket (H52): reparto de la cuota diaria. Nota distinta de
    # "cuota agotada" (429) y de un timeout, para poder separarlas al revisar
    # el período de sombra.
    throttled = _take_abuseipdb_token(rdb, settings, decisive, time.time() if now is None else now)
    if throttled:
        result.abuseipdb_available = False
        result.notes.append(f"abuseipdb: omitido por throttling ({throttled})")
        return result

    # 6) Consulta API
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
            wait = quota_reset_seconds(e.response)
            _set_negative(rdb, _abuseipdb_quota_key(settings), wait, "HTTP 429")
            log.warning(f"AbuseIPDB cuota agotada: sin consultas por {wait}s")
        else:
            _set_negative(rdb, _neg_key(settings, "abuseipdb", ip), settings.ti_negative_cache_ttl, f"HTTP {code}")
    except (httpx.HTTPError, ValueError) as e:
        result.abuseipdb_available = False
        result.notes.append(f"abuseipdb error: {type(e).__name__}")
        _set_negative(rdb, _neg_key(settings, "abuseipdb", ip), settings.ti_negative_cache_ttl, type(e).__name__)
        log.warning(f"AbuseIPDB no disponible para {ip}: {e}")

    return result


def _otx_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis, cache_only: bool = False,
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

    # 2) Fallo reciente para esta IP (negative cache)
    neg = _negative_reason(rdb, _neg_key(settings, "otx", ip))
    if neg:
        result.otx_available = False
        result.notes.append(f"otx no disponible (negative cache: {neg})")
        return result

    # 3) Evento stale (H38): solo caché
    if cache_only:
        result.otx_available = False
        result.notes.append(f"otx {STALE_NOTE}")
        return result

    # 4) Consulta API
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
        _set_negative(rdb, _neg_key(settings, "otx", ip), settings.ti_negative_cache_ttl, f"HTTP {code}")
    except (httpx.HTTPError, ValueError) as e:
        result.otx_available = False
        result.notes.append(f"otx error: {type(e).__name__}")
        _set_negative(rdb, _neg_key(settings, "otx", ip), settings.ti_negative_cache_ttl, type(e).__name__)
        log.warning(f"OTX no disponible para {ip}: {e}")

    return result


def _crowdsec_lookup(
    ip: str, settings: ResponseSettings, rdb: redis.Redis, cache_only: bool = False,
) -> EnrichmentResult:
    """
    H37 Fase 3: consulta si `ip` tiene una decisión activa de CrowdSec.

    SOLO OBSERVACIONAL — deliberadamente NO participa en
    count_corroborating_sources() ni en la acción recomendada de R2. No hay
    evidencia todavía de cuánta señal nueva aporta CrowdSec en este entorno
    (0 alertas agregadas en la ventana de validación de Fase 1) — se
    acumula visibilidad en soc-decisions para decidir con datos reales más
    adelante (recordatorio en PLAN_SPRINTS.md), no se le da peso a ciegas.

    Cachea la lista completa de decisiones activas en Redis (TTL corto,
    `crowdsec_cache_ttl` — las decisiones cambian mucho más rápido que una
    reputación agregada) en vez de pedir el stream completo en cada evento.
    Nunca lanza excepción hacia arriba — degradación elegante, mismo
    criterio que AbuseIPDB/OTX.
    """
    result = EnrichmentResult(src_ip=ip)

    # H38: la caché de decisiones pesa ~2.8 MiB (23.804 entradas) y se
    # deserializaba entera en cada tarea, incluidas las de IP interna (64%
    # de las tareas): una IP no pública no se busca.
    if not _is_public_ip(ip):
        result.notes.append("crowdsec: IP no pública, no se consulta")
        return result

    if not settings.crowdsec_lapi_url or not settings.crowdsec_api_key:
        result.notes.append("crowdsec: lapi_url/api_key no configurada")
        return result

    cache_key = f"{settings.enrich_cache_prefix}crowdsec:decisions"
    decisions_raw: list[dict] = []
    try:
        cached = rdb.get(cache_key)
        if cached:
            decisions_raw = json.loads(cached)
        elif cache_only:
            result.notes.append(f"crowdsec {STALE_NOTE}")
        else:
            fresh = fetch_decisions_stream(settings, startup=True)
            decisions_raw = [d.model_dump() for d in fresh]
            try:
                rdb.setex(cache_key, settings.crowdsec_cache_ttl, json.dumps(decisions_raw))
            except redis.RedisError as e:
                log.warning(f"cache write fallida (crowdsec) para {ip}: {e}")
    except (redis.RedisError, json.JSONDecodeError) as e:
        result.notes.append(f"crowdsec cache error: {type(e).__name__}")
        log.warning(f"CrowdSec cache no disponible: {e}")

    for d in decisions_raw:
        if d.get("ip") == ip:
            result.crowdsec_observado = True
            result.crowdsec_scenario = d.get("scenario")
            result.crowdsec_duration = d.get("duration")
            break

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
    src_ip: Optional[str], settings: ResponseSettings, rdb: redis.Redis, cache_only: bool = False,
) -> EnrichmentResult:
    """
    Punto de entrada de R1. Enriquece una IP de origen con DNS + reputación
    (AbuseIPDB + OTX/AlienVault) y calcula la corroboración multi-fuente que
    consume R2 (ver `count_corroborating_sources`).
    Siempre devuelve un EnrichmentResult, nunca lanza excepción.

    cache_only (H38, tareas stale del backlog): usa solo lo cacheado
    (positivo, negativo, cuota, decisiones de CrowdSec); no llama APIs de TI,
    no refresca CrowdSec ni resuelve DNS. Lo que falte queda "no disponible
    (evento stale)": una detección que no va a ejecutar ninguna acción no
    gasta cuota de API en tiempo real.
    """
    if not src_ip:
        r = EnrichmentResult()
        r.notes.append("sin src_ip")
        return r

    # OTX primero (H52): sin cuota diaria conocida que se agote, y su
    # resultado define si un cupo de AbuseIPDB es decisivo. Con el gate
    # vigente (count >= 2) solo puede cambiar la decisión de R2 una consulta
    # a AbuseIPDB sobre una IP que OTX ya corrobora.
    otx_result = _otx_lookup(src_ip, settings, rdb, cache_only)
    decisive = bool(
        otx_result.otx_available and otx_result.otx_pulse_count is not None
        and otx_result.otx_pulse_count >= settings.otx_min_pulse_count
    )
    result = _abuseipdb_lookup(src_ip, settings, rdb, cache_only, decisive=decisive)
    result.otx_pulse_count = otx_result.otx_pulse_count
    result.otx_available = otx_result.otx_available
    result.notes.extend(otx_result.notes)
    result.cached = result.cached or otx_result.cached
    result.reverse_dns = None if cache_only else _reverse_dns(src_ip)

    # H37 Fase 3: CrowdSec, solo observacional -- se calcula DESPUÉS de
    # count_corroborating_sources() para que quede explícito en la lectura
    # del código que no influye en ese conteo (ver _crowdsec_lookup).
    crowdsec_result = _crowdsec_lookup(src_ip, settings, rdb, cache_only)
    result.crowdsec_observado = crowdsec_result.crowdsec_observado
    result.crowdsec_scenario = crowdsec_result.crowdsec_scenario
    result.crowdsec_duration = crowdsec_result.crowdsec_duration
    result.notes.extend(crowdsec_result.notes)

    count, names = count_corroborating_sources(result, settings)
    result.corroboration_count = count
    result.corroborating_sources = names
    return result


# ── Correlación con alertas de Suricata (grupo `signature`, H53) ────────────
# El Fast Path solo recibe flows (H50): el classtype no llega al motor. El
# worker lo busca en suricata-alerts-* (Vector -> OpenSearch .140), fuera del
# camino crítico. Correlación en el motor, no en Vector (CLAUDE.md).
# httpx.Client sync a propósito: el worker es un loop sync sin event loop,
# misma excepción consciente que response_audit_indexer.py (H41).

_alerts_client: httpx.Client | None = None
_alerts_unavailable_until: float = 0.0


def _get_alerts_client(settings: ResponseSettings) -> httpx.Client:
    """Cliente OpenSearch reutilizable, con timeout explícito corto."""
    global _alerts_client
    if _alerts_client is None:
        verify: bool | ssl.SSLContext = True
        if not settings.os_verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            verify = ctx
        _alerts_client = httpx.Client(
            base_url=settings.os_host, auth=(settings.os_user, settings.os_pass), verify=verify,
            timeout=httpx.Timeout(ALERT_LOOKUP_READ_TIMEOUT_SECONDS,
                                  connect=ALERT_LOOKUP_CONNECT_TIMEOUT_SECONDS),
        )
    return _alerts_client


def build_alert_query(src_ip: str, dst_ip: str, dst_port: int, event_ts: float) -> dict:
    """DSL de la correlación flow -> alerta (objeto, nunca f-strings: los
    valores entran como términos ya validados por el llamador).

    3-tupla en cualquiera de los dos sentidos (la firma puede describir la
    respuesta del servidor) dentro de la ventana asimétrica de constants.py.
    Prioriza la alerta más severa (severity 1 = máxima) y, a igualdad, la
    más reciente.
    """
    lo = int((event_ts - ALERT_CORRELATION_LOOKBACK_SECONDS) * 1000)
    hi = int((event_ts + ALERT_CORRELATION_LOOKAHEAD_SECONDS) * 1000)
    return {
        "size": 1,
        "sort": [{"severity": {"order": "asc"}}, {"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "category", "signature", "signature_id", "severity"],
        "query": {"bool": {
            "filter": [{"range": {"timestamp": {"gte": lo, "lte": hi, "format": "epoch_millis"}}}],
            "should": [
                {"bool": {"filter": [{"term": {"src_ip.keyword": src_ip}},
                                     {"term": {"dest_ip.keyword": dst_ip}},
                                     {"term": {"dest_port": dst_port}}]}},
                {"bool": {"filter": [{"term": {"src_ip.keyword": dst_ip}},
                                     {"term": {"dest_ip.keyword": src_ip}},
                                     {"term": {"src_port": dst_port}}]}},
            ],
            "minimum_should_match": 1,
        }},
    }


def alert_match_from_source(src: dict) -> AlertMatch | None:
    """Arma el AlertMatch desde el _source de la alerta. `category` trae la
    descripción del classtype: se resuelve a nombre corto con
    classtype_attack.yaml (que indexa nombre y descripción)."""
    category = str(src.get("category") or "").strip()
    if not category:
        return None
    try:
        entry = lookup(category)
    except AttckMappingLoadError as e:
        log.error(f"mapeo ATT&CK no disponible, alerta sin resolver: {e}")
        entry = None
    classtype = entry.classtype if entry else category.lower()
    return AlertMatch(
        category=category,
        classtype=classtype,
        classtype_override=classtype in T3_CLASSTYPES,
        attack_mapped=bool(entry and entry.technique_id),
        attack_technique_id=entry.technique_id if entry else None,
        signature=src.get("signature"),
        signature_id=src.get("signature_id"),
        severity=src.get("severity"),
        alert_timestamp=src.get("timestamp"),
    )


def lookup_suricata_alert(
    src_ip: str | None, dst_ip: str | None, dst_port: int, event_ts: float,
    settings: ResponseSettings, client: httpx.Client | None = None, now: float | None = None,
) -> AlertLookupResult:
    """Busca en suricata-alerts-* una alerta de Suricata para el evento.

    Nunca lanza (degradación con gracia, mismo criterio que la TI): ante
    error o timeout de OpenSearch devuelve status "unavailable", loguea un
    WARNING y no vuelve a consultar durante
    ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS (el worker va justo de capacidad).

    Args:
        src_ip, dst_ip, dst_port: 3-tupla del flow (ResponseTask no trae
            src_port ni protocolo).
        event_ts: epoch en que el flow llegó al motor (task.ts).
        settings: ResponseSettings (credenciales de OpenSearch).
        client: cliente inyectable para tests.
        now: epoch actual, inyectable para tests del cooldown.

    Returns:
        AlertLookupResult con status "match" (y la alerta), "no_match",
        "unavailable" o "skipped" (entrada inválida, no se consultó).
    """
    global _alerts_unavailable_until
    now = time.time() if now is None else now
    try:
        src = str(ipaddress.ip_address(src_ip or ""))
        dst = str(ipaddress.ip_address(dst_ip or ""))
        port = int(dst_port)
        if not 0 <= port <= 65535:
            raise ValueError("puerto fuera de rango")
    except (ValueError, TypeError):
        return AlertLookupResult(status="skipped")
    if now < _alerts_unavailable_until:
        return AlertLookupResult(status="unavailable")

    try:
        http = client or _get_alerts_client(settings)
        r = http.post(f"/{SURICATA_ALERTS_INDEX_PATTERN}/_search",
                      json=build_alert_query(src, dst, port, event_ts))
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
    except (httpx.HTTPError, ValueError) as e:
        _alerts_unavailable_until = now + ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS
        log.warning("alert_lookup_unavailable error=%s detail=%s cooldown_s=%d",
                    type(e).__name__, str(e)[:120], ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS)
        return AlertLookupResult(status="unavailable")

    match = alert_match_from_source(hits[0].get("_source", {})) if hits else None
    return AlertLookupResult(status="match" if match else "no_match", match=match)
