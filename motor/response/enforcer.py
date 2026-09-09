"""
response/enforcer.py — R2: Acción activa (bloqueo parcial).

Para eventos de tier >= r2_min_tier, R2 bloquea la IP de origen vía firewall,
con TTL y auto-expiración. Diseñado con cuatro salvaguardas defendibles ante
el tribunal como "viabilidad operacional":

  1. SAFELIST — la infraestructura del lab nunca puede bloquearse (config.py).
  2. DRY_RUN  — modo por defecto: registra el bloqueo sin ejecutarlo.
  3. TTL + IDEMPOTENCIA — no re-bloquea; extiende el TTL si la IP reincide.
  4. DEGRADACIÓN — si el enforcer falla, R2 registra el error y NO crashea.

Backends (enforcer_backend):
  - dry_run   : no toca la red. Default seguro. Ideal para demos del semillero.
  - wazuh_api : dispara `firewall-drop` vía Wazuh Active Response (manager .139).
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Protocol

import httpx
import redis

from response.config import ResponseSettings
from response.schemas import ActionType, BlockResult

log = logging.getLogger("response.r2")


# ── Safelist ───────────────────────────────────────────────────────────────────
def is_safelisted(ip: str, settings: ResponseSettings) -> bool:
    """True si la IP no debe bloquearse jamás (infra del lab, loopback, etc.)."""
    if ip in settings.safelist:
        return True
    # Proteger también rangos privados por si entra tráfico interno mal etiquetado.
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
    except ValueError:
        # IP malformada -> por seguridad, no bloquear
        return True
    return False


# ── Tracking de bloqueos activos (idempotencia + TTL) ───────────────────────────
def _block_key(ip: str, settings: ResponseSettings) -> str:
    return f"{settings.blocks_key_prefix}{ip}"


def is_blocked(ip: str, settings: ResponseSettings, rdb: redis.Redis) -> bool:
    try:
        return rdb.exists(_block_key(ip, settings)) == 1
    except redis.RedisError as e:
        log.warning(f"no se pudo verificar estado de bloqueo de {ip}: {e}")
        return False


def _record_block(ip: str, settings: ResponseSettings, rdb: redis.Redis, trace_id: str):
    """Registra el bloqueo en Redis con TTL para auto-expiración e idempotencia."""
    try:
        rdb.setex(_block_key(ip, settings), settings.block_ttl_seconds, trace_id)
    except redis.RedisError as e:
        log.warning(f"no se pudo registrar bloqueo de {ip}: {e}")


# ── Interfaz de enforcer ────────────────────────────────────────────────────────
class Enforcer(Protocol):
    name: str
    def block(self, ip: str, ttl: int) -> tuple[bool, str | None]: ...


class DryRunEnforcer:
    """No toca la red. Registra lo que haría. Default seguro."""
    name = "dry_run"

    def block(self, ip: str, ttl: int) -> tuple[bool, str | None]:
        log.info(f"[DRY_RUN] bloquearía {ip} por {ttl}s (no ejecutado)")
        return False, None  # enforced=False: no se bloqueó realmente


class WazuhAPIEnforcer:
    """
    Dispara Active Response `firewall-drop` vía la API de Wazuh en el manager.
    Wazuh gestiona el iptables/timeout en los agentes; el motor solo orquesta.
    """
    name = "wazuh_api"

    def __init__(self, settings: ResponseSettings):
        self.s = settings

    def _token(self) -> str:
        resp = httpx.post(
            f"{self.s.wazuh_api_url}/security/user/authenticate",
            auth=(self.s.wazuh_api_user, self.s.wazuh_api_password),
            verify=self.s.wazuh_verify_tls,
            timeout=self.s.wazuh_api_timeout,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    def block(self, ip: str, ttl: int) -> tuple[bool, str | None]:
        try:
            token = self._token()
            body = {
                "command": f"!{self.s.wazuh_ar_command}",
                "alert": {"data": {"srcip": ip}},
            }
            params = {}
            agents = self.s.target_agents_list
            if agents != ["all"]:
                params["agents_list"] = ",".join(agents)

            resp = httpx.put(
                f"{self.s.wazuh_api_url}/active-response",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                json=body,
                verify=self.s.wazuh_verify_tls,
                timeout=self.s.wazuh_api_timeout,
            )
            resp.raise_for_status()
            log.info(f"[ENFORCE] firewall-drop disparado sobre {ip} (ttl={ttl}s)")
            return True, None
        except httpx.HTTPError as e:
            log.error(f"Wazuh AR falló para {ip}: {e}")
            return False, f"wazuh_api error: {type(e).__name__}"


def build_enforcer(settings: ResponseSettings) -> Enforcer:
    if settings.enforcer_backend == "wazuh_api" and settings.response_mode == "enforce":
        return WazuhAPIEnforcer(settings)
    return DryRunEnforcer()


# ── Punto de entrada de R2 ──────────────────────────────────────────────────────
def respond_block(
    src_ip: str | None,
    settings: ResponseSettings,
    rdb: redis.Redis,
    enforcer: Enforcer,
    trace_id: str,
) -> BlockResult:
    """
    Evalúa y (si corresponde) ejecuta el bloqueo de una IP.
    Orden de las salvaguardas: safelist -> idempotencia -> modo -> enforce.
    """
    result = BlockResult(src_ip=src_ip, enforcer=enforcer.name,
                         ttl_seconds=settings.block_ttl_seconds)

    if not src_ip:
        result.action = ActionType.BLOCK_SKIPPED
        result.reason = "sin src_ip"
        return result

    # 1) Safelist — barrera dura
    if is_safelisted(src_ip, settings):
        result.action = ActionType.BLOCK_SKIPPED
        result.reason = "safelisted (infra del lab)"
        log.info(f"[R2] {src_ip} en safelist — no se bloquea")
        return result

    # 2) Idempotencia — ya bloqueada
    if is_blocked(src_ip, settings, rdb):
        if settings.block_extend_on_repeat:
            _record_block(src_ip, settings, rdb, trace_id)  # extiende TTL
            result.action = ActionType.BLOCK_SKIPPED
            result.reason = "ya bloqueada — TTL extendido"
        else:
            result.action = ActionType.BLOCK_SKIPPED
            result.reason = "ya bloqueada"
        return result

    # 3) Modo dry_run — registra pero no ejecuta
    if settings.response_mode == "dry_run":
        result.action = ActionType.BLOCK_SKIPPED
        result.reason = "dry_run (no se ejecuta bloqueo real)"
        _record_block(src_ip, settings, rdb, trace_id)  # marca para idempotencia/visibilidad
        log.info(f"[R2][DRY_RUN] bloquearía {src_ip}")
        return result

    # 4) Enforce — ejecuta el bloqueo real
    enforced, error = enforcer.block(src_ip, settings.block_ttl_seconds)
    result.enforced = enforced
    result.error = error
    if enforced:
        result.action = ActionType.BLOCK
        result.reason = "bloqueo ejecutado"
        _record_block(src_ip, settings, rdb, trace_id)
    else:
        result.action = ActionType.BLOCK_SKIPPED
        result.reason = error or "enforcer no ejecutó"
    return result
