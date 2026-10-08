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
from attck_mapping import ATTACK_FIELDS, attack_fields

from response.config import OWN_INFRA, ResponseSettings
from response.schemas import ActionType, BlockResult

log = logging.getLogger("response.r2")


# ── Contexto de la decisión en el Active Response (H50) ─────────────────────────
def ar_context(trace_id: str, tier: int | str | None, classtype: str | None = None) -> dict[str, str]:
    """Contexto que viaja en alert.data del Active Response de Wazuh.

    Verificado en .139 (H50): la API pasa `alert` tal cual al agente
    (spec.yaml: alert.data es objeto libre; core/active_response.py lo
    serializa sin filtrar), el agente lo escribe en active-responses.log y
    el manager lo convierte en la alerta 651 "Host Blocked by firewall-drop
    Active Response", con el decoder ar_log_json exponiendo cada clave como
    data.parameters.alert.data.<clave>. Así un analista que mira el bloqueo
    en Wazuh puede saltar a soc-decisions/soc-responses por trace_id.

    Args:
        trace_id: trace_id de la decisión que originó el bloqueo.
        tier: tier de la decisión (int, o str si viene de un hash Redis);
            None si el origen no lo conoce.
        classtype: classtype de Suricata, si llegó (H50: hoy nunca llega).

    Returns:
        Diccionario de strings (tipos estables en el índice de alertas de
        Wazuh). Solo claves con valor: trace_id siempre; tier, classtype y
        los campos ATT&CK cuando existen.
    """
    ctx: dict[str, str] = {"trace_id": trace_id}
    if tier is not None:
        ctx["tier"] = str(tier)
    if classtype:
        ctx["classtype"] = classtype
        attck = attack_fields(classtype)
        ctx.update({f: attck[f] for f in ATTACK_FIELDS if attck[f]})
    return ctx


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


_OWN_INFRA_ADDRS = frozenset(ipaddress.ip_address(ip) for ip in OWN_INFRA)


def is_own_infra(ip: str) -> bool:
    """True si la IP es infraestructura propia del SOC (config.OWN_INFRA).

    A diferencia de is_safelisted(), NO exime rangos privados: decide si una
    T2 abre caso (H54), no si se puede bloquear. Compara como dirección, así
    la forma expandida de IPv6 que manda Suricata coincide con la lista.

    Args:
        ip: IP de origen del evento.

    Returns:
        True solo si está en OWN_INFRA. Una IP malformada da False (el caso
        se abre igual, como antes de H54).
    """
    try:
        return ipaddress.ip_address(ip) in _OWN_INFRA_ADDRS
    except ValueError:
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
    def block(self, ip: str, ttl: int, context: dict[str, str] | None = None) -> tuple[bool, str | None]: ...


class DryRunEnforcer:
    """No toca la red. Registra lo que haría. Default seguro."""
    name = "dry_run"

    def block(self, ip: str, ttl: int, context: dict[str, str] | None = None) -> tuple[bool, str | None]:
        """Registra el bloqueo sin ejecutarlo.

        Args:
            ip: IP que se bloquearía.
            ttl: segundos que duraría el bloqueo.
            context: contexto de la decisión (ver ar_context); solo se ignora.

        Returns:
            (False, None): no se bloqueó realmente y no hubo error.
        """
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

    def block(self, ip: str, ttl: int, context: dict[str, str] | None = None) -> tuple[bool, str | None]:
        """Dispara el Active Response sobre `ip`.

        Args:
            ip: IP a bloquear.
            ttl: segundos del bloqueo (lo aplica Wazuh según su config).
            context: contexto de la decisión para alert.data (ver
                ar_context). `srcip` siempre es `ip` y va PRIMERO: el
                contexto no puede pisarlo (es lo que lee firewall-drop), y
                el decoder de fábrica de Wazuh que llena data.srcip en la
                alerta 651 (0010-active-response_decoders.xml, regex
                `"data":{"srcip":"..."`) solo lo encuentra si es la
                primera clave -- con srcip al final, la alerta 651 perdía
                data.srcip (encontrado en producción tras H50).

        Returns:
            (enforced, error): (True, None) si la API aceptó el comando;
            (False, "wazuh_api error: <tipo>") si falló, sin lanzar.
        """
        try:
            token = self._token()
            extra = {k: v for k, v in (context or {}).items() if k != "srcip"}
            body = {
                "command": f"!{self.s.wazuh_ar_command}",
                "alert": {"data": {"srcip": ip, **extra}},
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
    context: dict[str, str] | None = None,
) -> BlockResult:
    """
    Evalúa y (si corresponde) ejecuta el bloqueo de una IP.
    Orden de las salvaguardas: safelist -> idempotencia -> modo -> enforce.

    Args:
        src_ip: IP de origen a bloquear.
        settings: ResponseSettings.
        rdb: cliente Redis (idempotencia/TTL del bloqueo).
        enforcer: backend de bloqueo.
        trace_id: trace_id de la decisión.
        context: contexto para el Active Response (ver ar_context); None
            manda solo trace_id.

    Returns:
        El BlockResult con la acción tomada y su motivo.
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
    enforced, error = enforcer.block(src_ip, settings.block_ttl_seconds,
                                     context or ar_context(trace_id, None))
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
