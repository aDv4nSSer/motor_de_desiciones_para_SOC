"""
response/config.py — Configuración de la capa de respuesta.

Todos los secretos y parámetros operacionales vienen de variables de entorno
(.env), respetando CLAUDE.md: nunca hardcodear credenciales.

REGLA DE ORO DE LA SAFELIST:
    La infraestructura del laboratorio NUNCA debe poder ser bloqueada por R2.
    Bloquear tu propio gateway, sensor, o sesión SSH de admin en mitad de una
    demo es el peor fallo posible de un SOAR. La safelist es la red de seguridad.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from response.schemas import ResponseMode


# IPs de la infraestructura del lab — NUNCA bloquear (subred 200.54.12.136/29).
# Se puede ampliar vía env RESPONSE_SAFELIST_EXTRA (coma-separada).
DEFAULT_SAFELIST: set[str] = {
    "200.54.12.137",   # Cisco 892FSP — gateway (Telefónica)
    "200.54.12.138",   # Gen9 A — web server
    "200.54.12.139",   # Gen10 — sensor / SOC
    "200.54.12.140",   # Lenovo — motor / ML (este host)
    "200.54.12.141",   # NO USAR — pero igual nunca bloquear
    "200.54.12.142",   # Gen9 B — sin asignar
    "127.0.0.1",
    "::1",
}


class ResponseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Modo de operación ──────────────────────────────────────────────
    # dry_run = registra lo que haría, NO bloquea. Default SEGURO.
    response_mode: ResponseMode = ResponseMode.DRY_RUN

    # ── Umbrales de disparo ────────────────────────────────────────────
    r1_min_tier: int = 1   # R1 (enrich) dispara desde T1
    r2_min_tier: int = 2   # R2 (block)  dispara desde T2

    # ── Cola Redis ─────────────────────────────────────────────────────
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    response_stream: str = "soc:response:tasks"
    response_group: str = "response-workers"
    response_consumer: str = "worker-1"
    blocks_key_prefix: str = "soc:blocks:"        # soc:blocks:<ip> con TTL
    enrich_cache_prefix: str = "soc:enrich:"      # cache AbuseIPDB por IP

    # ── R2: parámetros de bloqueo ──────────────────────────────────────
    block_ttl_seconds: int = 1800        # 30 min — alineado con Wazuh AR timeout
    block_extend_on_repeat: bool = True  # si re-ataca, extender TTL en vez de re-bloquear

    # ── R1: AbuseIPDB ──────────────────────────────────────────────────
    abuseipdb_api_key: str = ""          # OBLIGATORIO rotar (estuvo expuesta)
    abuseipdb_cache_ttl: int = 21600     # 6h — respeta límite 900 req/día
    abuseipdb_timeout: float = 4.0

    # ── R2: enforcer Wazuh API ─────────────────────────────────────────
    enforcer_backend: str = "dry_run"    # dry_run | wazuh_api
    wazuh_api_url: str = "https://200.54.12.139:55000"
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_ar_command: str = "firewall-drop"
    wazuh_target_agents: str = "all"     # "all" o lista coma-separada de agent IDs
    wazuh_api_timeout: float = 6.0
    wazuh_verify_tls: bool = False       # cert self-signed en el lab

    # ── Safelist extra (coma-separada) ─────────────────────────────────
    response_safelist_extra: str = ""

    @property
    def safelist(self) -> set[str]:
        extra = {
            ip.strip() for ip in self.response_safelist_extra.split(",") if ip.strip()
        }
        return DEFAULT_SAFELIST | extra

    @property
    def target_agents_list(self) -> list[str]:
        if self.wazuh_target_agents.strip().lower() == "all":
            return ["all"]
        return [a.strip() for a in self.wazuh_target_agents.split(",") if a.strip()]


@lru_cache
def get_settings() -> ResponseSettings:
    return ResponseSettings()
