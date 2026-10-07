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
    r2_min_tier: int = 3   # R2 (block)  dispara solo desde T3 (sección 4 de la
                           # especificación: bloqueo automático es exclusivo de T3;
                           # T2 solo alerta y crea caso — ver H29 en BITACORA_TECNICA.md)

    # ── Cola Redis ─────────────────────────────────────────────────────
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    # Continuación de H30: enqueue_response_task() se llama de forma síncrona
    # desde el Fast Path (main.py) en cada request — sin timeout, un Redis
    # lento bloquea el único event loop de uvicorn indefinidamente.
    redis_socket_timeout: float = 1.0
    redis_socket_connect_timeout: float = 1.0
    response_stream: str = "soc:response:tasks"
    response_group: str = "response-workers"
    response_consumer: str = "worker-1"
    blocks_key_prefix: str = "soc:blocks:"        # soc:blocks:<ip> con TTL
    enrich_cache_prefix: str = "soc:enrich:"      # cache AbuseIPDB por IP

    # ── Frescura de tareas (H38) ───────────────────────────────────────
    # Una tarea cuya detección original (task.ts, encolado por el Fast Path)
    # tiene más de esta antigüedad completa R1 y se audita con su
    # accion_recomendada, pero NO ejecuta bloqueo ni abre aprobación/caso:
    # actuar horas después de la detección (backlog de H38) no es respuesta.
    stale_event_max_age_seconds: int = 3600

    # ── Aprobaciones humanas (H38) ─────────────────────────────────────
    approval_ttl_seconds: int = 14400            # 4 h sin resolver -> expired
    approval_sweep_interval_seconds: int = 60    # barrido de expiración en el worker

    # ── R2: parámetros de bloqueo ──────────────────────────────────────
    block_ttl_seconds: int = 1800        # 30 min — alineado con Wazuh AR timeout
    block_extend_on_repeat: bool = True  # si re-ataca, extender TTL en vez de re-bloquear

    # ── R1: AbuseIPDB ──────────────────────────────────────────────────
    abuseipdb_api_key: str = ""          # OBLIGATORIO rotar (estuvo expuesta)
    abuseipdb_cache_ttl: int = 21600     # 6h — respeta límite 900 req/día
    abuseipdb_timeout: float = 4.0

    # ── R1: OTX/AlienVault ───────────────────────────────────────────────
    otx_api_key: str = ""
    otx_cache_ttl: int = 21600           # 6h — mismo criterio que AbuseIPDB
    otx_timeout: float = 4.0

    # ── R1: negative caching de TI (H38, "negative caching obligatorio") ─
    # Un fallo de red/HTTP de AbuseIPDB u OTX se cachea por IP este tiempo:
    # sin esto, cada tarea de la misma IP volvía a pagar el timeout de 4 s
    # (~61% del tiempo del worker en H38). El 429 de cuota de AbuseIPDB no es
    # por IP: corta la fuente entera hasta el reset (Retry-After).
    ti_negative_cache_ttl: int = 600

    # ── R1: CrowdSec (H37) — bouncer de SOLO LECTURA "r-soar-reader" ────
    # LAPI corre en .139 (agente local, colección crowdsecurity/suricata),
    # bindeada solo en la interfaz de VLAN10 (10.10.10.1:8081) para que este
    # host (.140) pueda alcanzarla sin exponerla en la IP pública ni otras
    # VLANs. Ver H37 en docs/BITACORA_TECNICA.md.
    crowdsec_lapi_url: str = ""
    crowdsec_api_key: str = ""
    crowdsec_timeout: float = 4.0
    # TTL corto (5 min, no 6h como AbuseIPDB/OTX): las decisiones de
    # CrowdSec son mucho más dinámicas (expiran en horas, se revocan) que
    # una reputación agregada — un cache largo mostraría un "observado"
    # ya vencido como si siguiera activo.
    crowdsec_cache_ttl: int = 300

    # ── R1: corroboración multi-fuente (gate real de R2, ver enrichment.py) ─
    # Umbral de "hallazgo malicioso corroborado" por fuente. Una fuente no
    # disponible (timeout/sin key/cuota) no cuenta ni a favor ni en contra.
    abuseipdb_malicious_threshold: int = 50   # abuseConfidenceScore 0-100
    otx_min_pulse_count: int = 1              # >=1 pulse ya es reporte comunitario curado
    # 2+ fuentes corroborando -> bloqueo automático (tabla sección 4 de la
    # especificación). Con menos, R2 no ejecuta: queda como pendiente de
    # aprobación humana (Operador N1+).
    # TODO(corroboración ponderada, 7-oct-2026): reemplazado como gate real
    # de R2 por `motor/scoring/corroboration.py` (bandas sobre `score`, ver
    # abajo). Se deja esta constante sin borrar porque los tests y el gate
    # anterior la siguen usando hasta que se apruebe wirear el reemplazo en
    # worker.py -- ver reports/Corroboracion ponderada para respuesta
    # autonoma SOAR.md.
    min_corroborating_sources_for_autoblock: int = 2

    # ── Score de corroboración ponderado (motor/scoring/corroboration.py) ──
    # Pesos máximos por grupo de evidencia, suman 100. Un grupo no
    # disponible para un evento (ver GroupScore.available) se excluye del
    # denominador de la normalización -- no se cuenta como 0. Pesos
    # iniciales según reports/Corroboracion ponderada para respuesta
    # autonoma SOAR.md (firma/ATT&CK > TI externa > ML ~= contexto), sujetos
    # a recalibración con datos reales de producción (soc-feedback).
    corr_weight_signature: float = 35.0   # classtype crítico + ATT&CK
    corr_weight_ti: float = 25.0          # AbuseIPDB + OTX (fusión sub-lineal)
    corr_weight_ml: float = 20.0          # risk_score (LightGBM + IsolationForest)
    corr_weight_context: float = 20.0     # recidivismo (H53, acumulador Redis por IP);
                                           # kill-chain todavía no instrumentado.

    # Bandas de decisión sobre el score renormalizado 0-100 (ver
    # CorroborationResult.band). Alineadas a T0-T3 de motor/model.py:tier(),
    # pero el GATE de autoblock en R2 es band=="high", no el tier solo.
    corr_band_low_max: float = 39.0        # <= esto: band "low"
    corr_band_medium_max: float = 69.0     # <= esto: band "medium"
    # > corr_band_medium_max y sin desacuerdo entre grupos: band "high"
    # (autoblock elegible). No hay techo superior -- la ambigüedad viene
    # SOLO del desacuerdo entre grupos (ver corr_disagreement_threshold),
    # nunca de que el score sea "demasiado alto". Referencia documental de
    # dónde empieza "alta confianza" para dashboards/reasoning.
    corr_band_high_max_reference: float = 84.0

    # Si el grupo de mayor score disponible y el de menor score disponible
    # (entre los que tienen peso >= corr_min_weight_for_disagreement)
    # difieren más que esto, el evento se marca `ambiguous` sin importar el
    # score agregado -- un C=75 por consenso no es lo mismo que un C=75 por
    # un grupo en 1.0 contra otro en 0.0 (ver corroboration.py).
    corr_disagreement_threshold: float = 0.6
    corr_min_weight_for_disagreement: float = 15.0

    # P3 (H53): diversidad mínima de evidencia para band "high". Se cuentan
    # FAMILIAS independientes entre los grupos que aportan al score: ml y
    # context son una sola familia (el recidivismo cuenta decisiones T2+
    # pasadas, que salen del mismo ML), ti y signature una cada una. Con
    # menos familias que esto, la banda se capa en "medium" aunque el score
    # renormalizado sea alto (caso real: T3 de ML solo -> 82,8, H52).
    # Mecanismo distinto del desacuerdo de arriba: aquel mira cuánto
    # discrepan los grupos disponibles; este, cuántas fuentes independientes hay.
    corr_min_evidence_families_for_high: int = 2

    # Grupo context (H53): recidivismo = horas distintas con un incidente
    # T2+ de la misma IP en los 30 días previos (acumulador Redis, ver
    # constants.py y response/recidivism.py). Satura a 1.0 en este valor.
    # Valor inicial, sujeto a calibración (mismo criterio que
    # corr_otx_pulse_saturation): 5 horas distintas en un mes ya no es una
    # ráfaga aislada. Con 0 el grupo queda disponible pero no aporta al score
    # ni al desacuerdo (evidencia unilateral: "primera vez" no es evidencia
    # de benignidad).
    corr_context_recidivism_saturation: int = 5

    # ── OpenSearch para la correlación con suricata-alerts-* (H53) ─────
    # Mismas variables de entorno que response_audit_indexer.py (.env de
    # motor/). Certificado autofirmado en .140, mismo criterio que el indexer.
    os_host: str = "https://localhost:9201"
    os_user: str = "admin"
    os_pass: str = ""
    os_verify_tls: bool = False

    # Normalización de OTX: pulse_count es un conteo sin cota superior
    # natural (a diferencia de abuseipdb_score, que ya es 0-100). Se satura
    # a 1.0 en este valor -- un puñado de pulses ya es evidencia fuerte
    # (reportes curados por analistas, no autogenerados, ver enrichment.py).
    corr_otx_pulse_saturation: int = 5

    # ── R2: enforcer Wazuh API ─────────────────────────────────────────
    enforcer_backend: str = "dry_run"    # dry_run | wazuh_api
    wazuh_api_url: str = "https://200.54.12.139:55000"
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_ar_command: str = "firewall-drop"
    wazuh_target_agents: str = "all"     # "all" o lista coma-separada de agent IDs
    wazuh_api_timeout: float = 6.0
    wazuh_verify_tls: bool = False       # cert self-signed en el lab

    # ── Vista de estado de nodos (H43): usuario de SOLO LECTURA ────────
    # Rol agents_readonly de la API de Wazuh (agent:read, group:read).
    # Separado a propósito de wazuh_api_user (el del enforcer): la vista
    # del dashboard nunca usa una credencial capaz de disparar Active
    # Response. Vacío -> la vista muestra Wazuh como "no configurado".
    wazuh_nodes_user: str = ""
    wazuh_nodes_password: str = ""

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
