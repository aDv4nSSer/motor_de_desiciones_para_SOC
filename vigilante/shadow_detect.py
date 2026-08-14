"""
shadow_detect.py -- Deteccion experimental en MODO OBSERVACION PURA.

Lee eve.json de Suricata en .139 en una sola pasada incremental y produce
dos tipos de hallazgo, escritos al mismo indice OpenSearch separado
(soc-experimental-detections) en .140, distinguidos por el campo "source":

  - "dga_shadow": entropia de Shannon sobre dominios DNS (excluyendo el
    sufijo publico/TLD via la Public Suffix List real). Ver DGA_ENTROPY_THRESHOLD.
  - "l7_shadow": relay de alertas L7 de Suricata cuyo signature_id esta en
    L7_SIGNATURE_IDS -- los 9 SIDs curados y documentados en
    infra/suricata/enable.conf (scanners/herramientas de SQLi/XSS/traversal,
    todas accion "alert", nunca drop/reject). Esto no es un detector nuevo:
    Suricata ya genera la alerta completa, este script solo la relay-ea a
    OpenSearch porque no existe otro pipeline que lo haga (el Vector de
    produccion descarta todo evento que no sea event_type=="flow").

Garantias de aislamiento (por diseno, no por configuracion):
  - Nunca escribe a soc-decisions (indice distinto, cliente HTTP propio).
  - No importa nada de response/ (enforcer, queue, worker) -- no tiene forma
    de encolar una tarea R1/R2 aunque quisiera.
  - No escribe a Redis Streams de tareas (soc:response:tasks). El unico
    estado que persiste es su propio offset de lectura de eve.json.
  - Corre via systemd timer independiente (shadow-detect.timer), proceso
    separado de watcher.py y de motor-soc.

Deduplicacion: antes de crear un documento nuevo, se busca un hallazgo
equivalente (misma entidad: domain para dga_shadow, signature_id+src_ip para
l7_shadow) dentro de DEDUP_WINDOW_HOURS. Si existe, se incrementa su campo
`occurrences` (update atomico via script Painless) en vez de duplicar --
evita que una fuente ruidosa periodica (ej. un dominio de healthcheck)
genere un documento nuevo en cada corrida del timer.

Umbral de entropia por defecto (3.5 bits/caracter): valor de referencia usado
en la practica para separar dominios legitimos (~3.0-3.5 bits) de dominios
tipo DGA (~4.0-4.5 bits) -- ver docs/BITACORA_TECNICA.md para la cita completa.
No es un valor universal de la literatura academica (no existe uno unico);
se espera calibrar contra el trafico DNS real de esta red tras unos dias
en modo sombra.

Motor SOC -- Tesis UBO.
"""
import base64
import json
import logging
import math
import os
import ssl
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

import tldextract

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [shadow_detect] %(levelname)s %(message)s",
)
log = logging.getLogger("shadow_detect")

# ── Configuración ────────────────────────────────────────────────────────
EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "/var/log/suricata/eve.json")
STATE_FILE = os.environ.get(
    "SHADOW_STATE_FILE", "/home/aiayala/tesis/vigilante/logs/shadow_detect_state.json"
)

OS_HOST = os.environ.get("OS_HOST", "https://200.54.12.140:9201")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "")
OS_INDEX = "soc-experimental-detections"

DGA_ENTROPY_THRESHOLD = float(os.environ.get("DGA_ENTROPY_THRESHOLD", "3.5"))
# Tope de lineas nuevas por corrida -- si el timer estuvo caido un tiempo largo,
# procesa hasta este limite y deja el resto para la proxima corrida en vez de
# bloquear indefinidamente poniendose al dia con un archivo de 14+ GB.
MAX_LINES_PER_RUN = int(os.environ.get("SHADOW_MAX_LINES_PER_RUN", "200000"))
# Ventana de deduplicacion -- mismo valor que la cascada de cache L1 de
# threat-intel-svc para veredicto "malicioso" (ver CLAUDE.md), no un numero
# arbitrario nuevo. Bastante para colapsar ruido periodico (ej. un domain
# de healthcheck que se repite cada pocos minutos) sin suprimir para siempre
# una recurrencia real que aparece horas despues.
DEDUP_WINDOW_HOURS = float(os.environ.get("DEDUP_WINDOW_HOURS", "6"))

# SIDs curados para relay L7 -- ver infra/suricata/enable.conf para el
# detalle completo de que detecta cada uno y por que se eligio.
L7_SIGNATURE_IDS = {
    2008538,  # ET SCAN Sqlmap SQL Injection Scan
    2012754,  # ET SCAN Possible SQLMAP Scan
    2012606,  # ET SCAN Havij SQL Injection Tool User-Agent Inbound
    2009833,  # ET SCAN WITOOL SQL Injection Scan
    2002677,  # ET SCAN Nikto Web App Scan in Progress
    2007757,  # ET SCAN w3af User Agent
    2009646,  # ET SCAN Acunetix Version 6 (Free Edition) Scan Detected
    2100981,  # GPL EXPLOIT unicode directory traversal attempt (/..%c0%af../)
    2100983,  # GPL EXPLOIT unicode directory traversal attempt (/..%c1%9c../)
}

# Extractor de sufijos publicos (Public Suffix List real, snapshot empaquetado
# con tldextract -- sin llamadas de red en runtime, para no depender de
# conectividad externa en un script de deteccion).
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


# ── OpenSearch (mismo patrón que opensearch_indexer.py / dashboard.py) ────
def _os_request(method: str, path: str, body: dict | None = None) -> dict | None:
    url = f"{OS_HOST}{path}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode(),
    }
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=5) as r:  # nosec B310 - esquema fijo (https) via OS_HOST
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        log.error(f"OpenSearch HTTP error en {path}: {e.read()}")
        return None
    except Exception as e:
        log.error(f"OpenSearch error en {path}: {e}")
        return None


def index_finding(doc: dict) -> bool:
    """Escribe un hallazgo (dga_shadow o l7_shadow) al índice experimental.

    Nunca toca soc-decisions -- índice y cliente HTTP completamente separados.

    Args:
        doc: documento del hallazgo (ver dns_findings / l7_finding).

    Returns:
        True si se indexó correctamente, False si falló (no fatal).
    """
    result = _os_request("POST", f"/{OS_INDEX}/_doc", doc)
    if result and result.get("result") == "created":
        return True
    log.error(f"no se pudo indexar hallazgo ({doc.get('source')}): {result}")
    return False


def _find_recent(must_clauses: list[dict]) -> str | None:
    """Busca el hallazgo más reciente que matchee must_clauses dentro de DEDUP_WINDOW_HOURS.

    Args:
        must_clauses: cláusulas `term` exactas para identificar la misma
            entidad (ej. source + domain para DNS, source + signature_id +
            src_ip para L7). El filtro de ventana temporal se agrega acá.

    Returns:
        El `_id` del documento existente más reciente, o None si no hay
        ninguno dentro de la ventana (o si OpenSearch no responde).
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
    query = {
        "size": 1,
        "sort": [{"detected_at": {"order": "desc"}}],
        "query": {"bool": {"must": must_clauses + [{"range": {"detected_at": {"gte": since}}}]}},
    }
    result = _os_request("POST", f"/{OS_INDEX}/_search", query)
    if result is None:
        return None
    hits = result.get("hits", {}).get("hits", [])
    return hits[0]["_id"] if hits else None


def _bump_occurrence(doc_id: str, detected_at: str, timestamp: str) -> bool:
    """Incrementa `occurrences` y actualiza `last_seen`/`timestamp` de un hallazgo existente.

    Usa un script Painless (`ctx._source.occurrences += 1`) en vez de
    leer-modificar-escribir desde Python -- evita una condición de carrera
    si dos corridas se solaparan.

    Args:
        doc_id: `_id` del documento existente a actualizar.
        detected_at: momento en que se detectó esta repetición.
        timestamp: timestamp del evento eve.json de esta repetición.

    Returns:
        True si se actualizó correctamente, False si falló (no fatal).
    """
    body = {
        "script": {
            "lang": "painless",
            "source": (
                "ctx._source.occurrences += 1; "
                "ctx._source.last_seen = params.detected_at; "
                "ctx._source.timestamp = params.timestamp;"
            ),
            "params": {"detected_at": detected_at, "timestamp": timestamp},
        }
    }
    result = _os_request("POST", f"/{OS_INDEX}/_update/{doc_id}", body)
    if result and result.get("result") in ("updated", "noop"):
        return True
    log.error(f"no se pudo actualizar occurrences de {doc_id}: {result}")
    return False


def upsert_finding(doc: dict, dedup_clauses: list[dict]) -> bool:
    """Escribe un hallazgo, o incrementa `occurrences` si ya existe uno
    equivalente (misma fuente + misma entidad) dentro de DEDUP_WINDOW_HOURS.

    Args:
        doc: documento del hallazgo (ver dns_findings / l7_finding).
        dedup_clauses: cláusulas `term` que identifican la misma entidad
            (ver _find_recent).

    Returns:
        True si se escribió o actualizó correctamente, False si falló.
    """
    existing_id = _find_recent(dedup_clauses)
    if existing_id:
        return _bump_occurrence(existing_id, doc["detected_at"], doc["timestamp"])

    doc["occurrences"] = 1
    doc["first_seen"] = doc["detected_at"]
    doc["last_seen"] = doc["detected_at"]
    return index_finding(doc)


# ── DNS / DGA — entropía de Shannon ─────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    """Entropía de Shannon en bits/carácter de una cadena.

    Args:
        s: cadena a medir.

    Returns:
        Bits de entropía por carácter (0.0 para cadena vacía).
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def domain_label_without_tld(rrname: str) -> str | None:
    """Nombre de dominio sin el sufijo público (TLD real, vía Public Suffix List).

    Args:
        rrname: nombre de dominio consultado (ej. "eywonbdkjgmvsstgkblztpkfxhi.ru").

    Returns:
        El dominio sin el sufijo (ej. "eywonbdkjgmvsstgkblztpkfxhi"), o None
        si no hay suficiente estructura para evaluar (ej. una IP o un TLD solo).
    """
    ext = _tld_extractor(rrname.rstrip("."))
    if not ext.domain:
        return None
    label = f"{ext.subdomain}.{ext.domain}" if ext.subdomain else ext.domain
    return label


def dns_findings(event: dict) -> list[dict]:
    """Hallazgos DGA para un evento DNS request (puede haber >1 query por evento).

    Args:
        event: evento eve.json con event_type == "dns" y dns.type == "request".

    Returns:
        Lista de documentos source="dga_shadow" (vacía si nada supera el umbral).
    """
    findings = []
    for query in event.get("dns", {}).get("queries", []):
        rrname = query.get("rrname", "")
        label = domain_label_without_tld(rrname)
        if label is None:
            continue

        entropy = shannon_entropy(label)
        if entropy < DGA_ENTROPY_THRESHOLD:
            continue

        findings.append({
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "source": "dga_shadow",
            "sensor": "suricata_139",
            "domain": rrname,
            "domain_label_evaluated": label,
            "entropy": round(entropy, 3),
            "threshold_used": DGA_ENTROPY_THRESHOLD,
            "rrtype": query.get("rrtype", ""),
            "src_ip": event.get("src_ip", ""),
            "dest_ip": event.get("dest_ip", ""),
        })
    return findings


# ── L7 — relay de alertas Suricata ya filtradas por SID ─────────────────────
def l7_finding(event: dict) -> dict:
    """Documento de hallazgo para un evento alert ya filtrado contra L7_SIGNATURE_IDS.

    Args:
        event: evento eve.json con event_type == "alert" y
            alert.signature_id en L7_SIGNATURE_IDS.

    Returns:
        Documento source="l7_shadow" listo para indexar.
    """
    alert = event.get("alert", {})
    return {
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "source": "l7_shadow",
        "sensor": "suricata_139",
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature", ""),
        "category": alert.get("category", ""),
        "severity": alert.get("severity"),
        "src_ip": event.get("src_ip", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port"),
    }


# ── Lectura incremental de eve.json (una sola pasada, DNS + alert) ─────────
def load_offset() -> int:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f).get("offset", 0)
        except (json.JSONDecodeError, OSError) as e:
            log.error(f"estado de offset ilegible, se reinicia desde el final: {e}")
    return -1  # sentinel: primera corrida, ver check()


def save_offset(offset: int) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"offset": offset, "updated": datetime.now(timezone.utc).isoformat()}, f)


def read_new_events(start_offset: int) -> tuple[list[dict], int]:
    """Lee líneas nuevas de eve.json y devuelve los eventos relevantes (DNS + L7).

    Args:
        start_offset: posición de bytes desde donde continuar.

    Returns:
        (lista de eventos dns-request y alert-de-SID-curado, nuevo offset de bytes).
    """
    size = os.path.getsize(EVE_LOG_PATH)
    offset = start_offset if 0 <= start_offset <= size else 0  # rotado/truncado -> reinicia

    events = []
    with open(EVE_LOG_PATH, "r", errors="replace") as f:
        f.seek(offset)
        lines_read = 0
        for line in f:
            if lines_read >= MAX_LINES_PER_RUN:
                break
            lines_read += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # línea a medio escribir (carrera con Suricata), se recupera la próxima corrida

            event_type = event.get("event_type")
            if event_type == "dns" and event.get("dns", {}).get("type") == "request":
                events.append(event)
            elif event_type == "alert" and event.get("alert", {}).get("signature_id") in L7_SIGNATURE_IDS:
                events.append(event)
        offset = f.tell()
    return events, offset


# ── Main ────────────────────────────────────────────────────────────────────
def check() -> None:
    if not os.path.exists(EVE_LOG_PATH):
        log.error(f"no existe {EVE_LOG_PATH}, nada que revisar")
        return

    start_offset = load_offset()
    if start_offset == -1:
        # Primera corrida: arrancar desde el final, igual que watcher.py con
        # alerts.json -- no reprocesar los 14+ GB históricos.
        start_offset = os.path.getsize(EVE_LOG_PATH)
        save_offset(start_offset)
        log.info(f"primera corrida, offset inicial = {start_offset} (fin del archivo)")
        return

    events, new_offset = read_new_events(start_offset)

    dns_events = 0
    alert_events = 0
    findings_written = 0

    for event in events:
        if event.get("event_type") == "dns":
            dns_events += 1
            for doc in dns_findings(event):
                clauses = [
                    {"term": {"source.keyword": "dga_shadow"}},
                    {"term": {"domain.keyword": doc["domain"]}},
                ]
                if upsert_finding(doc, clauses):
                    findings_written += 1
        else:  # "alert", ya filtrado por SID en read_new_events
            alert_events += 1
            doc = l7_finding(event)
            clauses = [
                {"term": {"source.keyword": "l7_shadow"}},
                {"term": {"signature_id": doc["signature_id"]}},
                {"term": {"src_ip.keyword": doc["src_ip"]}},
            ]
            if upsert_finding(doc, clauses):
                findings_written += 1

    save_offset(new_offset)
    log.info(
        f"revisados {dns_events} DNS + {alert_events} alertas L7 nuevas, "
        f"{findings_written} hallazgos escritos (dga_shadow + l7_shadow), "
        f"offset {start_offset} -> {new_offset}"
    )


if __name__ == "__main__":
    check()
