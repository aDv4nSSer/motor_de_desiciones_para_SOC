"""
watcher.py -- Vigilante FIM -> Cuarentena automatica -> Caso -> Correo.

Lee /var/ossec/logs/alerts/alerts.json en tiempo real (tail -f estructurado).
Cuando detecta un archivo ejecutable nuevo en el webroot de WordPress,
dispara la cuarentena via API de Wazuh, abre un caso, y notifica por correo.

Motor SOC -- Tesis UBO. Ejecutar como servicio systemd en el manager (.139).
"""
import json
import logging
import os
import time

import requests
import urllib3

from cases import open_case
from notify import send_case_email

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [watcher] %(levelname)s %(message)s",
)
log = logging.getLogger("watcher")

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
WAZUH_API_URL = "https://localhost:55000"
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")

# Debe coincidir con el restrict de ossec.conf (H12) -- doble verificacion.
EXECUTABLE_EXT = (".php", ".phtml", ".phar")
WATCHED_PATH_FRAGMENT = "/wp-content/uploads/"

# Idempotencia: no volver a abrir caso para el mismo path en esta ejecucion.
_seen_paths: set[str] = set()


def get_wazuh_token() -> str | None:
    try:
        resp = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
            verify=False, timeout=6,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]
    except Exception as e:
        log.error(f"no se pudo autenticar contra la API de Wazuh: {e}")
        return None


def trigger_quarantine(file_path: str) -> bool:
    token = get_wazuh_token()
    if not token:
        return False
    try:
        resp = requests.put(
            f"{WAZUH_API_URL}/active-response?agents_list=001",
            headers={"Authorization": f"Bearer {token}"},
            json={"command": "!quarantine-file", "alert": {"data": {"file_path": file_path}}},
            verify=False, timeout=6,
        )
        resp.raise_for_status()
        result = resp.json()
        ok = result.get("data", {}).get("total_failed_items", 1) == 0
        log.info(f"cuarentena disparada para {file_path}: {result}")
        return ok
    except Exception as e:
        log.error(f"fallo al disparar cuarentena para {file_path}: {e}")
        return False


def is_suspicious_fim_event(alert: dict) -> bool:
    groups = alert.get("rule", {}).get("groups", [])
    if "syscheck_file" not in groups:
        return False
    syscheck = alert.get("syscheck", {})
    if syscheck.get("event") not in ("added", "modified"):
        return False
    path = syscheck.get("path", "")
    if WATCHED_PATH_FRAGMENT not in path:
        return False
    if not path.lower().endswith(EXECUTABLE_EXT):
        return False
    return True


def handle_alert(alert: dict):
    if not is_suspicious_fim_event(alert):
        return

    syscheck = alert["syscheck"]
    path = syscheck["path"]
    agent = alert.get("agent", {})

    if path in _seen_paths:
        log.info(f"path ya procesado en esta sesion, se omite: {path}")
        return
    _seen_paths.add(path)

    log.warning(f"ARCHIVO SOSPECHOSO DETECTADO: {path} (agente {agent.get('name')})")

    quarantined = trigger_quarantine(path)

    case = open_case(
        kind="quarantine_file",
        host=f"{agent.get('name', '?')} ({agent.get('ip', '?')})",
        detail={
            "file_path": path,
            "sha256": syscheck.get("sha256_after"),
            "size_bytes": syscheck.get("size_after"),
            "owner": syscheck.get("uname_after"),
            "quarantine_triggered": quarantined,
            "wazuh_rule_id": alert.get("rule", {}).get("id"),
        },
    )

    estado_txt = "EJECUTADA" if quarantined else "FALLO -- REQUIERE ACCION MANUAL"
    subject = f"[MOTOR SOC] Archivo sospechoso en {agent.get('name')} -- cuarentena {estado_txt}"
    body = f"""Se detecto un archivo ejecutable nuevo en una carpeta de solo-uploads.

Host:        {agent.get('name')} ({agent.get('ip')})
Archivo:     {path}
SHA256:      {syscheck.get('sha256_after')}
Tamano:      {syscheck.get('size_after')} bytes
Propietario: {syscheck.get('uname_after')}
Cuarentena:  {estado_txt}

Caso abierto: {case['case_id']}
Revisar en el dashboard: https://motor-soc-ubo.duckdns.org/dashboard

Esta es una notificacion automatica del Motor de Decisiones SOC -- Tesis UBO.
Se requiere revision humana antes de restaurar el archivo o cerrar el caso.
"""
    send_case_email(subject, body)
    log.warning(f"caso {case['case_id']} abierto y notificado")


def tail_alerts():
    log.info(f"iniciando vigilancia de {ALERTS_FILE}")
    with open(ALERTS_FILE, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                handle_alert(alert)
            except Exception as e:
                log.error(f"error procesando alerta (no fatal): {e}")


if __name__ == "__main__":
    tail_alerts()
