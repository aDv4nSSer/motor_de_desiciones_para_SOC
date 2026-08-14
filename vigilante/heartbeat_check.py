"""
heartbeat_check.py -- Verifica que watcher.py siga vivo, de forma independiente.

Corre via systemd timer (motor-watcher-heartbeat.timer), separado del proceso
de motor-watcher.service -- si el vigilante murio (crash, stop manual, lo que
sea), este script sigue corriendo igual y puede avisar por correo. Reusa el
mismo canal de notificacion que el resto del lazo FIM -> cuarentena -> caso
-> correo (notify.py), no crea uno nuevo.

Motor SOC -- Tesis UBO.
"""
import logging
import os
from datetime import datetime, timezone

import redis

from cases import HEARTBEAT_KEY, REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
from notify import send_case_email

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [heartbeat_check] %(levelname)s %(message)s",
)
log = logging.getLogger("heartbeat_check")

STALE_THRESHOLD_HOURS = float(os.environ.get("WATCHER_HEARTBEAT_STALE_HOURS", "1"))
ALERT_COOLDOWN_HOURS = float(os.environ.get("WATCHER_HEARTBEAT_ALERT_COOLDOWN_HOURS", "6"))
ALERT_SENT_KEY = "soc:watcher:heartbeat_alert_sent"


def check() -> None:
    r = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
        decode_responses=True, socket_timeout=5, socket_connect_timeout=5,
    )
    raw = r.get(HEARTBEAT_KEY)

    if raw is None:
        age_hours = None
        stale = True
    else:
        last = datetime.fromisoformat(raw)
        age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
        stale = age_hours > STALE_THRESHOLD_HOURS

    if not stale:
        if r.delete(ALERT_SENT_KEY):
            log.info("heartbeat recuperado, se resetea el flag de alerta")
        return

    log.warning(f"heartbeat de motor-watcher stale (edad_horas={age_hours})")

    if r.exists(ALERT_SENT_KEY):
        log.info("ya se aviso de esta caida, dentro del cooldown -- no se reenvia")
        return

    edad_txt = (
        "sin ningun heartbeat registrado"
        if age_hours is None
        else f"{age_hours:.1f} horas sin actividad"
    )
    subject = "[MOTOR SOC] ALERTA: motor-watcher sin actividad"
    body = f"""El vigilante FIM (motor-watcher.service en .139) no ha reportado actividad.

Estado: {edad_txt}
Umbral configurado: {STALE_THRESHOLD_HOURS}h

Esto significa que el lazo FIM -> cuarentena -> caso -> correo puede no estar
funcionando -- archivos ejecutables nuevos en el webroot no se detectarian.

Revisar con: systemctl status motor-watcher (en .139)

Esta es una notificacion automatica del Motor de Decisiones SOC -- Tesis UBO.
No se repetira este aviso por {ALERT_COOLDOWN_HOURS}h mientras la caida persista.
"""
    if send_case_email(subject, body):
        r.set(ALERT_SENT_KEY, "1", ex=int(ALERT_COOLDOWN_HOURS * 3600))


if __name__ == "__main__":
    check()
