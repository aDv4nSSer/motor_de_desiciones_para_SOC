"""
notify.py -- Envio de alertas por correo (Gmail SMTP).
Motor SOC -- Tesis UBO. Requiere SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO
como variables de entorno (nunca hardcodeadas).
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def send_case_email(subject: str, body: str) -> bool:
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    to_addr = os.environ.get("ALERT_EMAIL_TO", "")

    if not user or not password or not to_addr:
        print("ERROR: faltan variables SMTP_USER/SMTP_PASSWORD/ALERT_EMAIL_TO")
        return False

    msg = MIMEMultipart()
    msg["From"] = user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(user, [to_addr], msg.as_string())
        print(f"OK: correo enviado a {to_addr}")
        return True
    except Exception as e:
        print(f"ERROR enviando correo: {e}")
        return False


if __name__ == "__main__":
    send_case_email(
        subject="[MOTOR SOC] Prueba de notificacion",
        body="Esto es una prueba del sistema de notificacion por correo.\n\nTesis UBO -- Motor de Decisiones SOC.",
    )
