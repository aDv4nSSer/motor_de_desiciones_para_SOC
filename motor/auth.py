"""
auth.py -- Autenticacion HTTP Basic para los endpoints del dashboard.

Las credenciales se guardan hasheadas (SHA-256) en la variable de entorno
DASHBOARD_USERS, con formato: usuario1:hash1,usuario2:hash2

NOTA de diseno: se usa secrets.compare_digest en vez de '==' para evitar
ataques de temporizacion (timing attacks), donde un atacante deduce la
credencial midiendo el tiempo de respuesta de comparaciones fallidas.

Motor SOC -- Tesis UBO.
"""
import hashlib
import os
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()


def _load_users() -> dict[str, str]:
    """Parsea DASHBOARD_USERS -> {usuario: hash_sha256}"""
    raw = os.environ.get("DASHBOARD_USERS", "")
    users = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        user, pw_hash = entry.split(":", 1)
        users[user.strip()] = pw_hash.strip()
    return users


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    users = _load_users()

    if not users:
        # Sin usuarios configurados -> se deniega todo (fail closed, no fail open).
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Autenticacion no configurada en el servidor",
        )

    expected_hash = users.get(credentials.username)
    provided_hash = hashlib.sha256(credentials.password.encode()).hexdigest()

    # Si el usuario no existe, comparamos contra un hash dummy de todos modos.
    # Esto mantiene el tiempo de respuesta constante y no revela si el
    # usuario existe o no (evita enumeracion de usuarios).
    if expected_hash is None:
        secrets.compare_digest(provided_hash, "0" * 64)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales invalidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not secrets.compare_digest(provided_hash, expected_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales invalidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username
