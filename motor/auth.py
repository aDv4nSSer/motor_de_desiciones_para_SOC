"""
auth.py — Autenticación JWT + control de acceso por rol para el dashboard.

Reemplaza el HTTP Basic plano anterior (un solo nivel, sin roles) por la
decisión cerrada en docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md, sección 5:
JWT sobre FastAPI, tabla de usuarios con rol, protección de rutas por
dependencia. Cada login (éxito o fallo) y cada acción restringida por rol se
audita — ver log_access_event() — hacia el mismo stream que consume
opensearch_indexer.py para el hash-chain de soc-decisions.

Roles: "N1" < "N2" < "CISO" (ver motor/users.py:ROLE_LEVEL). require_role()
es acumulativo (N2 pasa cualquier gate de N1); require_ciso() es exacto,
para los reportes de cumplimiento que son exclusivos de CISO.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from functools import lru_cache

import jwt
import redis
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic_settings import BaseSettings, SettingsConfigDict
from users import Role, User, authenticate, role_at_least

log = logging.getLogger("motor.auth")

security = HTTPBearer(auto_error=False)


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Reutiliza FASTAPI_SECRET_KEY (ya documentada en .env.example) como
    # clave de firma del JWT -- evita introducir un segundo secreto para lo
    # mismo. Nunca hardcodear: falla explícito si no está seteada.
    fastapi_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480  # 8h -- duración de un turno de operador


@lru_cache
def get_auth_settings() -> AuthSettings:
    return AuthSettings()


def _redis_for_audit() -> redis.Redis | None:
    """Cliente Redis best-effort para auditar accesos. None si falla -- nunca
    debe tumbar un login o una request por un problema de auditoría."""
    try:
        from response.config import get_settings
        s = get_settings()
        return redis.Redis(
            host=s.redis_host, port=s.redis_port, password=s.redis_password,
            decode_responses=True, socket_timeout=1, socket_connect_timeout=1,
        )
    except Exception as e:  # noqa: BLE001 — la auditoría nunca debe romper el flujo de auth
        log.warning(f"no se pudo obtener cliente Redis para auditoria de acceso: {e}")
        return None


def log_access_event(username: str, event: str, detail: dict | None = None) -> None:
    """Registra un evento de acceso/acción restringida por rol.

    Se publica en el mismo stream (soc:response:audit) que ya consume
    opensearch_indexer.py hacia soc-decisions (hash-chain, append-only) --
    no se abre un canal de auditoría paralelo. Fallo aquí se loguea pero
    NUNCA propaga excepción (ver CLAUDE.md: sin `except Exception: pass`
    silencioso -- se loguea el motivo explícito).

    Args:
        username: quién ejecutó la acción (o intentó).
        event: tipo de evento, ej. "login_success", "login_failed",
            "approval_granted", "approval_denied_role".
        detail: contexto adicional libre (trace_id, approval_level, etc.)
    """
    rdb = _redis_for_audit()
    if rdb is None:
        return
    try:
        payload = {
            "access_event": event,
            "username": username,
            "at": datetime.now(timezone.utc).isoformat(),
            "detail": detail or {},
        }
        rdb.xadd("soc:response:audit", {"data": json.dumps(payload)},
                 maxlen=100_000, approximate=True)
    except redis.RedisError as e:
        log.warning(f"no se pudo auditar evento de acceso '{event}' de {username!r}: {e}")


def create_access_token(user: User) -> str:
    """Emite un JWT firmado con el rol embebido en el claim `role`."""
    settings = get_auth_settings()
    if not settings.fastapi_secret_key:
        # Fail closed: nunca firmar tokens con una clave vacía.
        raise RuntimeError("FASTAPI_SECRET_KEY no está configurada — no se puede emitir JWT")
    now = int(time.time())
    payload = {
        "sub": user.username,
        "role": user.role,
        "iat": now,
        "exp": now + settings.jwt_expire_minutes * 60,
    }
    return jwt.encode(payload, settings.fastapi_secret_key, algorithm=settings.jwt_algorithm)


def login(username: str, password: str) -> str:
    """Verifica credenciales y devuelve un JWT si son válidas.

    Raises:
        HTTPException 401 si las credenciales son inválidas o el usuario
        está deshabilitado.
    """
    user = authenticate(username, password)
    if user is None:
        log_access_event(username, "login_failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )
    log_access_event(username, "login_success", {"role": user.role})
    return create_access_token(user)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> User:
    """Dependencia FastAPI: decodifica el Bearer JWT y devuelve el User autenticado.

    Fail closed en cada caso: sin header -> 401; token expirado/inválido -> 401;
    claim de rol desconocido -> 401 (nunca se asume un rol por defecto).
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings = get_auth_settings()
    try:
        payload = jwt.decode(
            credentials.credentials, settings.fastapi_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    username = payload.get("sub")
    role = payload.get("role")
    if not username or role not in ("N1", "N2", "CISO"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token con claims inválidos")

    return User(username=username, role=role, created_at="", disabled=False)


def require_role(minimum: Role):
    """Factory de dependencia: exige rol >= `minimum` en la jerarquía N1<N2<CISO.

    Uso: `user: User = Depends(require_role("N2"))` en un endpoint.
    """
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if not role_at_least(user.role, minimum):
            log_access_event(user.username, "action_denied_role",
                              {"required": minimum, "actual": user.role})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requiere rol {minimum} o superior (tiene {user.role})",
            )
        return user
    return _dependency


def require_ciso(user: User = Depends(get_current_user)) -> User:
    """Dependencia exacta para reportes de cumplimiento — exclusivo de CISO,
    NO acumulativo (sección 5: "Operador N2 ... No puede: reportes de
    cumplimiento / métricas gerenciales (salvo permiso extra)")."""
    if user.role != "CISO":
        log_access_event(user.username, "action_denied_role",
                          {"required": "CISO", "actual": user.role})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requiere rol CISO",
        )
    return user
