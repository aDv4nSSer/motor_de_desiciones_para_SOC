"""
auth.py — Autenticación JWT + control de acceso por rol para el dashboard.

Reemplaza el HTTP Basic plano anterior (un solo nivel, sin roles) por la
decisión cerrada en docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md, sección 5:
JWT sobre FastAPI, tabla de usuarios con rol, protección de rutas por
dependencia. Cada login (éxito o fallo) y cada acción restringida por rol se
publica — ver log_access_event() — en el stream Redis soc:response:audit,
que response_audit_indexer.py persiste con hash-chain en soc-responses-*
(H39). Desde H43 cada JWT lleva un `jti` registrado en sessions.py: un token
puntual se puede revocar sin tocar al usuario.

Roles: "N1" < "N2" < "CISO" (ver motor/users.py:ROLE_LEVEL). require_role()
es acumulativo (N2 pasa cualquier gate de N1); require_ciso() es exacto,
para los reportes de cumplimiento que son exclusivos de CISO.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache

import jwt
import redis
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic_settings import BaseSettings, SettingsConfigDict
from sessions import USER_AGENT_MAX_LEN, Session, register_session, session_exists
from users import Role, User, authenticate, get_user_record, role_at_least

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

    Se publica en el stream soc:response:audit, el mismo donde el worker
    audita R1/R2 -- no se abre un canal de auditoría paralelo. Lo persiste
    response_audit_indexer.py en soc-responses-* con hash-chain (H39), con
    event_type="access". Fallo aquí se loguea pero
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


def create_access_token(user: User, user_agent: str = "", client_ip: str = "") -> str:
    """Emite un JWT firmado con el rol embebido en el claim `role` y un `jti`
    único, y registra la sesión (H43: revocación por token).

    Args:
        user: usuario autenticado.
        user_agent: User-Agent del cliente (se acota a USER_AGENT_MAX_LEN).
        client_ip: IP informada por el proxy (X-Real-IP), solo informativa.

    Returns:
        El JWT firmado.

    Raises:
        RuntimeError: si FASTAPI_SECRET_KEY no está configurada.
        redis.RedisError: si no se pudo registrar la sesión (no se entrega
            un token que sería rechazado en la primera request).
    """
    settings = get_auth_settings()
    if not settings.fastapi_secret_key:
        # Fail closed: nunca firmar tokens con una clave vacía.
        raise RuntimeError("FASTAPI_SECRET_KEY no está configurada — no se puede emitir JWT")
    now = int(time.time())
    exp = now + settings.jwt_expire_minutes * 60
    jti = uuid.uuid4().hex
    payload = {
        "sub": user.username,
        "role": user.role,
        "iat": now,
        "exp": exp,
        "jti": jti,
    }
    register_session(Session(
        jti=jti, username=user.username, role=user.role, issued_at=now, expires_at=exp,
        user_agent=user_agent[:USER_AGENT_MAX_LEN], client_ip=client_ip[:64],
    ))
    return jwt.encode(payload, settings.fastapi_secret_key, algorithm=settings.jwt_algorithm)


def login(username: str, password: str, user_agent: str = "", client_ip: str = "") -> str:
    """Verifica credenciales y devuelve un JWT si son válidas.

    Args:
        username: usuario.
        password: contraseña en texto plano (se verifica con bcrypt).
        user_agent: User-Agent del cliente, para la vista de sesiones activas.
        client_ip: IP informada por el proxy, para la vista de sesiones activas.

    Returns:
        El JWT (la sesión queda registrada).

    Raises:
        HTTPException 401 si las credenciales son inválidas o el usuario
        está deshabilitado; 503 si no se pudo registrar la sesión en Redis.
    """
    user = authenticate(username, password)
    if user is None:
        log_access_event(username, "login_failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )
    try:
        token = create_access_token(user, user_agent=user_agent, client_ip=client_ip)
    except redis.RedisError as e:
        log.error(f"no se pudo registrar la sesión de {username!r}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No se pudo registrar la sesión, reintente",
        )
    log_access_event(username, "login_success", {"role": user.role})
    return token


def get_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> tuple[User, str]:
    """Dependencia FastAPI: decodifica el Bearer JWT y devuelve (User, jti).

    Fail closed en cada caso: sin header -> 401; token expirado/inválido -> 401;
    claim de rol desconocido -> 401 (nunca se asume un rol por defecto).

    Revocación: además de firma y vigencia, se relee el usuario en Redis en
    cada request. Usuario borrado, deshabilitado o con rol distinto al del
    token -> 401 (un JWT emitido no sobrevive a una baja ni a un cambio de
    rol). Si Redis no responde -> 503: no se puede confirmar que el usuario
    siga activo y no se deja pasar el token. A diferencia de TI/contexto
    ("unavailable" y la decisión continúa), acá el dato faltante ES el
    control de acceso — degradar abierto sería otorgar acceso.

    Sesión (H43): el `jti` del token tiene que seguir registrado en
    sessions.py. Un token sin `jti` (emitido antes de H43) o con la sesión
    revocada -> 401.

    Returns:
        (User, jti) del token.

    Raises:
        HTTPException 401 si el token, la sesión o el usuario no son válidos,
        503 si no se pudo verificar contra Redis.
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
    jti = payload.get("jti")
    if not username or role not in ("N1", "N2", "CISO") or not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token con claims inválidos")

    try:
        record = get_user_record(username)
        session_ok = session_exists(username, jti)
    except redis.RedisError as e:
        log.error(f"no se pudo verificar el estado del usuario {username!r} en Redis: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No se pudo verificar el usuario, reintente",
        )
    if record is None or record.disabled or record.role != role:
        reason = ("inexistente" if record is None
                  else "deshabilitado" if record.disabled else "rol_cambiado")
        log_access_event(username, "token_rejected_user_state",
                          {"reason": reason, "token_role": role})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión revocada, inicie sesión nuevamente",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not session_ok:
        log_access_event(username, "token_rejected_session_revoked", {"jti": jti})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión revocada, inicie sesión nuevamente",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = User(username=record.username, role=record.role,
                created_at=record.created_at, disabled=record.disabled)
    return user, jti


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> User:
    """Dependencia FastAPI: el User autenticado (ver get_current_session, que
    hace toda la verificación).

    Returns:
        El usuario dueño de un token válido, vigente y no revocado.

    Raises:
        HTTPException 401/503, igual que get_current_session.
    """
    return get_current_session(credentials)[0]


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


def require_role_session(minimum: Role):
    """Como require_role(), pero devuelve (User, jti): para endpoints que
    necesitan saber desde qué sesión se hizo el pedido (revocar sesiones)."""
    def _dependency(current: tuple[User, str] = Depends(get_current_session)) -> tuple[User, str]:
        user = current[0]
        if not role_at_least(user.role, minimum):
            log_access_event(user.username, "action_denied_role",
                             {"required": minimum, "actual": user.role})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requiere rol {minimum} o superior (tiene {user.role})",
            )
        return current
    return _dependency
