"""
sessions.py — Registro de sesiones activas del dashboard (H43).

Hasta H43 un JWT solo se podía invalidar indirectamente (deshabilitar el
usuario o cambiarle el rol, ver auth.get_current_user). Para "sesiones
activas" y "revocar un token puntual" cada JWT lleva un `jti` y se registra
acá; get_current_user exige que el `jti` siga registrado. Revocar = borrar el
registro: el token deja de servir en la request siguiente aunque su firma y
vigencia sigan siendo válidas.

Estructura en Redis (mismo cliente que users.py):
    soc:sessions:<username>  hash  jti -> JSON {jti, username, role,
                                    issued_at, expires_at, user_agent,
                                    client_ip}
El hash expira con la última sesión que contiene; las sesiones vencidas
dentro del hash se limpian al listarlas (el JWT vencido ya lo rechaza
jwt.decode, el registro solo sobra).

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

import redis
from pydantic import BaseModel
from users import USERS_INDEX_KEY, _get_redis

log = logging.getLogger("motor.sessions")

SESSIONS_KEY_PREFIX = "soc:sessions:"
USER_AGENT_MAX_LEN = 160  # el user-agent es texto libre del cliente: se acota


class Session(BaseModel):
    """Sesión registrada (un JWT emitido y no revocado)."""
    jti: str
    username: str
    role: str
    issued_at: int
    expires_at: int
    user_agent: str = ""
    client_ip: str = ""


def _key(username: str) -> str:
    return f"{SESSIONS_KEY_PREFIX}{username}"


def register_session(session: Session, rdb: redis.Redis | None = None) -> None:
    """Registra la sesión de un JWT recién emitido.

    Args:
        session: datos de la sesión; `expires_at` es el `exp` del JWT.
        rdb: cliente Redis opcional (tests).

    Raises:
        redis.RedisError: si no se pudo registrar. El llamador NO debe
            entregar el token en ese caso: un token sin registro sería
            rechazado en la primera request igual.
    """
    r = _get_redis(rdb)
    r.hset(_key(session.username), session.jti, session.model_dump_json())
    # El hash vive hasta la sesión más tardía; nunca se acorta un TTL ya mayor.
    ttl = max(1, session.expires_at - int(time.time()))
    current = r.ttl(_key(session.username))
    if current is None or current < ttl:
        r.expire(_key(session.username), ttl)


def session_exists(username: str, jti: str, rdb: redis.Redis | None = None) -> bool:
    """True si el `jti` sigue registrado para el usuario.

    Raises:
        redis.RedisError: Redis no respondió (get_current_user lo traduce a 503).
    """
    return bool(_get_redis(rdb).hexists(_key(username), jti))


def _parse(raw: str) -> Session | None:
    try:
        return Session(**json.loads(raw))
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        log.error(f"registro de sesión corrupto, se ignora: {e}")
        return None


def list_sessions(username: str, rdb: redis.Redis | None = None, now: int | None = None) -> list[Session]:
    """Sesiones vigentes de un usuario, la más reciente primero. Limpia las
    vencidas y las corruptas del hash.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    now = int(time.time()) if now is None else now
    out: list[Session] = []
    stale: list[str] = []
    for jti, raw in (r.hgetall(_key(username)) or {}).items():
        s = _parse(raw)
        if s is None or s.expires_at <= now:
            stale.append(jti)
            continue
        out.append(s)
    if stale:
        r.hdel(_key(username), *stale)
    return sorted(out, key=lambda s: s.issued_at, reverse=True)


def list_all_sessions(rdb: redis.Redis | None = None, now: int | None = None) -> list[Session]:
    """Sesiones vigentes de todos los usuarios de la tabla.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    out: list[Session] = []
    for username in sorted(r.smembers(USERS_INDEX_KEY) or []):
        out.extend(list_sessions(username, r, now))
    return sorted(out, key=lambda s: s.issued_at, reverse=True)


def revoke_session(username: str, jti: str, rdb: redis.Redis | None = None) -> bool:
    """Revoca un token puntual. True si existía.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    return bool(_get_redis(rdb).hdel(_key(username), jti))


def revoke_all_sessions(username: str, rdb: redis.Redis | None = None) -> int:
    """Revoca todos los tokens de un usuario. Devuelve cuántos había.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    count = len(r.hkeys(_key(username)) or [])
    r.delete(_key(username))
    return count


def session_view(s: Session) -> dict[str, Any]:
    """Representación para el dashboard (sin nada que permita reusar el token:
    el jti solo identifica la sesión, no autentica)."""
    return s.model_dump()
