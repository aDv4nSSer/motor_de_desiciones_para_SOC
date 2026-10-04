"""
users.py — Tabla de usuarios del dashboard (JWT + roles).

Persiste en Redis (soc:users:<username> -> JSON), no en un archivo ni en
variables de entorno, para poder crear/deshabilitar usuarios sin reiniciar
el servicio (cumple la decisión cerrada en
docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md, sección 5: "tabla de usuarios
con rol"). Las contraseñas se guardan con bcrypt (nunca en texto plano ni
con hash reversible).

Roles (mismos nombres que ya usa response/schemas.py:BlockResult.approval_level,
para no introducir una segunda taxonomía): "N1" < "N2" < "CISO". La
jerarquía es acumulativa para acciones (N2 puede todo lo de N1, CISO puede
todo lo de N2) — la única excepción son los reportes de cumplimiento, que
son exclusivos de CISO (ver require_ciso() en auth.py).

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Literal

import bcrypt
import redis
from pydantic import BaseModel, Field

log = logging.getLogger("motor.users")

Role = Literal["N1", "N2", "CISO"]

# Jerarquía de roles para gating de acciones (sección 5 de la especificación).
# CISO hereda todo lo de N2, N2 hereda todo lo de N1 -- excepto reportes de
# cumplimiento, que se gatean aparte por rol exacto (ver auth.require_ciso).
ROLE_LEVEL: dict[Role, int] = {"N1": 1, "N2": 2, "CISO": 3}

USERS_KEY_PREFIX = "soc:users:"
USERS_INDEX_KEY = "soc:users:index"  # set con todos los usernames


class User(BaseModel):
    """Registro de usuario tal como se persiste en Redis (sin password)."""
    username: str
    role: Role
    created_at: str
    disabled: bool = False


class UserRecord(User):
    """Registro completo, incluyendo el hash bcrypt. Nunca sale de este módulo."""
    password_hash: str = Field(repr=False)


_client: redis.Redis | None = None


def _get_redis(rdb: redis.Redis | None = None) -> redis.Redis:
    global _client
    if rdb is not None:
        return rdb
    if _client is None:
        # Import local para no acoplar este módulo a response.config en tiempo
        # de import (evita ciclos: response.config no depende de users.py).
        from response.config import get_settings
        s = get_settings()
        _client = redis.Redis(
            host=s.redis_host, port=s.redis_port, password=s.redis_password,
            decode_responses=True, socket_timeout=3, socket_connect_timeout=3,
        )
    return _client


def hash_password(plain: str) -> str:
    """Hashea una contraseña con bcrypt (cost factor default, 12)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Hash con formato inválido/corrupto -- nunca autenticar por defecto.
        log.error("hash de password con formato invalido en Redis")
        return False


def create_user(
    username: str, plain_password: str, role: Role, rdb: redis.Redis | None = None,
) -> User:
    """Crea (o reemplaza) un usuario. Pensado para usarse desde scripts/manage_users.py.

    Args:
        username: identificador único, case-sensitive.
        plain_password: contraseña en texto plano — se hashea acá, nunca se persiste tal cual.
        role: "N1" | "N2" | "CISO".
        rdb: cliente Redis opcional (para tests).

    Returns:
        El User creado (sin el hash).
    """
    r = _get_redis(rdb)
    record = UserRecord(
        username=username,
        role=role,
        created_at=datetime.now(timezone.utc).isoformat(),
        password_hash=hash_password(plain_password),
    )
    r.set(f"{USERS_KEY_PREFIX}{username}", record.model_dump_json())
    r.sadd(USERS_INDEX_KEY, username)
    log.info(f"usuario creado/actualizado: {username} (rol={role})")
    return User(**record.model_dump(exclude={"password_hash"}))


def get_user_record(username: str, rdb: redis.Redis | None = None) -> UserRecord | None:
    r = _get_redis(rdb)
    raw = r.get(f"{USERS_KEY_PREFIX}{username}")
    if raw is None:
        return None
    try:
        return UserRecord(**json.loads(raw))
    except (json.JSONDecodeError, ValueError) as e:
        log.error(f"registro de usuario corrupto para {username!r}: {e}")
        return None


def authenticate(username: str, plain_password: str, rdb: redis.Redis | None = None) -> User | None:
    """Verifica credenciales. Devuelve el User si son válidas, None si no.

    Comparación de password vía bcrypt.checkpw (ya es timing-safe por
    diseño del algoritmo). Si el usuario no existe, igual se ejecuta un
    checkpw contra un hash dummy para no filtrar por timing si el usuario
    existe o no (mismo criterio que auth.py anterior con HTTP Basic).
    """
    record = get_user_record(username, rdb)
    dummy_hash = "$2b$12$" + "0" * 22 + "." * 31  # hash bcrypt sintácticamente válido, nunca coincide
    if record is None or record.disabled:
        _verify_password(plain_password, dummy_hash)
        return None
    if not _verify_password(plain_password, record.password_hash):
        return None
    return User(**record.model_dump(exclude={"password_hash"}))


def list_users(rdb: redis.Redis | None = None) -> list[User]:
    r = _get_redis(rdb)
    usernames = r.smembers(USERS_INDEX_KEY)
    users = []
    for u in usernames:
        record = get_user_record(u, rdb)
        if record is not None:
            users.append(User(**record.model_dump(exclude={"password_hash"})))
    return sorted(users, key=lambda u: u.username)


def role_at_least(role: Role, minimum: Role) -> bool:
    """True si `role` tiene privilegios >= `minimum` en la jerarquía N1<N2<CISO."""
    return ROLE_LEVEL[role] >= ROLE_LEVEL[minimum]


# ── Gestión desde el dashboard (H43) ─────────────────────────────────────────
# Las reglas de quién puede gestionar a quién viven en user_admin.py; acá
# solo las escrituras. Mismo registro JSON que create_user().

MIN_PASSWORD_LENGTH = 12  # mismo mínimo que scripts/manage_users.py


class UserExistsError(Exception):
    """Alta de un username que ya existe (el alta desde el dashboard nunca
    reemplaza un usuario, a diferencia de create_user() del CLI)."""


def add_user(
    username: str, plain_password: str, role: Role, rdb: redis.Redis | None = None,
) -> User:
    """Alta de un usuario nuevo. No reemplaza uno existente (SET NX).

    Args:
        username: identificador único, case-sensitive.
        plain_password: contraseña en texto plano — se hashea con bcrypt.
        role: "N1" | "N2" | "CISO".
        rdb: cliente Redis opcional (tests).

    Returns:
        El User creado (sin el hash).

    Raises:
        UserExistsError: si el username ya existe.
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    record = UserRecord(
        username=username,
        role=role,
        created_at=datetime.now(timezone.utc).isoformat(),
        password_hash=hash_password(plain_password),
    )
    if not r.set(f"{USERS_KEY_PREFIX}{username}", record.model_dump_json(), nx=True):
        raise UserExistsError(username)
    r.sadd(USERS_INDEX_KEY, username)
    log.info(f"usuario dado de alta desde el dashboard: {username} (rol={role})")
    return User(**record.model_dump(exclude={"password_hash"}))


def _save(record: UserRecord, r: redis.Redis) -> User:
    r.set(f"{USERS_KEY_PREFIX}{record.username}", record.model_dump_json())
    return User(**record.model_dump(exclude={"password_hash"}))


def update_user(
    username: str,
    role: Role | None = None,
    disabled: bool | None = None,
    rdb: redis.Redis | None = None,
) -> User | None:
    """Cambia rol y/o estado. Un cambio de rol o una baja invalidan los JWT
    vigentes del usuario (get_current_user compara rol y estado en cada request).

    Returns:
        El User actualizado, o None si no existe.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    record = get_user_record(username, r)
    if record is None:
        return None
    if role is not None:
        record.role = role
    if disabled is not None:
        record.disabled = disabled
    return _save(record, r)


def set_password(username: str, plain_password: str, rdb: redis.Redis | None = None) -> User | None:
    """Reemplaza la contraseña (hash bcrypt nuevo).

    Returns:
        El User, o None si no existe.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    r = _get_redis(rdb)
    record = get_user_record(username, r)
    if record is None:
        return None
    record.password_hash = hash_password(plain_password)
    return _save(record, r)


def count_active(role: Role, rdb: redis.Redis | None = None) -> int:
    """Cantidad de usuarios habilitados con ese rol exacto.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    return sum(1 for u in list_users(rdb) if u.role == role and not u.disabled)
