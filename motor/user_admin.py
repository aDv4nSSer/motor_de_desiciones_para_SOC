"""
user_admin.py — Gestión de usuarios y sesiones desde el dashboard (H43).

Expone como API lo que antes solo hacía scripts/manage_users.py en `.140`.
Mínimo privilegio (sección 5 de la especificación), con reglas explícitas:

- CISO gestiona a cualquier usuario y asigna cualquier rol.
- N2 gestiona solo cuentas N1 (alta, baja, contraseña, sesiones) y solo
  asigna N1: nunca puede crear ni promover a alguien a su nivel o más.
- N1 no gestiona cuentas (el endpoint ni siquiera le responde: require_role("N2")).
- Nadie se cambia su propio rol ni se da de baja a sí mismo (escalamiento /
  bloqueo accidental); las propias sesiones sí se pueden revocar.
- Nunca se deja el sistema sin un CISO habilitado.

Cada operación (exitosa o denegada) se audita con auth.log_access_event, que
termina en el hash-chain de soc-responses-* (H39).

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import re

import sessions as sess
import users
from auth import log_access_event
from users import ROLE_LEVEL, Role, User

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
BCRYPT_MAX_BYTES = 72  # bcrypt ignora (o rechaza) lo que pasa de 72 bytes


class AdminError(Exception):
    """Operación rechazada. `status` es el código HTTP que corresponde."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def assignable_roles(actor: User) -> list[Role]:
    """Roles que `actor` puede asignar al crear o cambiar una cuenta."""
    if actor.role == "CISO":
        return ["N1", "N2", "CISO"]
    if actor.role == "N2":
        return ["N1"]
    return []


def can_manage(actor: User, target_role: Role) -> bool:
    """True si `actor` puede gestionar una cuenta con rol `target_role`.

    CISO: cualquiera. N2: solo N1 (estrictamente por debajo). N1: ninguna.
    """
    if actor.role == "CISO":
        return True
    return actor.role == "N2" and ROLE_LEVEL[target_role] < ROLE_LEVEL["N2"]


def validate_password(password: str) -> None:
    """Raises AdminError 422 si la contraseña no cumple el mínimo."""
    if len(password) < users.MIN_PASSWORD_LENGTH:
        raise AdminError(422, f"La contraseña debe tener al menos {users.MIN_PASSWORD_LENGTH} caracteres.")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise AdminError(422, f"La contraseña no puede superar {BCRYPT_MAX_BYTES} bytes.")


def _deny(actor: User, event: str, detail: dict, status: int, message: str) -> AdminError:
    log_access_event(actor.username, event, {**detail, "denied": True, "actor_role": actor.role})
    return AdminError(status, message)


def _target(actor: User, username: str, action: str) -> users.UserRecord:
    record = users.get_user_record(username)
    if record is None:
        raise AdminError(404, "Usuario no encontrado.")
    if not can_manage(actor, record.role) and username != actor.username:
        raise _deny(actor, "user_admin_denied", {"target": username, "action": action},
                    403, f"Tu rol ({actor.role}) no puede gestionar cuentas {record.role}.")
    return record


def _ensure_ciso_remains(record: users.UserRecord, new_role: Role | None, new_disabled: bool | None) -> None:
    if record.role != "CISO" or record.disabled:
        return
    loses_ciso = (new_role is not None and new_role != "CISO") or new_disabled is True
    if loses_ciso and users.count_active("CISO") <= 1:
        raise AdminError(409, "Es el único CISO habilitado: el sistema no puede quedar sin CISO.")


def list_accounts(actor: User) -> list[dict]:
    """Usuarios con su cantidad de sesiones activas y si `actor` puede gestionarlos.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    out = []
    for u in users.list_users():
        out.append({
            **u.model_dump(),
            "active_sessions": len(sess.list_sessions(u.username)),
            "manageable": can_manage(actor, u.role) and u.username != actor.username,
            "is_self": u.username == actor.username,
        })
    return out


def create_account(actor: User, username: str, password: str, role: Role) -> User:
    """Alta de una cuenta.

    Raises:
        AdminError: 422 (username/contraseña inválidos), 403 (rol no asignable),
            409 (ya existe).
        redis.RedisError: si Redis no responde.
    """
    if not USERNAME_PATTERN.fullmatch(username):
        raise AdminError(422, "Usuario inválido: 3 a 32 caracteres, minúsculas, números, punto, guion o guion bajo.")
    if role not in assignable_roles(actor):
        raise _deny(actor, "user_admin_denied", {"target": username, "action": "create", "role": role},
                    403, f"Tu rol ({actor.role}) no puede crear cuentas {role}.")
    validate_password(password)
    try:
        created = users.add_user(username, password, role)
    except users.UserExistsError:
        raise AdminError(409, "Ese usuario ya existe.")
    log_access_event(actor.username, "user_created", {"target": username, "role": role})
    return created


def update_account(actor: User, username: str, role: Role | None, disabled: bool | None) -> dict:
    """Cambio de rol y/o alta/baja. Una baja también revoca sus sesiones.

    Returns:
        El usuario actualizado y cuántas sesiones se revocaron.

    Raises:
        AdminError: 403/404/409/422 según la regla que falle.
        redis.RedisError: si Redis no responde.
    """
    if role is None and disabled is None:
        raise AdminError(422, "No hay cambios que aplicar.")
    if username == actor.username:
        raise _deny(actor, "user_admin_denied", {"target": username, "action": "update_self"},
                    403, "No puedes cambiar tu propio rol ni darte de baja.")
    record = _target(actor, username, "update")
    if role is not None and role not in assignable_roles(actor):
        raise _deny(actor, "user_admin_denied", {"target": username, "action": "set_role", "role": role},
                    403, f"Tu rol ({actor.role}) no puede asignar el rol {role}.")
    _ensure_ciso_remains(record, role, disabled)
    updated = users.update_user(username, role=role, disabled=disabled)
    if updated is None:
        raise AdminError(404, "Usuario no encontrado.")
    revoked = 0
    if disabled is True or (role is not None and role != record.role):
        # El token viejo ya no pasaría get_current_user (rol/estado), pero se
        # borran los registros para que "sesiones activas" no las muestre.
        revoked = sess.revoke_all_sessions(username)
    if role is not None and role != record.role:
        log_access_event(actor.username, "user_role_changed",
                         {"target": username, "from": record.role, "to": role})
    if disabled is not None and disabled != record.disabled:
        log_access_event(actor.username, "user_disabled" if disabled else "user_enabled", {"target": username})
    return {"user": updated.model_dump(), "revoked_sessions": revoked}


def reset_password(actor: User, username: str, password: str) -> dict:
    """Reemplaza la contraseña de otra cuenta y revoca todas sus sesiones.

    Raises:
        AdminError: 403/404/422.
        redis.RedisError: si Redis no responde.
    """
    if username == actor.username:
        raise AdminError(403, "Tu propia contraseña se cambia con scripts/manage_users.py, no desde este panel.")
    _target(actor, username, "reset_password")
    validate_password(password)
    users.set_password(username, password)
    revoked = sess.revoke_all_sessions(username)
    log_access_event(actor.username, "user_password_reset", {"target": username, "revoked_sessions": revoked})
    return {"revoked_sessions": revoked}


def visible_sessions(actor: User) -> list[dict]:
    """Sesiones activas que `actor` puede ver: CISO todas; N2 las de cuentas
    N1 y las propias.

    Raises:
        redis.RedisError: si Redis no responde.
    """
    out = []
    for s in sess.list_all_sessions():
        if s.username == actor.username or can_manage(actor, s.role):  # type: ignore[arg-type]
            out.append({**sess.session_view(s), "is_self": s.username == actor.username})
    return out


def revoke(actor: User, username: str, jti: str | None, current_jti: str) -> dict:
    """Revoca un token puntual (`jti`) o todos los de `username` (jti=None).

    Args:
        actor: quien revoca.
        username: dueño de las sesiones.
        jti: sesión puntual, o None para todas.
        current_jti: sesión desde la que se hace el pedido (revocarla equivale
            a cerrar la propia sesión; se informa al cliente).

    Raises:
        AdminError: 403/404.
        redis.RedisError: si Redis no responde.
    """
    if username != actor.username:
        _target(actor, username, "revoke_session")
    if jti is None:
        count = sess.revoke_all_sessions(username)
        log_access_event(actor.username, "sessions_revoked_all", {"target": username, "count": count})
        return {"revoked": count, "own_session_revoked": username == actor.username}
    if not sess.revoke_session(username, jti):
        raise AdminError(404, "La sesión ya no existe (expiró o fue revocada).")
    log_access_event(actor.username, "session_revoked", {"target": username, "jti": jti})
    return {"revoked": 1, "own_session_revoked": username == actor.username and jti == current_jti}
