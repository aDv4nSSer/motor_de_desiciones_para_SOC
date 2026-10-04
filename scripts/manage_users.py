#!/usr/bin/env python3
"""
manage_users.py — CLI para crear/listar usuarios del dashboard (Redis-backed).

Desde H43 las cuentas también se gestionan desde el dashboard (vista
"Usuarios y sesiones", N2+/CISO, reglas de mínimo privilegio en
motor/user_admin.py). Este script sigue siendo la vía para crear el primer
CISO (el panel exige estar autenticado) y para cambiar la propia contraseña;
se corre directamente en `.140` con acceso a Redis. Ojo: `create` reemplaza
un usuario existente y no revoca sus sesiones (el panel sí).

Uso:
    python scripts/manage_users.py create <username> <role: N1|N2|CISO>
        (pide la contraseña de forma interactiva, sin ecoar en pantalla)
    python scripts/manage_users.py list

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

# Permite correr el script desde la raíz del repo sin instalar el paquete.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "motor"))

from users import ROLE_LEVEL, create_user, list_users


def cmd_create(args: argparse.Namespace) -> None:
    if args.role not in ROLE_LEVEL:
        print(f"Rol inválido: {args.role!r}. Debe ser uno de: {', '.join(ROLE_LEVEL)}", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass(f"Contraseña para {args.username}: ")
    confirm = getpass.getpass("Confirmar contraseña: ")
    if password != confirm:
        print("Las contraseñas no coinciden.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 12:
        print("La contraseña debe tener al menos 12 caracteres.", file=sys.stderr)
        sys.exit(1)

    user = create_user(args.username, password, args.role)
    print(f"Usuario creado: {user.username} (rol={user.role})")


def cmd_list(_args: argparse.Namespace) -> None:
    users = list_users()
    if not users:
        print("No hay usuarios registrados todavía.")
        return
    for u in users:
        estado = "deshabilitado" if u.disabled else "activo"
        print(f"  {u.username:20s} rol={u.role:5s} {estado}  (creado {u.created_at})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gestión de usuarios del dashboard R-SOAR")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Crear o actualizar un usuario")
    p_create.add_argument("username")
    p_create.add_argument("role", choices=list(ROLE_LEVEL))
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="Listar usuarios existentes")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
