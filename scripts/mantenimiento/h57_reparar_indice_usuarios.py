#!/usr/bin/env python3
"""
h57_reparar_indice_usuarios.py — Reconstruye soc:users:index (H57, a1).

El índice de usuarios desapareció de Redis (probable desalojo de H54). El
login sigue andando (lee soc:users:<usuario>) y desde H57 cada login
re-registra al usuario, pero hasta que cada uno entre la vista de
Cumplimiento y la de sesiones no los ven. Este script los vuelve a agregar.

Solo usuarios legítimos: el registro existe, se puede leer y no está
deshabilitado. Las cuentas smoke-* (pruebas de H44) se excluyen siempre.
Por defecto solo lista lo que haría (dry-run); --apply hace los SADD.

Candidatos: por defecto, la lista explícita de --usuarios. Con --descubrir se
buscan por SCAN MATCH soc:users:* mediante redis_guard (COUNT 100, pausas,
tope de iteraciones): recorre todo el keyspace, así que se usa solo si no se
conoce la lista.

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/mantenimiento/h57_reparar_indice_usuarios.py --usuarios aiayala
    python3 ../scripts/mantenimiento/h57_reparar_indice_usuarios.py --usuarios aiayala --apply
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from redis_guard import guarded_scan
from users import USERS_INDEX_KEY, USERS_KEY_PREFIX, get_user_record

EXCLUDED_PREFIXES = ("smoke-",)


def candidates(rdb, explicit: list[str], discover: bool) -> list[str]:
    found = set(explicit)
    if discover:
        for batch in guarded_scan(rdb, match=f"{USERS_KEY_PREFIX}*", count=100, pause=0.05, max_iterations=20_000):
            for key in batch:
                name = key[len(USERS_KEY_PREFIX):]
                if name and name != "index":
                    found.add(name)
    return sorted(found)


def plan(rdb, names: list[str]) -> dict[str, list[str]]:
    out = {"agregar": [], "ya_indexados": [], "excluidos_smoke": [], "sin_registro": [], "deshabilitados": []}
    for name in names:
        if name.startswith(EXCLUDED_PREFIXES):
            out["excluidos_smoke"].append(name)
            continue
        rec = get_user_record(name, rdb)
        if rec is None:
            out["sin_registro"].append(name)
        elif rec.disabled:
            out["deshabilitados"].append(name)
        elif rdb.sismember(USERS_INDEX_KEY, name):
            out["ya_indexados"].append(name)
        else:
            out["agregar"].append(name)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--usuarios", default="", help="lista separada por comas")
    ap.add_argument("--descubrir", action="store_true", help="buscar por SCAN guardado (recorre el keyspace)")
    ap.add_argument("--apply", action="store_true", help="hacer los SADD (default: solo listar)")
    args = ap.parse_args()
    explicit = [u.strip() for u in args.usuarios.split(",") if u.strip()]
    if not explicit and not args.descubrir:
        ap.error("pasá --usuarios o --descubrir")
    from users import _get_redis

    rdb = _get_redis()
    p = plan(rdb, candidates(rdb, explicit, args.descubrir))
    for k, v in p.items():
        print(f"{k}: {v}")
    if args.apply and p["agregar"]:
        for name in p["agregar"]:
            rdb.sadd(USERS_INDEX_KEY, name)
        print(f"agregados: {p['agregar']} | SCARD {rdb.scard(USERS_INDEX_KEY)}")
    elif not args.apply:
        print("dry-run: no se escribió nada")
    return 0


if __name__ == "__main__":
    sys.exit(main())
