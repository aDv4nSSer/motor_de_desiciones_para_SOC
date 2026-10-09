"""H57 (a1): índice de usuarios. El login re-registra; si el índice está vacío o
no contiene al usuario autenticado, no es confiable; reparación sin smoke-*."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

import users

# ── a1 ───────────────────────────────────────────────────────────────────────

class FakeUsersRedis:
    def __init__(self, members=()):
        self.members = set(members)

    def scard(self, key):
        return len(self.members)

    def sismember(self, key, m):
        return m in self.members

    def sadd(self, key, m):
        self.members.add(m)


class TestIndiceDeUsuarios:
    def test_indice_vacio_no_es_confiable(self) -> None:
        st = users.users_index_status("aiayala", FakeUsersRedis())
        assert st["reliable"] is False and "vacío" in st["reason"]

    def test_indice_sin_el_usuario_autenticado_no_es_confiable(self) -> None:
        st = users.users_index_status("aiayala", FakeUsersRedis({"otro"}))
        assert st["reliable"] is False and "aiayala" in st["reason"]

    def test_el_login_vuelve_a_registrar_al_usuario(self) -> None:
        r = FakeUsersRedis()
        users._ensure_indexed("aiayala", r)
        assert users.users_index_status("aiayala", r)["reliable"] is True


# ── Script de reparación del índice de usuarios ──────────────────────────────

def test_reparacion_excluye_smoke_y_no_inventa_usuarios(monkeypatch) -> None:
    import importlib.util
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("rep", root / "scripts/mantenimiento/h57_reparar_indice_usuarios.py")
    rep = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rep)

    class Rec:
        def __init__(self, disabled):
            self.disabled = disabled
    records = {"aiayala": Rec(False), "smoke-ciso": Rec(False), "viejo": Rec(True)}
    monkeypatch.setattr(rep, "get_user_record", lambda name, rdb: records.get(name))
    r = FakeUsersRedis()
    p = rep.plan(r, ["aiayala", "smoke-ciso", "viejo", "fantasma"])
    assert p == {"agregar": ["aiayala"], "ya_indexados": [], "excluidos_smoke": ["smoke-ciso"],
                 "sin_registro": ["fantasma"], "deshabilitados": ["viejo"]}
