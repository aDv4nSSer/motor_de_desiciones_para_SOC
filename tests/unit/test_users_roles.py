"""
Verifica la tabla de usuarios (Redis-backed) y la jerarquía de roles
N1 < N2 < CISO (sección 5 de docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from users import (
    authenticate,
    create_user,
    get_user_record,
    role_at_least,
)


class FakeRedis:
    """Redis mínimo en memoria — lo que users.py y sessions.py necesitan
    (strings con NX, sets, hashes, TTL)."""

    def __init__(self):
        self._kv: dict[str, str] = {}
        self._sets: dict[str, set[str]] = {}
        self._hashes: dict[str, dict[str, str]] = {}
        self._ttl: dict[str, int] = {}

    def set(self, key, value, nx=False):
        if nx and key in self._kv:
            return None
        self._kv[key] = value
        return True

    def get(self, key):
        return self._kv.get(key)

    def sadd(self, key, value):
        self._sets.setdefault(key, set()).add(value)

    def smembers(self, key):
        return self._sets.get(key, set())

    def hset(self, key, field, value):
        self._hashes.setdefault(key, {})[field] = value

    def hexists(self, key, field):
        return field in self._hashes.get(key, {})

    def hgetall(self, key):
        return dict(self._hashes.get(key, {}))

    def hkeys(self, key):
        return list(self._hashes.get(key, {}))

    def hdel(self, key, *fields):
        h = self._hashes.get(key, {})
        return sum(1 for f in fields if h.pop(f, None) is not None)

    def delete(self, *keys):
        n = 0
        for k in keys:
            n += int(self._kv.pop(k, None) is not None) + int(self._hashes.pop(k, None) is not None)
        return n

    def ttl(self, key):
        return self._ttl.get(key, -1)

    def expire(self, key, seconds):
        self._ttl[key] = seconds


class TestCreateAndAuthenticate:
    def test_correct_password_authenticates(self) -> None:
        rdb = FakeRedis()
        create_user("ana", "una-passphrase-larga-123", "N1", rdb=rdb)
        user = authenticate("ana", "una-passphrase-larga-123", rdb=rdb)
        assert user is not None
        assert user.username == "ana"
        assert user.role == "N1"

    def test_wrong_password_rejected(self) -> None:
        rdb = FakeRedis()
        create_user("ana", "una-passphrase-larga-123", "N1", rdb=rdb)
        assert authenticate("ana", "password-incorrecta", rdb=rdb) is None

    def test_unknown_user_rejected_without_raising(self) -> None:
        rdb = FakeRedis()
        assert authenticate("no-existe", "cualquier-cosa", rdb=rdb) is None

    def test_disabled_user_rejected_even_with_correct_password(self) -> None:
        rdb = FakeRedis()
        create_user("bob", "otra-passphrase-larga-456", "CISO", rdb=rdb)
        record = get_user_record("bob", rdb=rdb)
        record.disabled = True
        rdb.set("soc:users:bob", record.model_dump_json())

        assert authenticate("bob", "otra-passphrase-larga-456", rdb=rdb) is None

    def test_password_never_stored_in_plain_text(self) -> None:
        rdb = FakeRedis()
        create_user("carla", "password-super-secreta-789", "N2", rdb=rdb)
        raw = rdb.get("soc:users:carla")
        assert "password-super-secreta-789" not in raw


class TestRoleHierarchy:
    def test_n1_meets_n1_minimum(self) -> None:
        assert role_at_least("N1", "N1") is True

    def test_n1_does_not_meet_n2_minimum(self) -> None:
        assert role_at_least("N1", "N2") is False

    def test_ciso_meets_every_minimum(self) -> None:
        assert role_at_least("CISO", "N1") is True
        assert role_at_least("CISO", "N2") is True
        assert role_at_least("CISO", "CISO") is True

    def test_n2_meets_n1_but_not_ciso(self) -> None:
        assert role_at_least("N2", "N1") is True
        assert role_at_least("N2", "CISO") is False
