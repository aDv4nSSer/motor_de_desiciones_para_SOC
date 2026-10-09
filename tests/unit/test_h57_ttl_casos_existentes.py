"""H57 (ítem 1.2): TTL escalonado de los casos previos, sin leer su contenido."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "motor"))
spec = importlib.util.spec_from_file_location("h57", ROOT / "scripts/mantenimiento/h57_ttl_casos_existentes.py")
h57 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h57)

AUTO = [{"state": "abierto", "at": "x", "note": "Caso creado automáticamente (R1, tier T2)"}]


class FakeRedis:
    def __init__(self, n: int, maxmemory: int = 1000, used: int = 100):
        self.kv = {f"soc:cases:c{i}": json.dumps({"state": "abierto", "history": AUTO}) for i in range(n)}
        self.ttl = {k: -1 for k in self.kv}
        self.index = [f"c{i}" for i in range(n)]
        self.mem = {"used_memory": used, "maxmemory": maxmemory}
        self.evicted = 0
        self.reads = 0

    def sscan(self, key, cursor=0, count=10):
        nxt = cursor + count
        return (0 if nxt >= len(self.index) else nxt), self.index[cursor:nxt]

    def info(self, section):
        return self.mem if section == "memory" else {"evicted_keys": self.evicted}

    def pipeline(self, transaction=True):
        return FakePipe(self)

    def mget(self, keys):
        self.reads += len(keys)
        return [self.kv.get(k) for k in keys]


class FakePipe:
    def __init__(self, r):
        self.r, self.ops = r, []

    def expire(self, key, ttl, nx=False):
        self.ops.append((key, ttl, nx))

    def execute(self):
        out = []
        for key, ttl, nx in self.ops:
            ok = key in self.r.kv and (not nx or self.r.ttl[key] == -1)
            if ok:
                self.r.ttl[key] = ttl
            out.append(ok)
        return out


def test_ttl_escalonado_entre_2_y_14_horas() -> None:
    ttls = [h57.staggered_ttl(f"case-{i}") for i in range(2000)]
    assert min(ttls) >= 2 * 3600 and max(ttls) < 14 * 3600
    assert len({t // 3600 for t in ttls}) == 12  # repartido en las 12 horas


def test_detecta_casos_tocados_por_un_analista() -> None:
    assert not h57.touched_by_analyst({"state": "abierto", "history": AUTO})
    assert h57.touched_by_analyst({"state": "cerrado", "history": AUTO})
    assert h57.touched_by_analyst({"state": "abierto", "history": AUTO + [{"note": "lo miro", "actor": "n1"}]})


def test_apply_respeta_exclusion_y_nx_sin_leer_contenido(monkeypatch) -> None:
    r = FakeRedis(1000)
    r.ttl["soc:cases:c5"] = 604800  # caso nuevo de H57: ya tiene TTL, NX no lo toca
    res = h57.apply(r, excluded={"c7"}, pause=0)
    assert res == {"aplicados": 998, "sin_cambio": 1, "excluidos": 1, "lotes": 10}
    assert r.ttl["soc:cases:c7"] == -1 and r.ttl["soc:cases:c5"] == 604800
    assert r.reads == 0  # --apply no lee el contenido de los casos


def test_apply_aborta_si_aparecen_desalojos() -> None:
    r = FakeRedis(5000)
    orig, calls = r.info, {"stats": 0}

    def info(section):
        if section == "stats":
            calls["stats"] += 1
            if calls["stats"] > 1:
                r.evicted = 1  # aparece un desalojo después de la línea base
        return orig(section)
    r.info = info
    res = h57.apply(r, excluded=set(), pause=0)
    assert "abortado" in res and res["lotes"] == h57.GUARD_EVERY


def test_apply_aborta_con_memoria_sobre_el_90() -> None:
    r = FakeRedis(5000, maxmemory=1000, used=950)
    res = h57.apply(r, excluded=set(), pause=0)
    assert "used_memory" in res["abortado"]
