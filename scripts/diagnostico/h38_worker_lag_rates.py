"""Diagnóstico SOLO LECTURA del atraso de response-worker (H38). No escribe en Redis,
no llama APIs de TI, no reinicia nada."""
import collections, ipaddress, json, os, socket, statistics as st, time
import redis

r = redis.Redis(password=os.environ["REDIS_PASSWORD"], decode_responses=True)
S, G = "soc:response:tasks", "response-workers"

def grp():
    return next(g for g in r.xinfo_groups(S) if g["name"] == G)

def pct(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(p / 100 * len(xs)))] if xs else None

# A) tasa de entrada vs procesamiento, 60 s
g0, s0, t0 = grp(), r.xinfo_stream(S)["entries-added"], time.time()
time.sleep(60)
g1, s1, t1 = grp(), r.xinfo_stream(S)["entries-added"], time.time()
dt = t1 - t0
inn, out = (s1 - s0) / dt, (g1["entries-read"] - g0["entries-read"]) / dt
print(f"A) entrada {inn:.2f} tareas/s | procesadas {out:.2f} tareas/s | lag {g1['lag']} | pending {g1['pending']}")
last = int(g1["last-delivered-id"].split("-")[0]) / 1000
print(f"   atraso del último entregado: {(time.time() - last) / 3600:.2f} h")

# B) costo por tarea según perfil, desde las últimas respuestas auditadas
recs = []
for _, f in r.xrevrange("soc:response:audit", count=4000):
    try:
        a = json.loads(f["data"])
    except Exception:
        continue
    if a.get("processed_at") and ("enrichment" in a or "accion_recomendada" in a):
        recs.append(a)
recs.sort(key=lambda a: a["processed_at"])
rows = []
for prev, cur in zip(recs, recs[1:]):
    d = cur["processed_at"] - prev["processed_at"]
    if d < 0 or d > 120:
        continue
    e = cur.get("enrichment") or {}
    ip = cur.get("src_ip") or e.get("src_ip") or ""
    try:
        priv = ipaddress.ip_address(ip).is_private
    except ValueError:
        priv = True
    notes = " ".join(e.get("notes") or [])
    if not ip:
        prof = "sin src_ip"
    elif priv:
        prof = "IP privada (sin TI)"
    elif "Timeout" in notes or "ConnectError" in notes:
        prof = "TI con timeout/error de red"
    elif "HTTP 429" in notes:
        prof = "TI con 429 (cuota)"
    elif e.get("cached"):
        prof = "TI desde caché"
    else:
        prof = "TI consulta real OK"
    b = cur.get("block") or {}
    rows.append((prof, d, cur.get("tier"), b.get("action"), ip))
n = len(rows)
tot = sum(x[1] for x in rows)
print(f"B) {n} tareas consecutivas, {tot:.0f} s en total ({n / tot:.2f} tareas/s), mediana {st.median(x[1] for x in rows):.2f} s, p95 {pct([x[1] for x in rows], 95):.2f} s")
by = collections.defaultdict(list)
for prof, d, *_ in rows:
    by[prof].append(d)
for prof, ds in sorted(by.items(), key=lambda kv: -sum(kv[1])):
    print(f"   {prof:28s} n={len(ds):5d} ({100 * len(ds) / n:4.1f}%)  mediana {st.median(ds):5.2f}s  p95 {pct(ds, 95):5.2f}s  -> {100 * sum(ds) / tot:4.1f}% del tiempo")
tiers = collections.Counter(x[2] for x in rows)
print(f"   tiers procesados: {dict(sorted(tiers.items()))}  (T1 = {100 * tiers.get(1, 0) / n:.1f}%)")
t1_time = sum(x[1] for x in rows if x[2] == 1)
print(f"   tiempo gastado en T1: {100 * t1_time / tot:.1f}%")
acts = collections.Counter(x[3] for x in rows if x[3])
print(f"   acciones R2: {dict(acts)}")
pub = [x[4] for x in rows if x[0] not in ("IP privada (sin TI)", "sin src_ip")]
print(f"   IPs públicas distintas: {len(set(pub))} de {len(pub)} tareas con IP pública")

# C) DNS inverso (sin timeout ni caché en el código): costo real
sample = list(dict.fromkeys(pub))[:15]
dns = []
for ip in sample:
    t = time.perf_counter()
    try:
        socket.gethostbyaddr(ip)
    except OSError:
        pass
    dns.append(time.perf_counter() - t)
if dns:
    print(f"C) DNS inverso en {len(dns)} IPs reales: mediana {st.median(dns):.2f}s, max {max(dns):.2f}s")

# D) latencia de Redis
lat = []
for _ in range(200):
    t = time.perf_counter(); r.ping(); lat.append((time.perf_counter() - t) * 1000)
print(f"D) Redis PING: mediana {st.median(lat):.3f} ms, p99 {pct(lat, 99):.3f} ms")
