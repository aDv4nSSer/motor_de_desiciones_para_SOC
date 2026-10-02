"""H38, segunda pasada SOLO LECTURA: atribución correcta (el gap entre dos
processed_at es la duración de la tarea ANTERIOR) + tiempo por etapa."""
import collections, ipaddress, json, os, statistics as st, sys, time
sys.path.insert(0, ".")
import redis
from response.config import get_settings
from response.enrichment import _crowdsec_lookup, _reverse_dns

r = redis.Redis(password=os.environ["REDIS_PASSWORD"], decode_responses=True)
pct = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(p / 100 * len(xs)))]

recs = []
for _, f in r.xrevrange("soc:response:audit", count=4000):
    try:
        a = json.loads(f["data"])
    except Exception:
        continue
    if a.get("processed_at") and ("enrichment" in a or "accion_recomendada" in a):
        recs.append(a)
recs.sort(key=lambda a: a["processed_at"])

def profile(a):
    e = a.get("enrichment") or {}
    ip = a.get("src_ip") or ""
    try:
        if ipaddress.ip_address(ip).is_private:
            return "IP privada (sin TI)"
    except ValueError:
        return "sin src_ip"
    notes = " ".join(e.get("notes") or [])
    # Post-H38-C: un fallo servido desde negative cache o el corte por cuota
    # no llama a la API; se clasifica aparte (si no, su nota "ReadTimeout"
    # lo haría pasar por timeout real).
    if "evento stale, solo caché" in notes:
        return "TI stale solo caché (sin llamada)"
    if "negative cache" in notes or "cuota diaria agotada" in notes:
        return "TI negative cache / cuota (sin llamada)"
    if (a.get("block") or {}).get("reason", "").startswith("stale_backlog"):
        pass  # la antigüedad no cambia el costo de R1; se reporta aparte abajo
    if "Timeout" in notes or "ConnectError" in notes:
        return "TI timeout/error de red"
    if "HTTP 429" in notes:
        return "TI 429 (cuota)"
    return "TI desde caché" if e.get("cached") else "TI consulta real OK"

rows = [(profile(a), b["processed_at"] - a["processed_at"], a.get("tier"), (a.get("block") or {}).get("action"))
        for a, b in zip(recs, recs[1:]) if 0 <= b["processed_at"] - a["processed_at"] <= 120]
tot = sum(d for _, d, *_ in rows)
print(f"B') {len(rows)} tareas, {tot:.0f}s -> {len(rows) / tot:.2f} tareas/s")
by = collections.defaultdict(list)
for p, d, *_ in rows:
    by[p].append(d)
for p, ds in sorted(by.items(), key=lambda kv: -sum(kv[1])):
    print(f"   {p:26s} n={len(ds):5d} ({100 * len(ds) / len(rows):4.1f}%)  mediana {st.median(ds):5.3f}s  p95 {pct(ds, 95):5.2f}s  max {max(ds):5.2f}s -> {100 * sum(ds) / tot:4.1f}% del tiempo")
for t in (1, 2, 3):
    ds = [d for _, d, tier, _ in rows if tier == t]
    print(f"   T{t}: n={len(ds)}  {100 * sum(ds) / tot:4.1f}% del tiempo, mediana {st.median(ds):.3f}s")
r2 = [d for _, d, _, act in rows if act == "block"]
if r2:
    print(f"   R2 con bloqueo ejecutado (Wazuh API): n={len(r2)} mediana {st.median(r2):.2f}s p95 {pct(r2, 95):.2f}s -> {100 * sum(r2) / tot:.1f}% del tiempo")
stale = sum(1 for a in recs if (a.get("block") or {}).get("reason", "").startswith("stale_backlog"))
ages = [a["event_age_seconds"] for a in recs if a.get("event_age_seconds") is not None]
if ages:
    print(f"   antigüedad de detección: mediana {st.median(ages) / 3600:.2f} h, máx {max(ages) / 3600:.2f} h; R2 omitido por antigüedad: {stale}")
priv = collections.Counter(a.get("src_ip") for a in recs if profile(a) == "IP privada (sin TI)")
print(f"   IPs privadas distintas: {len(priv)} -> {priv.most_common(4)}")

s = get_settings()
for ip in ("10.10.10.3", "10.30.30.2"):
    ts = []
    for _ in range(5):
        t = time.perf_counter(); _reverse_dns(ip); ts.append(time.perf_counter() - t)
    print(f"C') DNS inverso {ip}: mediana {st.median(ts):.3f}s max {max(ts):.3f}s")
ts = []
for _ in range(5):
    t = time.perf_counter(); _crowdsec_lookup("10.10.10.3", s, r); ts.append(time.perf_counter() - t)
print(f"E) CrowdSec lookup (lectura de caché): mediana {st.median(ts):.3f}s max {max(ts):.3f}s (ttl caché {s.crowdsec_cache_ttl}s)")
print(f"F) caché crowdsec existe ahora: {r.exists(s.enrich_cache_prefix + 'crowdsec:decisions')}, TTL restante {r.ttl(s.enrich_cache_prefix + 'crowdsec:decisions')}s")
