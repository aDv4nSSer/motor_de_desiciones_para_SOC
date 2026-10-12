# Análisis E y F (solo lectura): tendencia diaria 3–12 oct y causas de aprobación humana del período 2

Extraído 2026-10-12T16:26:08.393772+00:00 UTC (12-oct 13:26 -03), un solo script en `.140` (`motor/` como directorio de trabajo). Días UTC. Reproducir: ver "Consulta exacta" al final de este documento. Salida cruda y CSV archivados fuera de git; hashes en `manifiesto_ef.md`.

Alcance: solo lectura sobre `soc-decisions-*` y `soc-responses-*` (agregaciones; `top_hits` de 1 documento por IP en F y R). No toca código ni lógica de decisión.

## Definiciones comunes

- **UTC:** todos los días son días UTC; el período 2 es 2026-10-09T14:21:00Z a 2026-10-12T14:21:00Z (9-oct 11:21 a 12-oct 11:21 -03, corte de R4).
- **Safelist de 13 IPs:** `get_settings().safelist` de `response.config` (13 IPs planas, ningún CIDR; el script lo verifica con un `assert`). Se excluyen (`must_not` sobre `src_ip`) de IPs con T3, IPs derivadas y bloqueos. Las decisiones, T2/T3, expiradas y manuales **no** se filtran: no tienen `src_ip` en `soc-decisions-*` o no aplica.
- **Primer bloqueo:** primer día, dentro de la ventana 3–12-oct, en que la IP tiene un bloqueo ejecutado (`block_action = block` y `block_enforced = true`). **Re-bloqueo:** IP bloqueada un día posterior a su primer bloqueo en la ventana (volvió a bloquearse al vencer el TTL). Las IPs ya bloqueadas antes del 3-oct cuentan como "primer bloqueo" en su primer día dentro de la ventana.
- **IPs derivadas a aprobación (proxy de aprobaciones creadas):** IPs distintas con una respuesta T3 `block_action = block_pending_approval`. Es un proxy: el registro de aprobaciones deduplica por IP (una abierta por IP) y no hay un evento de creación consultable, así que no se cuenta el número exacto de aprobaciones creadas por día.
- **Aprobaciones expiradas:** documentos `event_type = approval_expired` por día del evento (una por aprobación). **Aprobaciones manuales:** documentos `event_type = manual_approval` (aprobaciones resueltas por un operador).
- **Decisiones, T2 y T3:** documentos de `soc-decisions-*` por día de `timestamp` y `tier`.
- **Cardinalidades:** `cardinality` con `precision_threshold` 40000 (exactas en estos volúmenes).

## E) Tendencia diaria, 3–12 oct

| Día (UTC) | Decisiones | T2 | T3 | T3/T2 | IPs con T3 | IPs derivadas a aprobación | IPs bloqueadas | Primer bloqueo | Re-bloqueo | Aprob. expiradas | Aprob. manuales |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-10-03 | 390.982 | 75.681 | 10.206 | 0,13 | 503 | 492 | 17 | 17 | 0 | 545 | 0 |
| 2026-10-04 | 603.499 | 107.360 | 32.191 | 0,30 | 538 | 527 | 276 | 271 | 5 | 1.529 | 0 |
| 2026-10-05 | 658.412 | 160.978 | 34.285 | 0,21 | 659 | 655 | 254 | 5 | 249 | 1.729 | 0 |
| 2026-10-06 | 282.785 | 96.297 | 29.702 | 0,31 | 478 | 477 | 264 | 4 | 260 | 1.536 | 0 |
| 2026-10-07 | 203.602 | 80.714 | 27.325 | 0,34 | 525 | 481 | 287 | 21 | 266 | 1.273 | 0 |
| 2026-10-08 | 252.795 | 91.146 | 25.124 | 0,28 | 555 | 541 | 284 | 19 | 265 | 1.288 | 0 |
| 2026-10-09 | 324.734 | 122.147 | 30.854 | 0,25 | 500 | 483 | 287 | 15 | 272 | 1.403 | 0 |
| 2026-10-10 | 366.008 | 140.066 | 29.584 | 0,21 | 470 | 221 | 375 | 97 | 278 | 143 | 65 |
| 2026-10-11 | 272.692 | 95.088 | 29.108 | 0,31 | 473 | 210 | 383 | 94 | 289 | 202 | 0 |
| 2026-10-12 (parcial) | 192.438 | 93.444 | 12.889 | 0,14 | 457 | 70 | 400 | 96 | 304 | 137 | 1 |

### Antes y después

- **Período 1:** promedio de los días completos 5, 6, 7 y 8-oct.
- **Período 2:** 11-oct, un solo día completo.
- **Excluidos:** el 10-oct (65 aprobaciones manuales, incluida la prueba de operador), el 9-oct (contiene el corte de R4 a las 14:21Z), el 3 y 4-oct (arranque de la serie) y el 12-oct (parcial, hasta las 16:26Z).

| Métrica | Período 1: promedio 5–8-oct | Período 2: 11-oct | Cambio |
|---|---|---|---|
| Decisiones | 349.398 | 272.692 | −22,0 % |
| T2 | 107.284 | 95.088 | −11,4 % |
| T3 | 29.109 | 29.108 | −0,0 % |
| T3/T2 (promedio de las razones diarias) | 0,28 | 0,31 | +7,8 % |
| IPs con T3 | 554 | 473 | −14,7 % |
| IPs derivadas a aprobación (proxy de aprobaciones creadas) | 538 | 210 | −61,0 % |
| IPs bloqueadas | 272 | 383 | +40,7 % |
| Primer bloqueo | 12 | 94 | +667,3 % |
| Re-bloqueo | 260 | 289 | +11,2 % |
| Aprobaciones expiradas | 1.456 | 202 | −86,1 % |

**Lectura.** T3 (29.108 contra 29.109 de promedio) y la razón T3/T2 del 11-oct caen dentro del rango diario del período 1 (T3 25.124–34.285; razón 0,21–0,34). Las IPs con T3 (473) quedan 5 por debajo del mínimo diario de ese período (478) y las decisiones y T2 bajan 22 % y 11 %. Lo que cambia de nivel es la parte de la respuesta: las IPs derivadas a aprobación (−61 %) y las expiraciones (−86 %) bajan, y las IPs bloqueadas (+41 %) y los primeros bloqueos suben (de 12 a 94 al día; la base del período 1 es pequeña, así que el porcentaje exagera). El re-bloqueo casi no cambia. **Es una coincidencia temporal con el corte de R4 (9-oct 14:21Z), no una prueba de causalidad:** no se probó con un experimento ni se descartaron otras causas.

**Límites de interpretación.**
- Un solo día en el período 2 y cuatro en el período 1: no hay intervalo de confianza; el 11-oct es un domingo y no se probó que la actividad de los domingos sea comparable.
- El 10-oct (65 manuales) y el 12-oct (parcial) quedan fuera de la comparación, pero la tabla los muestra.
- El 3-oct es el arranque de la serie (17 IPs bloqueadas) y el 4-oct tiene la mayor parte de los "primer bloqueo" de la ventana inicial; no se comparan.
- "Primer bloqueo" depende del inicio de la ventana: las IPs bloqueadas antes del 3-oct aparecen como primer bloqueo.
- El hueco de H54 (8-oct 03:32:41 a 03:32:45Z) y el restart del 9-oct (13,8 s) no se excluyen: a escala diaria son irrelevantes. La ventana H25 (18-ago a 04-sep) queda fuera del rango.
- No se analizó qué otros cambios coincidieron con el corte del 9-oct (por ejemplo `fase3a-cuota`, el cambio de régimen del bucket de AbuseIPDB o el uso del dashboard).

### Perfil de las IPs con T3 (verificación de robustez)

Pregunta: ¿cambió el tipo de IP que llega a T3 entre períodos? Medida: porcentaje de IPs con T3 cuyo OTX tiene al menos 1 pulso, por día, 5 al 12-oct. Una IP cuenta una vez por día y se clasifica por su **último** T3 de ese día (los campos `payload.*` no están indexados; no se pueden filtrar ni agregar, por eso el script lee el `top_hits` de cada par día-IP).

| Día (UTC) | IPs con T3 | IPs con OTX consultada | IPs con OTX ≥ 1 pulso | % sobre IPs con T3 | % sobre IPs con OTX consultada |
|---|---|---|---|---|---|
| 2026-10-05 | 659 | 620 | 527 | 80,0 % | 85,0 % |
| 2026-10-06 | 478 | 452 | 429 | 89,7 % | 94,9 % |
| 2026-10-07 | 525 | 462 | 431 | 82,1 % | 93,3 % |
| 2026-10-08 | 555 | 523 | 494 | 89,0 % | 94,5 % |
| 2026-10-09 | 500 | 464 | 454 | 90,8 % | 97,8 % |
| 2026-10-10 | 470 | 452 | 441 | 93,8 % | 97,6 % |
| 2026-10-11 | 473 | 452 | 430 | 90,9 % | 95,1 % |
| 2026-10-12 (parcial) | 457 | 437 | 419 | 91,7 % | 95,9 % |

Período 1 (5–8-oct): 85,2 % sobre IPs con T3 (rango 80,0–89,7), 91,9 % sobre IPs con OTX consultada (rango 85,0–94,9) y OTX consultada en 92,7 % de las IPs. Período 2 (11-oct): 90,9 %, 95,1 % y 95,6 %.

**Lectura.** El perfil por pulsos de OTX es parecido, con un aumento leve en el período 2. Sobre las IPs con T3, el 11-oct está 5,7 puntos sobre el promedio del período 1 (90,9 % contra 85,2 %); de ese salto, unos 2,9 puntos vienen de que OTX se consultó en más IPs (95,6 % contra 92,7 %) y unos 3,2 puntos de una mayor proporción con pulsos entre las IPs consultadas (95,1 % contra 91,9 %, apenas sobre el máximo diario del período 1, 94,9 %). El 10 y el 12-oct (93,8 % y 91,7 %) quedan en la misma zona. Esto es **consistente** con que el cambio del 10-oct en bloqueos y aprobaciones venga del régimen y no de otro tipo de atacante, pero no lo demuestra: solo mide un atributo (pulsos de OTX), y el leve aumento significa que el perfil no es idéntico.

## F) Causas de aprobación humana en el período 2

**Población:** IPs distintas, sin infra propia, con al menos una respuesta T3 `block_action = block_pending_approval` entre 2026-10-09T14:21:00Z y 2026-10-12T14:21:00Z. Cada IP se clasifica por su **último** registro dentro de la ventana, con el mismo criterio que `frontend/operativo/src/lib/ti.ts` (`sourceStatus`) para distinguir valor, política, no aplica, error y sin dato. Las categorías son excluyentes y se asignan en este orden: error de TI (C), luego D, luego A, luego B, luego otro.

| Causa | IPs distintas | % |
|---|---|---|
| A. OTX corrobora (≥ 1 pulso) y AbuseIPDB omitida por política de cuota (1/2) | 318 | 58,9 % |
| B. OTX consultada con 0 pulsos | 53 | 9,8 % |
| C. Error de TI (en todos los casos, OTX) | 90 | 16,7 % |
| D. 1/2 con ambas fuentes consultadas | 79 | 14,6 % |
| **Total** | **540** | 100 % |

Detalle de C: abuseipdb=politica otx=error: 58; abuseipdb=valor otx=error: 32.

**Límites de interpretación.**
- La población son IPs con T3 pendiente de aprobación en la ventana, no aprobaciones creadas ni resueltas; una IP puede además haberse bloqueado automáticamente en otro momento de la ventana.
- Una IP se clasifica por su último registro: si su estado cambió durante la ventana, solo cuenta el último.
- "Política de cuota" agrupa las notas de R1 `throttling`, `r2_min_tier`, `stale`, `no decisiva` y `cuota diaria agotada`. En A la nota es la de throttling; no se separó "presupuesto" de "no decisiva" más allá de eso.
- C es "hubo error", no "hubo amenaza": una fuente con error no equivale a "sin evidencia" (H64).
- Los 540 resultados por IP están en `f_ips_periodo2.csv` (archivo fuera de git).

## Consulta exacta

Se ejecuta en `.140` desde `~/tesis/repo/motor`: `python3 - < consulta_ef.py > salida_cruda.json`. Genera E, la verificación de robustez (R) y F en un solo recorrido; los CSV del archivo salen de ese JSON.

```python
"""Análisis E y F (solo lectura). Se ejecuta en .140 desde motor/: python3 - < consulta_ef.py > salida_cruda.json
E: tendencia diaria 3-12 oct; F: causas de aprobación humana del período 2; R: perfil OTX de las IPs con T3.
Todas las fechas en UTC. Solo agregaciones (_search con size 0, salvo top_hits size 1 por IP en F)."""
import sys, json, base64, urllib.request, urllib.error, collections
from datetime import datetime, timezone
sys.path.insert(0, ".")
import dashboard
from response.config import get_settings


def rq(method, path, body=None):
    h = {"Content-Type": "application/json",
         "Authorization": "Basic " + base64.b64encode(f"{dashboard.OS_USER}:{dashboard.OS_PASS}".encode()).decode()}
    req = urllib.request.Request(dashboard.OS_HOST + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers=h, method=method)
    try:
        with urllib.request.urlopen(req, context=dashboard._ssl_ctx, timeout=120) as r:  # nosec B310
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code} en {path}: {e.read().decode()[:300]}")


DESDE, HASTA = "2026-10-03T00:00:00Z", "2026-10-13T00:00:00Z"
P2_DESDE, P2_HASTA = "2026-10-09T14:21:00Z", "2026-10-12T14:21:00Z"   # 9-oct 11:21 a 12-oct 11:21 -03
R, D = "/soc-responses-*/_search", "/soc-decisions-*/_search"
safelist = [x for x in get_settings().safelist if x]
assert len(safelist) == 13 and not any("/" in x for x in safelist), safelist
infra = {"terms": {"src_ip": safelist}}
rng = {"range": {"event_time": {"gte": DESDE, "lt": HASTA}}}
drng = {"range": {"timestamp": {"gte": DESDE, "lt": HASTA}}}
day = lambda f: {"date_histogram": {"field": f, "calendar_interval": "1d"}}
resp = {"term": {"event_type": "response"}}
t3f = {"term": {"tier": 3}}


def per_day(filters, agg_field, must_not=None, extra_filters=None):
    q = {"bool": {"filter": [rng, *filters], "must_not": must_not or []}}
    aggs = {"c": {"cardinality": {"field": agg_field, "precision_threshold": 40000}}}
    for name, flt in (extra_filters or {}).items():
        aggs[name] = {"filter": flt, "aggs": {"c": {"cardinality": {"field": agg_field, "precision_threshold": 40000}}}}
    r = rq("POST", R, {"size": 0, "query": q, "aggs": {"d": {**day("event_time"), "aggs": aggs}}})
    return {b["key_as_string"][:10]: b for b in r["aggregations"]["d"]["buckets"]}


# ---- E: decisiones por día y tier (soc-decisions-*)
a = rq("POST", D, {"size": 0, "query": drng,
                   "aggs": {"d": {**day("timestamp"), "aggs": {"t": {"terms": {"field": "tier", "size": 5}}}}}})
dec = {}
for b in a["aggregations"]["d"]["buckets"]:
    t = {x["key"]: x["doc_count"] for x in b["t"]["buckets"]}
    dec[b["key_as_string"][:10]] = (b["doc_count"], t.get(2, 0), t.get(3, 0))
t3 = per_day([resp, t3f], "src_ip", [infra])
deriv = per_day([resp, t3f, {"term": {"block_action": "block_pending_approval"}}], "src_ip", [infra])
exp = per_day([{"term": {"event_type": "approval_expired"}}], "trace_id")
man = per_day([{"term": {"event_type": "manual_approval"}}], "trace_id")
blk = [resp, {"term": {"block_action": "block"}}, {"term": {"block_enforced": True}}]
r = rq("POST", R, {"size": 0, "query": {"bool": {"filter": [rng, *blk], "must_not": [infra]}},
                   "aggs": {"d": {**day("event_time"), "aggs": {"ips": {"terms": {"field": "src_ip", "size": 30000}}}}}})
byday = {b["key_as_string"][:10]: {x["key"] for x in b["ips"]["buckets"]} for b in r["aggregations"]["d"]["buckets"]}
first = {}
for dd in sorted(byday):
    for ip in byday[dd]:
        first.setdefault(ip, dd)
E = []
for dd in sorted(dec):
    n, t2, t3n = dec[dd]
    ips = byday.get(dd, set())
    fb = sum(1 for i in ips if first[i] == dd)
    E.append({"dia": dd, "decisiones": n, "t2": t2, "t3": t3n, "ratio_t3_t2": round(t3n / t2, 4) if t2 else None,
              "ips_t3": t3.get(dd, {}).get("c", {}).get("value", 0), "ips_derivadas": deriv.get(dd, {}).get("c", {}).get("value", 0),
              "ips_bloqueadas": len(ips), "primer_bloqueo": fb, "rebloqueo": len(ips) - fb,
              "aprob_expiradas": exp.get(dd, {}).get("doc_count", 0), "aprob_manuales": man.get(dd, {}).get("doc_count", 0)})

# ---- R: perfil OTX de las IPs con T3. Los campos de payload.* no están indexados (no sirven en filtros ni
# agregaciones), así que se lee el ÚLTIMO T3 de cada (día, IP) con top_hits y se clasifica en Python.
rr, after = collections.defaultdict(lambda: [0, 0, 0]), None
while True:
    comp = {"size": 500, "sources": [{"dia": {"date_histogram": {"field": "event_time", "calendar_interval": "1d"}}},
                                     {"ip": {"terms": {"field": "src_ip"}}}]}
    if after:
        comp["after"] = after
    r = rq("POST", R, {"size": 0, "query": {"bool": {"filter": [rng, resp, t3f], "must_not": [infra]}},
                       "aggs": {"c": {"composite": comp, "aggs": {"last": {"top_hits": {
                           "size": 1, "sort": [{"event_time": "desc"}], "_source": ["payload.enrichment.otx_pulse_count"]}}}}}})
    c = r["aggregations"]["c"]
    for b in c["buckets"]:
        dd = datetime.fromtimestamp(b["key"]["dia"] / 1000, timezone.utc).date().isoformat()
        pulsos = (((b["last"]["hits"]["hits"][0]["_source"].get("payload") or {}).get("enrichment")) or {}).get("otx_pulse_count")
        rr[dd][0] += 1
        rr[dd][1] += pulsos is not None
        rr[dd][2] += (pulsos or 0) >= 1
    after = c.get("after_key")
    if not c["buckets"] or not after:
        break
R_ = [{"dia": dd, "ips_t3": v[0], "ips_otx_con_valor": v[1], "ips_otx_pulsos_ge1": v[2]} for dd, v in sorted(rr.items())]

# ---- F: causas de aprobación humana, período 2, IPs distintas (último registro de cada IP)
q = {"bool": {"filter": [{"range": {"event_time": {"gte": P2_DESDE, "lt": P2_HASTA}}}, resp, t3f,
                         {"term": {"block_action": "block_pending_approval"}}], "must_not": [infra]}}
rows, after = {}, None
while True:
    comp = {"size": 500, "sources": [{"ip": {"terms": {"field": "src_ip"}}}]}
    if after:
        comp["after"] = after
    r = rq("POST", R, {"size": 0, "query": q, "aggs": {"c": {"composite": comp, "aggs": {"last": {"top_hits": {
        "size": 1, "sort": [{"event_time": "desc"}], "_source": ["payload.enrichment", "corroboration_count"]}}}}}})
    c = r["aggregations"]["c"]
    for b in c["buckets"]:
        rows[b["key"]["ip"]] = (b["doc_count"], b["last"]["hits"]["hits"][0]["_source"])
    after = c.get("after_key")
    if not c["buckets"] or not after:
        break


def fuente(e, prefijo, valor, disponible):
    """Mismo criterio que frontend/operativo/src/lib/ti.ts (sourceStatus)."""
    notas = [n.lower() for n in (e.get("notes") or []) if n.lower().startswith(prefijo)]
    nota = notas[0] if notas else ""
    if valor is not None:
        return "valor"
    if disponible is not False and not nota:
        return "sin_dato"
    if "ip no pública" in nota:
        return "no_aplica"
    if any(k in nota for k in ("stale", "r2_min_tier", "throttling", "no decisiva", "cuota diaria agotada")):
        return "politica"
    if "no configurada" in nota:
        return "no_configurada"
    return "error" if nota else "sin_motivo"


cat, detalle, ips_f = collections.Counter(), collections.Counter(), []
for ip, (n, sd) in sorted(rows.items()):
    e = (sd.get("payload") or {}).get("enrichment") or {}
    ab = fuente(e, "abuseipdb", e.get("abuseipdb_score"), e.get("abuseipdb_available"))
    ox = fuente(e, "otx", e.get("otx_pulse_count"), e.get("otx_available"))
    cnt, pulsos = e.get("corroboration_count", sd.get("corroboration_count")), e.get("otx_pulse_count")
    if "error" in (ab, ox):
        c = "C"; detalle[f"abuseipdb={ab} otx={ox}"] += 1
    elif ab == "valor" and ox == "valor" and cnt == 1:
        c = "D"
    elif ox == "valor" and (pulsos or 0) >= 1 and ab == "politica":
        c = "A"
    elif ox == "valor" and pulsos == 0:
        c = "B"
    else:
        c = "E"; detalle[f"otro abuseipdb={ab} otx={ox} n={cnt} pulsos={pulsos}"] += 1
    cat[c] += 1
    ips_f.append([ip, c, ab, ox, cnt, pulsos, n])
print(json.dumps({"extraido_utc": datetime.now(timezone.utc).isoformat(), "safelist_n": len(safelist), "E": E, "R": R_,
                  "F": {"total_ips": len(rows), "categorias": dict(sorted(cat.items())), "detalle": dict(detalle), "ips": ips_f}},
                 ensure_ascii=False))
```
