"""Marco muestral y muestra para medir la precisión del auto-bloqueo en el período 2 (solo lectura).

Se ejecuta UNA vez en .140 desde ~/tesis/repo/motor:
    python3 - < extraer_marco.py > salida_cruda.json
y escribe un único JSON por stdout (los avisos van a stderr). No escribe en Redis ni en OpenSearch.

Marco: IPs distintas con al menos un bloqueo AUTOMÁTICO ejecutado (soc-responses-*, event_type=response,
block_action=block, block_enforced=true) entre 2026-10-09T14:21:00Z y 2026-10-12T14:21:00Z (9-oct 11:21 a
12-oct 11:21 -03). Se excluyen, en este orden: safelist de 13 IPs, RFC1918, otras no globales, y las IPs con
cualquier aprobación manual (event_type=manual_approval con approved_by) en la ventana. Por IP se usa su primer
bloqueo automático de la ventana.

Muestra: random.Random(20261012).sample(marco ordenado por dirección, 100): sin reemplazo y en orden aleatorio.
Comportamiento por IP: soc-responses-* (decisiones T2/T3 con src_ip; payload.dst_port se lee de _source porque
payload.* no está indexado) y suricata-alerts-* (firmas y categorías). Ventana de comportamiento: desde
2026-10-03T00:00:00Z hasta la extracción.
"""
import base64
import collections
import ipaddress
import json
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, ".")
import dashboard
from response.config import get_settings

VENTANA_DESDE, VENTANA_HASTA = "2026-10-09T14:21:00Z", "2026-10-12T14:21:00Z"
COMPORTAMIENTO_DESDE = "2026-10-03T00:00:00Z"
SEMILLA, TAMANO_MUESTRA, MARCO_MINIMO = 20261012, 100, 100
MAX_DOCS_COMPORTAMIENTO = 400_000
RESPUESTAS, SURICATA = "soc-responses-*", "suricata-alerts-*"
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def rq(method: str, path: str, body: dict | None = None) -> dict:
    """Pedido a OpenSearch; ante un error HTTP aborta con el detalle (nada se reintenta)."""
    headers = {"Content-Type": "application/json",
               "Authorization": "Basic " + base64.b64encode(f"{dashboard.OS_USER}:{dashboard.OS_PASS}".encode()).decode()}
    req = urllib.request.Request(dashboard.OS_HOST + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=dashboard._ssl_ctx, timeout=120) as r:  # nosec B310
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code} en {method} {path}: {e.read().decode()[:300]}")


def clasificar_ip(ip: str, safelist: set[str]) -> str:
    """Motivo de exclusión de una IP ('' si entra al marco por estos criterios)."""
    if ip in safelist:
        return "safelist"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "no_valida"
    if any(addr in net for net in RFC1918 if addr.version == 4):
        return "rfc1918"
    if not addr.is_global:
        return "otra_no_global"
    return ""


def primer_bloqueo_por_ip() -> dict[str, dict]:
    """Primer bloqueo automático ejecutado de cada IP dentro de la ventana."""
    filtros = [{"term": {"event_type": "response"}}, {"term": {"block_action": "block"}}, {"term": {"block_enforced": True}},
               {"range": {"event_time": {"gte": VENTANA_DESDE, "lt": VENTANA_HASTA}}}]
    out, after = {}, None
    while True:
        comp = {"size": 500, "sources": [{"ip": {"terms": {"field": "src_ip"}}}]}
        if after:
            comp["after"] = after
        r = rq("POST", f"/{RESPUESTAS}/_search", {"size": 0, "query": {"bool": {"filter": filtros}}, "aggs": {"c": {
            "composite": comp, "aggs": {"primero": {"top_hits": {"size": 1, "sort": [{"event_time": "asc"}], "_source": [
                "event_time", "trace_id", "risk_score", "tier", "payload.enrichment", "payload.approved_by",
                "payload.manual_approval"]}}}}}})
        c = r["aggregations"]["c"]
        for b in c["buckets"]:
            out[b["key"]["ip"]] = {"docs_bloqueo": b["doc_count"], **b["primero"]["hits"]["hits"][0]["_source"]}
        after = c.get("after_key")
        if not c["buckets"] or not after:
            return out


def ips_con_aprobacion_manual() -> dict[str, int]:
    """IPs con algún manual_approval con approved_by en la ventana (src_ip del payload o del documento)."""
    r = rq("POST", f"/{RESPUESTAS}/_search", {"size": 5000, "query": {"bool": {"filter": [
        {"term": {"event_type": "manual_approval"}}, {"range": {"event_time": {"gte": VENTANA_DESDE, "lt": VENTANA_HASTA}}}]}},
        "_source": ["src_ip", "username", "payload.src_ip", "payload.approved_by", "payload.enforced"]})
    if r["hits"]["total"]["value"] > 5000:
        raise SystemExit("más de 5000 manual_approval en la ventana: ampliar la lectura")
    ips = collections.Counter()
    for h in r["hits"]["hits"]:
        s = h["_source"]
        p = s.get("payload") or {}
        if p.get("approved_by") or s.get("username"):
            ip = p.get("src_ip") or s.get("src_ip")
            if ip:
                ips[ip] += 1
    return dict(ips)


def comportamiento_respuestas(ips: list[str]) -> dict[str, dict]:
    """Por IP: flujos con decisión T2/T3, puertos destino y primera/última vez vista (scroll de _source)."""
    q = {"bool": {"filter": [{"term": {"event_type": "response"}}, {"terms": {"src_ip": ips}},
                             {"range": {"event_time": {"gte": COMPORTAMIENTO_DESDE}}}]}}
    r = rq("POST", f"/{RESPUESTAS}/_search?scroll=2m", {"size": 5000, "track_total_hits": True, "query": q,
                                                        "sort": ["_doc"], "_source": ["src_ip", "event_time", "payload.dst_port"]})
    total = r["hits"]["total"]["value"]
    if total > MAX_DOCS_COMPORTAMIENTO:
        raise SystemExit(f"{total} documentos de comportamiento: demasiados para una lectura única")
    acc: dict[str, dict] = {ip: {"flujos": 0, "puertos": collections.Counter(), "primera": None, "ultima": None} for ip in ips}
    scroll_id = r.get("_scroll_id")
    while r["hits"]["hits"]:
        for h in r["hits"]["hits"]:
            s = h["_source"]
            a = acc[s["src_ip"]]
            a["flujos"] += 1
            puerto = (s.get("payload") or {}).get("dst_port")
            if puerto is not None:
                a["puertos"][int(puerto)] += 1
            t = s["event_time"]
            a["primera"] = t if a["primera"] is None or t < a["primera"] else a["primera"]
            a["ultima"] = t if a["ultima"] is None or t > a["ultima"] else a["ultima"]
        r = rq("POST", "/_search/scroll", {"scroll": "2m", "scroll_id": scroll_id})
        scroll_id = r.get("_scroll_id", scroll_id)
    rq("DELETE", "/_search/scroll", {"scroll_id": scroll_id})
    return {ip: {"flujos": a["flujos"], "puertos": {str(k): v for k, v in a["puertos"].most_common()},
                 "primera": a["primera"], "ultima": a["ultima"]} for ip, a in acc.items()} | {"_total_docs": total}


def _aplanar(props: dict, prefijo: str = "") -> dict[str, dict]:
    out = {}
    for nombre, d in props.items():
        ruta = prefijo + nombre
        if "properties" in d:
            out.update(_aplanar(d["properties"], ruta + "."))
        else:
            out[ruta] = {"type": d.get("type"), "kw": "keyword" in (d.get("fields") or {})}
    return out


def resolver(campos: dict[str, dict], candidatos: list[str]) -> str | None:
    """Primer campo candidato agregable (keyword/ip/date, o su subcampo .keyword)."""
    for c in candidatos:
        d = campos.get(c)
        if d:
            return c if d["type"] in ("keyword", "ip", "date") else (c + ".keyword" if d["kw"] else None)
    return None


def suricata(ips: list[str]) -> dict:
    """Firmas y categorías de Suricata por IP origen (suricata-alerts-*); campos resueltos desde el mapping."""
    m = rq("GET", f"/{SURICATA}/_mapping")
    campos: dict[str, dict] = {}
    for v in m.values():
        campos.update(_aplanar(v["mappings"].get("properties", {})))
    f_ip = resolver(campos, ["src_ip", "data.src_ip", "source.ip"])
    f_sig = resolver(campos, ["alert.signature", "data.alert.signature", "signature"])
    f_cat = resolver(campos, ["alert.category", "data.alert.category", "category"])
    f_t = resolver(campos, ["@timestamp", "timestamp", "event_time"])
    info = {"campos": {"ip": f_ip, "firma": f_sig, "categoria": f_cat, "tiempo": f_t}, "indices": len(m), "por_ip": {}}
    if not (f_ip and (f_sig or f_cat)):
        info["aviso"] = "sin campos resolubles: firmas y categorías quedan 'sin datos'"
        return info
    filtros: list[dict] = [{"terms": {f_ip: ips}}]
    if f_t:
        filtros.append({"range": {f_t: {"gte": COMPORTAMIENTO_DESDE}}})
    aggs: dict = {}
    if f_sig:
        aggs["sig"] = {"terms": {"field": f_sig, "size": 5}}
    if f_cat:
        aggs["cat"] = {"terms": {"field": f_cat, "size": 5}}
    r = rq("POST", f"/{SURICATA}/_search", {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filtros}},
                                           "aggs": {"ip": {"terms": {"field": f_ip, "size": len(ips)}, "aggs": aggs}}})
    info["docs"] = r["hits"]["total"]["value"]
    for b in r["aggregations"]["ip"]["buckets"]:
        info["por_ip"][b["key"]] = {"alertas": b["doc_count"],
                                    "firmas": {x["key"]: x["doc_count"] for x in b.get("sig", {}).get("buckets", [])},
                                    "categorias": {x["key"]: x["doc_count"] for x in b.get("cat", {}).get("buckets", [])}}
    return info


def main() -> None:
    safelist = set(get_settings().safelist)
    assert len(safelist) == 13, safelist
    primeros = primer_bloqueo_por_ip()
    manuales = ips_con_aprobacion_manual()
    motivos = {ip: clasificar_ip(ip, safelist) for ip in primeros}
    cuenta = collections.Counter(motivos.values())
    en_doc_manual = {ip for ip, d in primeros.items() if (d.get("payload") or {}).get("approved_by")
                     or (d.get("payload") or {}).get("manual_approval")}
    sin_otros = [ip for ip, m in motivos.items() if not m]
    excl_manual = [ip for ip in sin_otros if ip in manuales or ip in en_doc_manual]
    marco = sorted((ip for ip in sin_otros if ip not in excl_manual), key=lambda s: int(ipaddress.ip_address(s)))
    exclusiones = {
        "ips_con_bloqueo_automatico": len(primeros),
        "excluidas_safelist": cuenta["safelist"], "excluidas_rfc1918": cuenta["rfc1918"],
        "excluidas_otra_no_global": cuenta["otra_no_global"] + cuenta["no_valida"],
        "excluidas_aprobacion_manual": len(excl_manual),
        "aprobacion_manual_ips_en_ventana_total": len(manuales),
        "aprobacion_manual_en_el_propio_documento": len(en_doc_manual),
        "n_marco": len(marco),
    }
    salida: dict = {"extraido_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version.split()[0],
                    "ventana": [VENTANA_DESDE, VENTANA_HASTA], "comportamiento_desde": COMPORTAMIENTO_DESDE,
                    "semilla": SEMILLA, "algoritmo": "random.Random(semilla).sample(marco ordenado por dirección, k)",
                    "exclusiones": exclusiones, "marco_ok": len(marco) >= MARCO_MINIMO}
    if len(marco) < MARCO_MINIMO:
        salida["aviso"] = f"N del marco ({len(marco)}) < {MARCO_MINIMO}: no se toma muestra"
        print(json.dumps(salida, ensure_ascii=False))
        return
    muestra = random.Random(SEMILLA).sample(marco, TAMANO_MUESTRA)
    comp = comportamiento_respuestas(muestra)
    salida.update({"marco": [{"ip": ip, **primeros[ip]} for ip in marco], "muestra": muestra,
                   "comportamiento": comp, "suricata": suricata(muestra)})
    print(json.dumps(salida, ensure_ascii=False))


main()
