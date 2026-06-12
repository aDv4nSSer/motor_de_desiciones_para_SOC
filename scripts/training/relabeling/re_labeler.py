#!/usr/bin/env python3
"""
re_labeler.py — Re-etiquetado de flujos para reentrenamiento LightGBM
Tesis UBO — Motor de Decisiones SOC
Autor: Antonio (infraestructura) — para uso de Joaquín (ML)

IMPORTANTE:
- host_group (src_ip) es SOLO para GroupKFold — NUNCA entra al modelo
- SERVER_TCP_FLAGS se agrega en paso 2 (correlación con JSONL)
- AbuseIPDB se usa para ETIQUETAR, no como feature del modelo
"""

import json, csv, os, time, urllib.request, urllib.parse
from datetime import datetime

# ── Rutas ─────────────────────────────────────────────────────────────────────
BASE    = "/home/ia_ubo/tesis/relabeling"
EVE     = f"{BASE}/data/eve.json"
OUT_CSV = f"{BASE}/output/corpus_relabeled_v1.csv"
CACHE   = f"{BASE}/cache/abuseipdb_cache.json"

# ── API Key AbuseIPDB (solo para etiquetado, no entra al modelo) ──────────────
# Obtener en: https://www.abuseipdb.com/account/api
ABUSEIPDB_KEY = ""  # <-- completar con tu API key

# ── Reglas de etiquetado por categoría Suricata ───────────────────────────────
# label=1: ataque confirmado
ATTACK_CATS = {
    "Web Application Attack",
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "A Network Trojan was Detected",
    "Successful Administrator Privilege Gain",
    "Denial of Service Attack",
    "Malware Command and Control Activity Detected",
}

# label=0: ruido benigno confirmado
NOISE_CATS = {
    "Generic Protocol Command Decode",
    "Detection of a Network Scan",
    "Not Suspicious Traffic",
    "Unknown Traffic",
}

# ── Caché AbuseIPDB ───────────────────────────────────────────────────────────
def load_cache():
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            return json.load(f)
    return {}

def save_cache(c):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, 'w') as f:
        json.dump(c, f)

def query_abuse(ip, cache, key):
    if ip in cache:
        return cache[ip].get("score", -1)
    if not key or not ip:
        return -1
    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            score = data["data"]["abuseConfidenceScore"]
            cache[ip] = {"score": score, "reports": data["data"]["totalReports"]}
            time.sleep(0.15)  # respetar rate limit 1000/día
            return score
    except Exception as e:
        print(f"  [AbuseIPDB] Error {ip}: {e}")
        return -1

# ── Calcular duración en ms ───────────────────────────────────────────────────
def duration_ms(flow):
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
        t0 = datetime.strptime(flow["start"], fmt)
        t1 = datetime.strptime(flow["end"],   fmt)
        return max(0, int((t1 - t0).total_seconds() * 1000))
    except Exception:
        return 0

# ── Determinar etiqueta ───────────────────────────────────────────────────────
def get_label(category, alerted, dur, out_pkts, abuse_score):
    """
    Retorna: (label, razon, confianza)
    label: 1=ataque, 0=benigno, -1=revisar_manualmente
    """
    # 1. Categoría de ataque confirmada
    if category in ATTACK_CATS:
        return 1, f"suricata:{category}", "alta"

    # 2. Ruido benigno confirmado por Suricata
    if category in NOISE_CATS:
        return 0, f"suricata_ruido:{category}", "alta"

    # 3. Sin alerta + comportamiento muy corto → benigno
    if not alerted and dur < 150 and out_pkts <= 2:
        return 0, "sin_alerta+conexion_cortisima", "alta"

    # 4. AbuseIPDB score alto → ataque
    if abuse_score >= 75:
        return 1, f"abuseipdb_score:{abuse_score}", "alta"

    # 5. AbuseIPDB score alto medio + alerta → ataque
    if abuse_score >= 40 and alerted:
        return 1, f"abuseipdb:{abuse_score}+alerta", "media"

    # 6. Sin alerta + IP limpia → benigno
    if not alerted and (abuse_score < 15 or abuse_score == -1):
        return 0, f"sin_alerta+ip_limpia:{abuse_score}", "media"

    # 7. "Potentially Bad Traffic" sin confirmación → revisar
    return -1, f"revisar:category={category},abuse={abuse_score},alerta={alerted}", "revisar"


# ── FASE 1: Construir índice de alertas por flow_id ───────────────────────────
def build_alert_index():
    print("[FASE 1] Construyendo índice de alertas por flow_id...")
    index = {}
    with open(EVE, 'rb') as f:
        for line in f:
            try:
                r = json.loads(line.decode('utf-8', errors='ignore'))
            except Exception:
                continue
            if r.get("event_type") != "alert":
                continue
            fid = r.get("flow_id")
            if fid:
                a = r.get("alert", {})
                index[fid] = {
                    "category":  a.get("category", ""),
                    "signature": a.get("signature", "")[:80],
                    "severity":  a.get("severity", 3),
                }
    print(f"  Alertas indexadas: {len(index)}")
    return index


# ── FASE 2: Recopilar IPs únicas para AbuseIPDB ───────────────────────────────
def collect_ips(alert_index):
    print("[FASE 2] Recopilando IPs únicas de flujos alertados...")
    ips = set()
    with open(EVE, 'rb') as f:
        for line in f:
            try:
                r = json.loads(line.decode('utf-8', errors='ignore'))
            except Exception:
                continue
            if r.get("event_type") != "flow":
                continue
            fid = r.get("flow_id")
            if fid in alert_index or r.get("flow", {}).get("alerted", False):
                ip = r.get("src_ip", "")
                if ip:
                    ips.add(ip)
    print(f"  IPs únicas: {len(ips)}")
    return ips


# ── FASE 3: Consultar AbuseIPDB ───────────────────────────────────────────────
def enrich_ips(ips, cache):
    if not ABUSEIPDB_KEY:
        print("[FASE 3] Sin API key — omitiendo AbuseIPDB")
        return
    print(f"[FASE 3] Consultando AbuseIPDB para {len(ips)} IPs...")
    pendientes = [ip for ip in ips if ip not in cache]
    print(f"  ({len(pendientes)} no cacheadas)")
    for i, ip in enumerate(pendientes, 1):
        query_abuse(ip, cache, ABUSEIPDB_KEY)
        if i % 50 == 0:
            save_cache(cache)
            print(f"  Progreso: {i}/{len(pendientes)}")
    save_cache(cache)
    print("  Consultas completadas.")


# ── FASE 4: Etiquetar flujos y generar CSV ────────────────────────────────────
def label_flows(alert_index, cache):
    print("[FASE 4] Etiquetando flujos y generando CSV...")
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

    campos = [
        # Metadatos (NUNCA features del modelo)
        "flow_id", "timestamp", "host_group", "dest_ip",
        # Features disponibles desde eve.json (3 de los 4 Golden)
        "L4_DST_PORT", "FLOW_DURATION_MILLISECONDS", "OUT_PKTS", "IN_PKTS",
        # SERVER_TCP_FLAGS: se agrega en paso 2 (correlacion_jsonl.py)
        # Contexto de etiquetado (NUNCA features del modelo)
        "alerted", "alert_category", "alert_signature", "abuseipdb_score",
        # Etiqueta final
        "label", "razon", "confianza",
    ]

    stats = {"1": 0, "0": 0, "-1": 0, "total": 0}

    with open(EVE, 'rb') as fin, \
         open(OUT_CSV, 'w', newline='', encoding='utf-8') as fout:

        writer = csv.DictWriter(fout, fieldnames=campos)
        writer.writeheader()

        for line in fin:
            try:
                r = json.loads(line.decode('utf-8', errors='ignore'))
            except Exception:
                continue

            if r.get("event_type") != "flow":
                continue

            stats["total"] += 1
            fid       = r.get("flow_id")
            src_ip    = r.get("src_ip", "")
            flow_data = r.get("flow", {})
            alert_info = alert_index.get(fid, {})
            alerted    = bool(alert_info) or flow_data.get("alerted", False)
            category   = alert_info.get("category", "")
            dur        = duration_ms(flow_data)
            out_pkts   = flow_data.get("pkts_toclient", 0)
            abuse_score = cache.get(src_ip, {}).get("score", -1) if src_ip else -1

            label, razon, confianza = get_label(
                category, alerted, dur, out_pkts, abuse_score
            )
            stats[str(label)] += 1

            writer.writerow({
                "flow_id":                   fid,
                "timestamp":                 r.get("timestamp", ""),
                "host_group":                src_ip,
                "dest_ip":                   r.get("dest_ip", ""),
                "L4_DST_PORT":               r.get("dest_port", 0),
                "FLOW_DURATION_MILLISECONDS": dur,
                "OUT_PKTS":                  out_pkts,
                "IN_PKTS":                   flow_data.get("pkts_toserver", 0),
                "alerted":                   int(alerted),
                "alert_category":            category,
                "alert_signature":           alert_info.get("signature", ""),
                "abuseipdb_score":           abuse_score,
                "label":                     label,
                "razon":                     razon,
                "confianza":                 confianza,
            })

    t = stats["total"]
    print(f"\n  ══ Resumen final ══")
    print(f"  Total flujos procesados : {t:,}")
    print(f"  Ataques    (label=1)    : {stats['1']:,}  ({stats['1']/t*100:.2f}%)")
    print(f"  Benignos   (label=0)    : {stats['0']:,}  ({stats['0']/t*100:.2f}%)")
    print(f"  Revisar    (label=-1)   : {stats['-1']:,}  ({stats['-1']/t*100:.2f}%)")
    print(f"\n  CSV generado: {OUT_CSV}")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  Re-etiquetador de flujos — Tesis UBO")
    print("=" * 55)

    cache       = load_cache()
    alert_index = build_alert_index()
    ips         = collect_ips(alert_index)

    enrich_ips(ips, cache)

    label_flows(alert_index, cache)

    print("\n✓ Proceso completado.")
