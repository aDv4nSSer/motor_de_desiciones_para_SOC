#!/usr/bin/env python3
"""
etiquetador_diario.py v2 — Etiqueta flows usando AbuseIPDB para TODAS las IPs externas
Tesis UBO — Motor de Decisiones SOC
Cron en .139: 30 3 * * * ABUSEIPDB_KEY=xxx python3 /home/aiayala/tesis/ataques/etiquetador_diario.py

CAMBIO v2: consulta AbuseIPDB para todas las IPs externas (no solo alertadas),
           priorizando por volumen de flows para maximizar cobertura con el
           limite de 1000 requests/dia de la API gratuita.
"""

import json, csv, os, time, glob, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

# ── Rutas ─────────────────────────────────────────────────────────────────────
EVE_FILE   = "/var/log/suricata/eve.json"
JSONL_DIR  = "/home/aiayala/tesis/motor_decisiones_soc/pipeline-ingesta/outputs"
CORPUS     = "/home/aiayala/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv"
ESTADO     = "/home/aiayala/tesis/ataques/logs/etiquetador_estado.json"
CACHE      = "/home/aiayala/tesis/ataques/cache/abuseipdb_cache.json"
REPORTE    = f"/home/aiayala/tesis/ataques/logs/reporte_{datetime.now().strftime('%Y%m%d')}.txt"

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY", "")
MAX_API_CALLS  = 900   # conservador, limite gratuito 1000/dia
SCORE_ATAQUE   = 40    # umbral para etiquetar como ataque
SCORE_BENIGNO  = 10    # umbral para etiquetar como benigno

ATTACK_CATS = {
    "Web Application Attack",
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "A Network Trojan was Detected",
    "Successful Administrator Privilege Gain",
    "Denial of Service Attack",
    "Malware Command and Control Activity Detected",
}

NOISE_CATS = {
    "Generic Protocol Command Decode",
    "Detection of a Network Scan",
    "Not Suspicious Traffic",
    "Unknown Traffic",
}

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg):
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    os.makedirs(os.path.dirname(REPORTE), exist_ok=True)
    with open(REPORTE, "a") as f:
        f.write(line + "\n")

# ── Checkpoint ────────────────────────────────────────────────────────────────
def cargar_estado():
    if os.path.exists(ESTADO):
        with open(ESTADO) as f:
            return json.load(f)
    return {"ultimo_timestamp": "2026-01-01T00:00:00"}

def guardar_estado(ts):
    os.makedirs(os.path.dirname(ESTADO), exist_ok=True)
    with open(ESTADO, "w") as f:
        json.dump({
            "ultimo_timestamp": ts,
            "actualizado": datetime.now().isoformat()
        }, f, indent=2)

# ── Caché AbuseIPDB ───────────────────────────────────────────────────────────
def cargar_cache():
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            return json.load(f)
    return {}

def guardar_cache(c):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "w") as f:
        json.dump(c, f)

def query_abuse(ip, cache):
    if ip in cache:
        return cache[ip].get("score", -1)
    if not ABUSEIPDB_KEY or not ip:
        return -1
    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data   = json.loads(r.read())
            score  = data["data"]["abuseConfidenceScore"]
            cache[ip] = {
                "score":   score,
                "reports": data["data"]["totalReports"]
            }
            time.sleep(0.15)
            return score
    except Exception as e:
        return -1

# ── Duración ──────────────────────────────────────────────────────────────────
def duration_ms(flow):
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
        t0  = datetime.strptime(flow["start"], fmt)
        t1  = datetime.strptime(flow["end"],   fmt)
        return max(0, int((t1 - t0).total_seconds() * 1000))
    except:
        return 0

# ── Etiqueta ──────────────────────────────────────────────────────────────────
def get_label(category, alerted, dur, out_pkts, abuse_score):
    # Prioridad 1: categoria Suricata confirma ataque
    if category in ATTACK_CATS:
        return 1, f"suricata:{category}", "alta"

    # Prioridad 2: AbuseIPDB score alto = ataque confirmado
    if abuse_score >= SCORE_ATAQUE:
        return 1, f"abuseipdb:{abuse_score}", "alta"

    # Prioridad 3: categoria ruido confirmado
    if category in NOISE_CATS and abuse_score < SCORE_ATAQUE:
        return 0, f"ruido:{category}", "alta"

    # Prioridad 4: sin alerta, sin actividad, IP limpia
    if not alerted and dur < 150 and out_pkts <= 2 and abuse_score < SCORE_BENIGNO:
        return 0, "sin_alerta+cortisima+ip_limpia", "alta"

    # Prioridad 5: AbuseIPDB score medio con alerta
    if abuse_score >= 20 and alerted:
        return 1, f"abuseipdb:{abuse_score}+alerta", "media"

    # Prioridad 6: sin alerta + IP sin historial
    if not alerted and (abuse_score < SCORE_BENIGNO or abuse_score == -1):
        return 0, "sin_alerta+ip_limpia", "media"

    return -1, f"revisar:cat={category},abuse={abuse_score}", "revisar"

# ── Indice JSONL para SERVER_TCP_FLAGS ────────────────────────────────────────
def build_jsonl_index():
    log("Construyendo indice JSONL (ultimas 96h)...")
    idx_exact = defaultdict(list)
    idx_relax = defaultdict(list)
    n = 0
    for filepath in sorted(glob.glob(f"{JSONL_DIR}/flows_*.jsonl"))[-96:]:
        try:
            with open(filepath) as f:
                for line in f:
                    flow  = json.loads(line.strip())
                    flags = flow.get("SERVER_TCP_FLAGS", -1)
                    dst   = flow.get("L4_DST_PORT", -1)
                    outp  = flow.get("OUT_PKTS", -1)
                    inp   = flow.get("IN_PKTS", -1)
                    dur   = flow.get("FLOW_DURATION_MILLISECONDS", -1)
                    idx_exact[(dst, outp, inp, dur)].append(flags)
                    idx_relax[(dst, outp, inp)].append(flags)
                    n += 1
        except:
            continue
    log(f"  JSONL indexados: {n:,} flows")
    return idx_exact, idx_relax

def get_tcp_flags(dst, outp, inp, dur, idx_exact, idx_relax):
    key = (dst, outp, inp, dur)
    if key in idx_exact:
        lst = idx_exact[key]
        return max(set(lst), key=lst.count)
    if outp == 0:
        return 0
    key2 = (dst, outp, inp)
    if key2 in idx_relax:
        lst = idx_relax[key2]
        return max(set(lst), key=lst.count)
    return -1

def es_ip_interna(ip):
    return (ip.startswith("200.54.12.")
            or ip.startswith("172.")
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip == "0.0.0.0"
            or ip.startswith("ff"))

# ── Fieldnames ────────────────────────────────────────────────────────────────
def get_fieldnames():
    if os.path.exists(CORPUS):
        with open(CORPUS) as f:
            return next(csv.reader(f))
    return [
        "flow_id", "timestamp", "host_group", "dest_ip",
        "L4_DST_PORT", "FLOW_DURATION_MILLISECONDS", "OUT_PKTS", "IN_PKTS",
        "alerted", "alert_category", "alert_signature", "abuseipdb_score",
        "label", "razon", "confianza", "SERVER_TCP_FLAGS"
    ]


# ── Campañas controladas ──────────────────────────────────────────────────────
def cargar_registro_campanas():
    path = "/home/aiayala/tesis/ataques/registro_campanas.jsonl"
    registros = {}
    if not os.path.exists(path):
        return registros
    with open(path) as f:
        for line in f:
            try:
                r = json.loads(line.strip())
                ip = r["ip_atacante"]
                fecha = datetime.fromisoformat(r["fecha"].replace("Z", "+00:00"))
                tipos = [a["tipo"] for a in r.get("ataques", [])]
                if ip not in registros:
                    registros[ip] = []
                registros[ip].append({
                    "desde": fecha - timedelta(minutes=5),
                    "hasta": fecha + timedelta(minutes=35),
                    "tipos": tipos
                })
            except:
                continue
    log(f"  Campañas cargadas: {sum(len(v) for v in registros.values())} de {len(registros)} IPs")
    return registros

def get_label_campana(src_ip, timestamp_str, campanas):
    if src_ip not in campanas:
        return None
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except:
        return None
    for c in campanas[src_ip]:
        desde = c["desde"].replace(tzinfo=timezone.utc) if c["desde"].tzinfo is None else c["desde"]
        hasta = c["hasta"].replace(tzinfo=timezone.utc) if c["hasta"].tzinfo is None else c["hasta"]
        if desde <= ts <= hasta:
            return 1, f"campaña:{'+'.join(c['tipos'])}", "alta"
    return None

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("=" * 60)
    log("Etiquetador diario v2 — AbuseIPDB para todas las IPs externas")
    log("=" * 60)

    estado     = cargar_estado()
    campanas   = cargar_registro_campanas()
    ultimo_ts  = estado["ultimo_timestamp"]
    cache      = cargar_cache()
    fieldnames = get_fieldnames()

    log(f"Procesando flows desde: {ultimo_ts}")

    # ── Fase 1: leer eve.json ─────────────────────────────────────────────────
    log("Fase 1: Leyendo eve.json...")
    alert_index  = {}
    flows_nuevos = []
    ip_counter   = Counter()   # contar flows por IP externa
    max_ts       = ultimo_ts

    with open(EVE_FILE, 'rb') as f:
        for line in f:
            try:
                r  = json.loads(line.decode('utf-8', errors='ignore'))
                ts = r.get("timestamp", "")
                if ts <= ultimo_ts:
                    continue
                if ts > max_ts:
                    max_ts = ts

                et = r.get("event_type")

                if et == "alert":
                    fid = r.get("flow_id")
                    if fid:
                        a = r.get("alert", {})
                        alert_index[fid] = {
                            "category":  a.get("category", ""),
                            "signature": a.get("signature", "")[:80],
                        }

                elif et == "flow":
                    flows_nuevos.append(r)
                    src = r.get("src_ip", "")
                    if src and not es_ip_interna(src):
                        ip_counter[src] += 1

            except:
                continue

    log(f"  Flows nuevos      : {len(flows_nuevos):,}")
    log(f"  Alertas nuevas    : {len(alert_index):,}")
    log(f"  IPs externas unic.: {len(ip_counter):,}")

    if not flows_nuevos:
        log("Sin flows nuevos. Saliendo.")
        guardar_estado(max_ts)
        return

    # ── Fase 2: AbuseIPDB para IPs externas por volumen ──────────────────────
    # Priorizar las IPs con mas flows (mas impacto en el corpus)
    ips_ordenadas  = [ip for ip, _ in ip_counter.most_common()]
    ips_pendientes = [ip for ip in ips_ordenadas if ip not in cache]
    consultas      = min(len(ips_pendientes), MAX_API_CALLS)

    if ABUSEIPDB_KEY and ips_pendientes:
        log(f"Fase 2: AbuseIPDB para {consultas} IPs (de {len(ips_pendientes)} pendientes)...")
        consultadas = 0
        for ip in ips_pendientes[:MAX_API_CALLS]:
            score = query_abuse(ip, cache)
            consultadas += 1
            if consultadas % 100 == 0:
                guardar_cache(cache)
                log(f"  Progreso: {consultadas}/{consultas} — ultimo score: {score}")
        guardar_cache(cache)
        log(f"  Consultas completadas: {consultadas}")
    else:
        log("Fase 2: AbuseIPDB omitido (sin key o todas cacheadas)")

    # Stats de scores
    scores = [cache.get(ip, {}).get("score", -1) for ip in ip_counter]
    ips_ataque   = sum(1 for s in scores if s >= SCORE_ATAQUE)
    ips_benignas = sum(1 for s in scores if 0 <= s < SCORE_BENIGNO)
    log(f"  IPs con score >={SCORE_ATAQUE} (ataque)  : {ips_ataque}")
    log(f"  IPs con score < {SCORE_BENIGNO} (benigno) : {ips_benignas}")

    # ── Fase 3: indice JSONL ──────────────────────────────────────────────────
    idx_exact, idx_relax = build_jsonl_index()

    # ── Fase 4: etiquetar y escribir ──────────────────────────────────────────
    log("Fase 4: Etiquetando y escribiendo corpus...")
    stats = {"1": 0, "0": 0, "-1": 0}

    with open(CORPUS, "a", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames)

        for r in flows_nuevos:
            fid        = r.get("flow_id")
            src_ip     = r.get("src_ip", "")
            dest_port  = r.get("dest_port", 0)
            flow_data  = r.get("flow", {})
            alert_info = alert_index.get(fid, {})
            alerted    = bool(alert_info) or flow_data.get("alerted", False)
            category   = alert_info.get("category", "")
            dur        = duration_ms(flow_data)
            out_pkts   = flow_data.get("pkts_toclient", 0)
            in_pkts    = flow_data.get("pkts_toserver", 0)

            # Para IPs internas no consultamos AbuseIPDB
            if es_ip_interna(src_ip):
                abuse_score = -1
            else:
                abuse_score = cache.get(src_ip, {}).get("score", -1)

            # Prioridad 0: campaña controlada (más alta)
            camp_result = get_label_campana(src_ip, r.get("timestamp",""), campanas)
            if camp_result:
                label, razon, confianza = camp_result
            else:
                label, razon, confianza = get_label(
                    category, alerted, dur, out_pkts, abuse_score
                )
            tcp_flags = get_tcp_flags(
                dest_port, out_pkts, in_pkts, dur, idx_exact, idx_relax
            )
            stats[str(label)] += 1

            writer.writerow({
                "flow_id":                    fid,
                "timestamp":                  r.get("timestamp", ""),
                "host_group":                 src_ip,
                "dest_ip":                    r.get("dest_ip", ""),
                "L4_DST_PORT":               dest_port,
                "FLOW_DURATION_MILLISECONDS": dur,
                "OUT_PKTS":                   out_pkts,
                "IN_PKTS":                    in_pkts,
                "alerted":                    int(alerted),
                "alert_category":             category,
                "alert_signature":            alert_info.get("signature", ""),
                "abuseipdb_score":            abuse_score,
                "label":                      label,
                "razon":                      razon,
                "confianza":                  confianza,
                "SERVER_TCP_FLAGS":           tcp_flags,
            })

    guardar_estado(max_ts)

    total = sum(stats.values())
    log(f"\n  ══ Resumen ══")
    log(f"  Flows procesados : {total:,}")
    log(f"  Ataques   (1)   : {stats['1']:,}  ({stats['1']/total*100:.2f}%)")
    log(f"  Benignos  (0)   : {stats['0']:,}  ({stats['0']/total*100:.2f}%)")
    log(f"  Revisar   (-1)  : {stats['-1']:,}  ({stats['-1']/total*100:.2f}%)")
    log(f"  Reporte         : {REPORTE}")
    log("Completado.")

if __name__ == "__main__":
    main()
