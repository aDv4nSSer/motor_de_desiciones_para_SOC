#!/usr/bin/env python3
"""
Resuelve los 23 casos 'revisar' usando AbuseIPDB.
Actualiza corpus_relabeled_v1.csv con las etiquetas finales.
"""
import json, csv, time, urllib.request, urllib.parse, os, shutil

API_KEY  = os.environ.get("ABUSEIPDB_KEY", "")
BASE     = "/home/ia_ubo/tesis/relabeling"
CSV_IN   = f"{BASE}/output/corpus_relabeled_v1.csv"
CSV_OUT  = f"{BASE}/output/corpus_relabeled_v2.csv"
CACHE    = f"{BASE}/cache/abuseipdb_cache.json"

def load_cache():
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            return json.load(f)
    return {}

def save_cache(c):
    with open(CACHE, 'w') as f:
        json.dump(c, f, indent=2)

def query_abuse(ip, cache):
    if ip in cache:
        return cache[ip]["score"]
    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": API_KEY, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
            score = data["data"]["abuseConfidenceScore"]
            reports = data["data"]["totalReports"]
            cache[ip] = {"score": score, "reports": reports}
            print(f"  {ip:<20} score={score:>3}  reportes={reports}")
            time.sleep(0.3)
            return score
    except Exception as e:
        print(f"  [ERROR] {ip}: {e}")
        return -1

# Paso 1: recopilar IPs pendientes
cache = load_cache()
ips_pendientes = set()

with open(CSV_IN) as f:
    for row in csv.DictReader(f):
        if row["label"] == "-1":
            ips_pendientes.add(row["host_group"])

print(f"IPs a consultar: {len(ips_pendientes)}")
print("-" * 50)

# Paso 2: consultar AbuseIPDB
for ip in sorted(ips_pendientes):
    query_abuse(ip, cache)

save_cache(cache)

# Paso 3: reescribir CSV con etiquetas resueltas
resueltos = {"ataque": 0, "benigno": 0}

with open(CSV_IN) as fin, open(CSV_OUT, 'w', newline='') as fout:
    reader = csv.DictReader(fin)
    writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
    writer.writeheader()

    for row in reader:
        if row["label"] == "-1":
            ip    = row["host_group"]
            score = cache.get(ip, {}).get("score", -1)
            row["abuseipdb_score"] = score

            if score >= 40:
                row["label"]      = "1"
                row["razon"]      = f"abuseipdb_score:{score}"
                row["confianza"]  = "alta"
                resueltos["ataque"] += 1
            else:
                row["label"]      = "0"
                row["razon"]      = f"abuseipdb_score:{score}+trafico_potencialmente_malo_sin_confirmacion"
                row["confianza"]  = "media"
                resueltos["benigno"] += 1

        writer.writerow(row)

print(f"\n{'='*50}")
print(f"Resueltos como ataque  (1): {resueltos['ataque']}")
print(f"Resueltos como benigno (0): {resueltos['benigno']}")
print(f"CSV final: {CSV_OUT}")
