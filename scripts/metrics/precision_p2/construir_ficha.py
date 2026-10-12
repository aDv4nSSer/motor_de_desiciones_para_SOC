"""Construye la ficha ciega, la clave sellada y la ficha del segundo etiquetador (se ejecuta en el Mac).

Entrada: la salida cruda de extraer_marco.py. Resuelve DNS inverso con confirmación directa (FCrDNS) con `dig` y
ASN/organización/país con el whois masivo de Team Cymru, ambos DESDE ESTE EQUIPO (nunca desde producción).
Aplica las reglas de preetiquetado (solo DNS inverso confirmado, ASN u organización; nunca score ni TI de R-SOAR).

Uso:
    python3 construir_ficha.py --raw salida_cruda.json --base ~/tesis_archivo/precision_p2

Escribe en <base>/<timestamp>/: ficha_ciega.csv, ficha_segundo_etiquetador.csv, clave_sellada.csv,
resolucion_externa.json, salida_cruda.json, copia de los scripts y manifiesto_precision_p2.md (con los sha256).
El manifiesto con el hash de la clave se escribe antes de que se etiquete nada.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import random
import re
import shutil
import socket
import subprocess  # nosec B404 - se invoca `dig` con argumentos en lista, sin shell
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SEMILLA = 20261012
SEGUNDO_ETIQUETADOR = 30
CYMRU_HOST, CYMRU_PORT = "whois.cymru.com", 43
DIG_BASE = ["dig", "+time=3", "+tries=1", "+short"]

# Reglas de preetiquetado: (id, proyecto, campo, patrón). Campo "rdns": el DNS inverso debe tener FCrDNS
# confirmado y terminar en el sufijo. Campo "as_name": expresión regular sobre el nombre del AS (Team Cymru, en
# mayúsculas). Lista cerrada; cualquier regla nueva se agrega aquí y en el protocolo, con su evidencia.
REGLAS = [
    ("R01", "Censys", "rdns", ".censys-scanner.com"),
    ("R02", "Censys", "as_name", r"CENSYS"),
    ("R03", "Shodan", "rdns", ".shodan.io"),
    ("R04", "Shadowserver", "rdns", ".shadowserver.org"),
    ("R05", "Shadowserver", "as_name", r"SHADOWSERVER"),
    ("R06", "Onyphe", "rdns", ".onyphe.net"),
    ("R07", "Onyphe", "rdns", ".onyphe.io"),
    ("R08", "Onyphe", "as_name", r"ONYPHE"),
    ("R09", "Modat", "rdns", ".modat.io"),
    ("R10", "Stretchoid", "rdns", ".stretchoid.com"),
    ("R11", "Criminal IP", "rdns", ".criminalip.com"),
    ("R12", "Driftnet", "rdns", ".driftnet.io"),
    ("R13", "BitSight", "rdns", ".bitsight.com"),
    ("R14", "BitSight", "as_name", r"BITSIGHT"),
    ("R15", "TUM (Technische Universität München)", "rdns", ".in.tum.de"),
    ("R16", "Internet Measurement", "rdns", ".internet-measurement.com"),
]
PUERTOS_SENSIBLES = frozenset({21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 2222})
PUERTOS_AUTENTICACION = frozenset({21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 2222})
CLAVE_SHA256_ESPERADA = "c869fc311e22b7ed9b676f6d3aa19692ccd1b7d7bef0186b60cf807fd1b5cbd4"  # pragma: allowlist secret - sha256 público de clave_sellada.csv, no un secreto
COLUMNAS_FICHA = ["id", "ip", "net24", "rdns", "fcrdns", "asn", "organizacion", "pais", "n_puertos", "n_flujos",
                  "max_flujos_puerto_auth", "n_top5_sensibles", "top5_puertos", "primera_vista", "ultima_vista",
                  "suricata_alertas", "suricata_firmas", "suricata_categorias", "pre_etiqueta", "regla", "etiqueta",
                  "evidencia", "notas"]
COLUMNAS_SEGUNDO = [c for c in COLUMNAS_FICHA if c not in ("pre_etiqueta", "regla")]
COLUMNAS_CLAVE = ["id", "ip", "score", "tier", "fuentes_ti", "abuseipdb_score", "otx_pulsos", "hora_bloqueo", "trace_id"]


def reglas_markdown() -> str:
    """Tabla de reglas para el protocolo, generada desde REGLAS (única fuente)."""
    filas = ["| Regla | Proyecto | Señal | Condición exacta |", "|---|---|---|---|"]
    for rid, proyecto, campo, patron in REGLAS:
        if campo == "rdns":
            cond = f"DNS inverso con FCrDNS confirmado y que termina en `{patron}`"
            senal = "DNS inverso (FCrDNS)"
        else:
            cond = f"el nombre del AS (Team Cymru) contiene `{patron}` (sin distinguir mayúsculas)"
            senal = "ASN / organización"
        filas.append(f"| {rid} | {proyecto} | {senal} | {cond} |")
    return "\n".join(filas)


def dig(*args: str) -> list[str]:
    """Salida de `dig +short` como lista de líneas; vacía ante timeout o error."""
    try:
        r = subprocess.run([*DIG_BASE, *args], capture_output=True, text=True, timeout=12, check=False)  # nosec B603 B607
    except subprocess.TimeoutExpired:
        return []
    return [x.strip() for x in r.stdout.splitlines() if x.strip() and not x.startswith(";;")]


def resolver_dns(ip: str) -> dict:
    """DNS inverso y confirmación directa: algún PTR cuyo A/AAAA incluya la IP original."""
    ptrs = [p.rstrip(".").lower() for p in dig("-x", ip)]
    if not ptrs:
        return {"rdns": "", "fcrdns": "sin_ptr", "ptrs": []}
    objetivo = ipaddress.ip_address(ip)
    for nombre in ptrs:
        tipo = "AAAA" if objetivo.version == 6 else "A"
        directas = {ipaddress.ip_address(x) for x in dig(nombre, tipo) if _es_ip(x)}
        if objetivo in directas:
            return {"rdns": nombre, "fcrdns": "confirmado", "ptrs": ptrs}
    return {"rdns": ptrs[0], "fcrdns": "no_confirmado", "ptrs": ptrs}


def _es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


def cymru_masivo(ips: list[str]) -> dict[str, dict]:
    """Whois masivo de Team Cymru (modo verbose): ASN, prefijo, país, registro, nombre del AS por IP."""
    consulta = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    datos = b""
    with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=20) as s:
        s.sendall(consulta.encode())
        s.settimeout(20)
        while True:
            trozo = s.recv(65536)
            if not trozo:
                break
            datos += trozo
    out: dict[str, dict] = {}
    for linea in datos.decode(errors="replace").splitlines():
        campos = [c.strip() for c in linea.split("|")]
        if len(campos) >= 7 and campos[1] and _es_ip(campos[1]):
            out[campos[1]] = {"asn": campos[0], "prefijo": campos[2], "pais": campos[3], "registro": campos[4],
                              "as_name": campos[6]}
    return out


def preetiquetar(dns: dict, cymru: dict) -> tuple[str, str]:
    """(pre_etiqueta, regla) con solo DNS inverso confirmado y AS; vacíos si ninguna regla aplica."""
    aplicadas = []
    for rid, proyecto, campo, patron in REGLAS:
        if campo == "rdns":
            if dns["fcrdns"] == "confirmado" and dns["rdns"].endswith(patron):
                aplicadas.append(f"{rid} ({proyecto}): FCrDNS confirmado, {dns['rdns']} termina en {patron}")
        elif cymru.get("as_name") and re.search(patron, cymru["as_name"].upper()):
            aplicadas.append(f"{rid} ({proyecto}): AS '{cymru['as_name']}' contiene {patron}")
    return ("escáner de investigación", "; ".join(aplicadas)) if aplicadas else ("", "")


def net24(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))


def metricas_comportamiento(puertos: dict[str, int]) -> dict[str, int]:
    """Cifras derivadas SOLO del comportamiento observado (puertos y flujos), nunca de score, tier ni TI."""
    p = {int(k): v for k, v in puertos.items()}
    top5 = sorted(p.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return {"n_puertos": len(p), "n_flujos": sum(p.values()),
            "max_flujos_puerto_auth": max((v for k, v in p.items() if k in PUERTOS_AUTENTICACION), default=0),
            "n_top5_sensibles": sum(1 for k, _ in top5 if k in PUERTOS_SENSIBLES)}


def formato_top(d: dict, n: int = 5) -> str:
    return "; ".join(f"{k}:{v}" for k, v in list(d.items())[:n])


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def escribir_csv(path: Path, columnas: list[str], filas: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columnas, extrasaction="ignore")
        w.writeheader()
        w.writerows(filas)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path)
    ap.add_argument("--base", type=Path)
    ap.add_argument("--reutilizar", type=Path, help="carpeta existente: regenera las fichas con la salida cruda y la "
                    "resolución externa guardadas (sin consultar nada) y exige que la clave no cambie")
    a = ap.parse_args()
    if a.reutilizar:
        destino = a.reutilizar.expanduser()
        raw_path, resolucion = destino / "salida_cruda.json", json.loads((destino / "resolucion_externa.json").read_text())
    else:
        if not (a.raw and a.base):
            sys.exit("falta --raw y --base (o --reutilizar)")
        destino, raw_path, resolucion = None, a.raw, None
    texto = raw_path.read_text(encoding="utf-8")
    raw = json.loads(texto[texto.index('{"extraido_utc"'):])
    if not raw.get("marco_ok"):
        sys.exit(f"marco insuficiente: {raw.get('exclusiones')}")
    marco = [m["ip"] for m in raw["marco"]]
    muestra = raw["muestra"]
    if random.Random(raw["semilla"]).sample(marco, len(muestra)) != muestra:
        sys.exit("la muestra no se reproduce con random.Random(semilla).sample en este equipo")
    if resolucion is None:
        destino = a.base.expanduser() / raw["extraido_utc"][:19].replace(":", "").replace("-", "")
        destino.mkdir(parents=True, exist_ok=False)
        with ThreadPoolExecutor(max_workers=8) as ex:
            dns = dict(zip(muestra, ex.map(resolver_dns, muestra)))
        cymru = cymru_masivo(muestra)
        (destino / "resolucion_externa.json").write_text(json.dumps({"dns": dns, "cymru": cymru}, ensure_ascii=False, indent=1))
    else:
        dns, cymru = resolucion["dns"], resolucion["cymru"]
        anterior = destino / "v1_reemplazada"
        anterior.mkdir(exist_ok=False)
        for nombre in ("ficha_ciega.csv", "ficha_segundo_etiquetador.csv", "manifiesto_precision_p2.md",
                       "construir_ficha.py", "analizar_etiquetado.py"):
            shutil.move(destino / nombre, anterior / nombre)

    rng = random.Random(SEMILLA + 1)       # ids opacos: no derivan de la IP ni de su posición
    ids: list[str] = []
    while len(ids) < len(muestra):
        nuevo = f"{rng.getrandbits(32):08x}"
        if nuevo not in ids:
            ids.append(nuevo)
    por_ip = {m["ip"]: m for m in raw["marco"]}
    comp, sur = raw["comportamiento"], raw["suricata"]
    ficha, clave = [], []
    for i, ip in zip(ids, muestra):
        c, s = comp[ip], sur.get("por_ip", {}).get(ip, {})
        cy, d = cymru.get(ip, {}), dns[ip]
        pre, regla = preetiquetar(d, cy)
        ficha.append({"id": i, "ip": ip, "net24": net24(ip), "rdns": d["rdns"], "fcrdns": d["fcrdns"], "asn": cy.get("asn", ""),
                      "organizacion": cy.get("as_name", ""), "pais": cy.get("pais", ""), **metricas_comportamiento(c["puertos"]),
                      "top5_puertos": formato_top(c["puertos"]), "primera_vista": c["primera"], "ultima_vista": c["ultima"],
                      "suricata_alertas": "" if sur.get("aviso") else s.get("alertas", 0),
                      "suricata_firmas": formato_top(s.get("firmas", {})), "suricata_categorias": formato_top(s.get("categorias", {})),
                      "pre_etiqueta": pre, "regla": regla, "etiqueta": "", "evidencia": "", "notas": ""})
        m = por_ip[ip]
        enr = (m.get("payload") or {}).get("enrichment") or {}
        clave.append({"id": i, "ip": ip, "score": m.get("risk_score"), "tier": m.get("tier"),
                      "fuentes_ti": "+".join(enr.get("corroborating_sources") or []) or "ninguna",
                      "abuseipdb_score": enr.get("abuseipdb_score"), "otx_pulsos": enr.get("otx_pulse_count"),
                      "hora_bloqueo": m.get("event_time"), "trace_id": m.get("trace_id")})
    clave_path = destino / "clave_sellada.csv"
    if a.reutilizar:       # la clave ya está sellada: se regenera en memoria y debe dar exactamente el mismo archivo
        verificacion = destino / ".clave_verificacion.csv"
        escribir_csv(verificacion, COLUMNAS_CLAVE, clave)
        igual = sha256(verificacion) == sha256(clave_path) == CLAVE_SHA256_ESPERADA
        verificacion.unlink()
        if not igual:
            sys.exit("la clave regenerada no coincide con la sellada: no se toca nada más")
    else:
        escribir_csv(clave_path, COLUMNAS_CLAVE, clave)
    escribir_csv(destino / "ficha_ciega.csv", COLUMNAS_FICHA, ficha)
    escribir_csv(destino / "ficha_segundo_etiquetador.csv", COLUMNAS_SEGUNDO, ficha[:SEGUNDO_ETIQUETADOR])
    if not a.reutilizar:
        shutil.copy(raw_path, destino / "salida_cruda.json")
    for p in Path(__file__).resolve().parent.glob("*.py"):
        shutil.copy(p, destino / p.name)

    filas = [f"| `{p.name}` | {p.stat().st_size} | `{sha256(p)}` |" for p in sorted(destino.iterdir()) if p.is_file()]
    ex = raw["exclusiones"]
    nota_v2 = ("Segunda versión de las fichas (columnas numéricas derivadas del comportamiento, nuevo orden de evaluación). "
               "Nadie había etiquetado la versión anterior, que queda en `v1_reemplazada/`. La clave sellada no cambió.\n\n"
               if a.reutilizar else "")
    (destino / "manifiesto_precision_p2.md").write_text(
        "# Manifiesto de la muestra de precisión del período 2 (salidas fuera de git)\n\n" + nota_v2 +
        f"Extraído {raw['extraido_utc']} UTC. Ventana de bloqueos: {raw['ventana'][0]} a {raw['ventana'][1]}. Semilla {raw['semilla']}; "
        f"algoritmo: {raw['algoritmo']} (Python {raw['python']} en .140; reproducido en este equipo con Python {sys.version.split()[0]}).\n\n"
        f"Marco: N = {ex['n_marco']}. Exclusiones: {json.dumps(ex, ensure_ascii=False)}.\n\n"
        "El sha256 de `clave_sellada.csv` se registró aquí antes de entregar la ficha para etiquetar.\n\n"
        "| Archivo | Bytes | sha256 |\n|---|---|---|\n" + "\n".join(filas) + "\n", encoding="utf-8")
    print(destino)
    print(f"preetiquetadas: {sum(1 for f in ficha if f['pre_etiqueta'])} de {len(ficha)}")


if __name__ == "__main__":
    main()
