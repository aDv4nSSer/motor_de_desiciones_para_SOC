#!/usr/bin/env bash
# deploy_operativo.sh — compila el Dashboard Operativo en esta máquina y lo
# copia a .140 (motor/static/operativo), servido por motor-soc en /operativo.
#
# El build NUNCA corre en .140 (RAM limitada). Copia con tar sobre UNA sola
# conexión ssh (fail2ban en .139 banea ráfagas de conexiones) y reemplazo
# atómico: la versión anterior queda en operativo.prev para rollback.
#
# Uso:  scripts/deploy_operativo.sh            # tests + build + copia
#       scripts/deploy_operativo.sh --rollback # vuelve a operativo.prev
#
# Requisitos: alias `motor140` en ~/.ssh/config y la llave cargada en ssh-agent.
# El PRIMER despliegue requiere además reiniciar motor-soc (el mount de
# /operativo se registra al arrancar); los siguientes no.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$REPO_ROOT/frontend/operativo"
BUILD_DIR="$REPO_ROOT/motor/static/operativo"
REMOTE_HOST="${REMOTE_HOST:-motor140}"
REMOTE_DIR="tesis/repo/motor/static/operativo"   # relativo al home remoto

if [[ "${1:-}" == "--rollback" ]]; then
  ssh "$REMOTE_HOST" "set -e; cd ~/$(dirname "$REMOTE_DIR"); test -d operativo.prev; rm -rf operativo.failed; mv operativo operativo.failed; mv operativo.prev operativo; echo 'rollback ok'"
  exit 0
fi

ssh-add -l >/dev/null 2>&1 || { echo "La llave no está en ssh-agent: ssh-add --apple-use-keychain ~/.ssh/tesis_ubo_aiayala" >&2; exit 1; }

echo "==> tests y build"
cd "$APP_DIR"
npm test --silent
npm run build --silent
test -f "$BUILD_DIR/index.html"

echo "==> copiando a $REMOTE_HOST:~/$REMOTE_DIR"
tar -C "$BUILD_DIR" -cf - . | ssh "$REMOTE_HOST" "
  set -e
  base=~/$(dirname "$REMOTE_DIR")
  mkdir -p \"\$base\"
  tmp=\$(mktemp -d \"\$base/.operativo.XXXXXX\")
  tar -xf - -C \"\$tmp\"
  test -f \"\$tmp/index.html\"
  chmod 755 \"\$tmp\"
  rm -rf \"\$base/operativo.prev\"
  if [ -d \"\$base/operativo\" ]; then mv \"\$base/operativo\" \"\$base/operativo.prev\"; fi
  mv \"\$tmp\" \"\$base/operativo\"
  echo \"desplegado: \$(find \"\$base/operativo\" -type f | wc -l) archivos\"
"
echo "==> listo. Verificar: https://motor-soc-ubo.duckdns.org/operativo/"
