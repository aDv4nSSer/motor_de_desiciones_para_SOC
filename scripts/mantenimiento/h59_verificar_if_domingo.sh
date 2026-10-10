#!/usr/bin/env bash
# h59_verificar_if_domingo.sh — Verificación posterior al reentrenamiento
# semanal del Isolation Forest (cron de .140: domingo 04:00 -03). Solo lectura.
#
# Igual hash (prefijo 4958eb4b) = mismo modelo: se anota como EVENTO.
# Hash distinto = CORTE DE RÉGIMEN (cambia anomaly_score, risk_score y tiers):
# se anota en docs/PENDIENTES_MODO_SOMBRA.md §6 y en motor/regimes.py, y las
# métricas del período 2 se separan por tramo (H56, H59).
#
# Uso (en .140): bash ~/tesis/repo/scripts/mantenimiento/h59_verificar_if_domingo.sh
set -u
CORPUS="$HOME/tesis/motor_decisiones_soc/scripts/training/corpus/corpus_relabeled_v3_completo.csv"
ESPERADO="4958eb4b"
echo "== $(date '+%F %T %z')"
echo "cron: $(crontab -l 2>/dev/null | grep -c retrain_isolation_forest) línea(s) de reentrenamiento"
echo "corpus mtime: $(stat -c %y "$CORPUS" 2>&1)  (esperado 2026-06-20 13:52)"
echo "directorios de modelos: $(readlink -f "$HOME/tesis/motor/models") | $(readlink -f "$HOME/tesis/motor-runtime/models")"
for f in "$HOME/tesis/motor-runtime/models/isolation_forest.pkl" "$HOME/tesis/motor/models/isolation_forest.pkl"; do
  [ -f "$f" ] && echo "$f sha256=$(sha256sum "$f" | cut -c1-16) mtime=$(stat -c %y "$f")"
done
H=$(sha256sum "$HOME/tesis/motor-runtime/models/isolation_forest.pkl" | cut -c1-8)
if [ "$H" = "$ESPERADO" ]; then
  echo "RESULTADO: mismo modelo ($H): EVENTO, no corte de régimen"
else
  echo "RESULTADO: modelo distinto ($H, antes $ESPERADO): CORTE DE RÉGIMEN"
fi
echo "motor-soc activo desde: $(systemctl show -p ActiveEnterTimestamp --value motor-soc)"
for log in "$HOME/tesis/motor/logs/retrain_cron.log" "$HOME/tesis/repo/motor/logs/retrain_cron.log"; do
  [ -f "$log" ] && { echo "-- $log"; tail -n 6 "$log" | cut -c1-140; }
done
echo "health: $(curl -s -o /dev/null -w %{http_code} localhost:8000/health)"
