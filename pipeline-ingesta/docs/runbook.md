# Runbook: Pipeline de Ingesta Golden Subset v4

## Requisitos previos

### Permisos de Suricata
```bash
sudo chmod o+rx /var/log/suricata
```
Sin esto Vector no puede leer el eve.json (directorio solo accesible por grupo suricata).

## Iniciar el pipeline

### Modo desarrollo (stdin, para testing)
```bash
cd ~/documents/tesis/motor_de_desiciones_para_SOC/pipeline-ingesta
source ../.venv/bin/activate
cat samples/sample_eve.json | vector --config configs/vector.toml 2>/dev/null | jq -c .
```

### Modo producción (lee eve.json de Suricata en tiempo real)
```bash
cd ~/documents/tesis/motor_de_desiciones_para_SOC/pipeline-ingesta
vector --config configs/vector.production.toml
```

## Verificar que funciona

```bash
tail -f outputs/flows_$(date +%Y-%m-%d_%H).jsonl | jq -c .
wc -l outputs/flows_$(date +%Y-%m-%d_%H).jsonl
vector test configs/vector.toml
```

## Troubleshooting

### Vector no procesa nada
1. Verificar permisos: `ls -la /var/log/suricata/`
2. Verificar que Suricata está corriendo: `sudo systemctl status suricata`
3. Verificar que eve.json crece: `watch -n 1 wc -l /var/log/suricata/eve.json`
4. Correr Vector sin suprimir logs: `vector --config configs/vector.production.toml`

### El archivo JSONL no se crea
```bash
mkdir -p ~/documents/tesis/motor_de_desiciones_para_SOC/pipeline-ingesta/outputs
```

### Resetear checkpoints
```bash
rm -rf .vector-data/*
```

## Archivos importantes

| Archivo | Descripción |
|---|---|
| configs/vector.toml | Config desarrollo (stdin) |
| configs/vector.production.toml | Config producción (file source) |
| samples/sample_eve.json | EVE JSON sintético para tests |
| samples/pcaps/ | PCaps de prueba para Suricata offline |
| outputs/flows_YYYY-MM-DD_HH.jsonl | Flows procesados rotados por hora |

## Deploy en ProLiant Gen 10

1. Clonar repo: `git clone https://github.com/aDv4nSSer/motor_de_desiciones_para_SOC.git`
2. Instalar Vector: `curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash`
3. Agregar al PATH: `echo 'export PATH="$HOME/.vector/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
4. Actualizar rutas en vector.production.toml (cambiar /home/aiayala/ por ruta del servidor)
5. Permisos Suricata: `sudo chmod o+rx /var/log/suricata`
6. Crear outputs: `mkdir -p outputs`
7. Arrancar: `vector --config configs/vector.production.toml`
