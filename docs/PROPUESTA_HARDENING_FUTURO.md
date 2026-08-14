# Propuesta: hardening de `motor-watcher.service` con `sd_notify` + `WatchdogSec`

Estado: **diseño aprobado, implementación diferida a post-defensa** (aprobado 2026-08-12).
No implementar sin tiempo de validación real — un `WatchdogSec` mal calibrado puede
causar restarts en caliente del vigilante FIM por falsos positivos.

## Contexto

El 2026-08-12 se auditó una caída silenciosa de `motor-watcher.service` (.139) de
~34 días (10 jul → 12 ago), causada por un crash-loop el 9 de julio que agotó el
`StartLimitBurst` por defecto de systemd (5 reinicios en 10s), dejando el unit en
estado `failed` sin que `Restart=always` volviera a intentarlo. Ver
`docs/BITACORA_TECNICA.md` (H17) para el detalle completo del incidente.

Esa causa raíz ya se corrigió (`StartLimitIntervalSec=0` en el unit, desplegado el
mismo día) y se agregó un heartbeat vía Redis + alerta por correo con cooldown,
independiente del proceso, para detectar cualquier futura caída sin depender de
que systemd la resuelva solo.

**Lo que ninguno de esos dos fixes cubre**: un `motor-watcher.py` que sigue *vivo*
como proceso (PID activo, systemd lo ve `active (running)`) pero cuyo loop
principal (`tail_alerts()`) quedó colgado — por ejemplo, un deadlock, un `read()`
bloqueado indefinidamente sobre un filesystem con problemas, o cualquier estado
donde el proceso no crashea pero tampoco progresa. Ni `Restart=always` (no hay
nada que reiniciar, el proceso no murió) ni el heartbeat basado en Redis (que
igual dejaría de actualizarse, pero solo *alerta* — no *repara*) resuelven esto
automáticamente. Ahí es donde entra `sd_notify` + `WatchdogSec`: systemd puede
matar y reiniciar un proceso colgado si deja de "avisar que sigue vivo" dentro
de una ventana de tiempo.

## Diseño

### 1. Unit file (`motor-watcher.service`)

```ini
[Service]
Type=notify
NotifyAccess=main
WatchdogSec=120
```

`WatchdogSec=120` da margen: el proceso debe notificar al menos una vez cada
120s o systemd lo mata y lo reinicia (con `Restart=always` ya presente, vuelve
solo). El código debe notificar a la mitad de ese intervalo o menos (ver abajo),
siguiendo la recomendación oficial de systemd.

### 2. Código (`watcher.py`)

Sin dependencias nuevas — el protocolo `sd_notify` es un datagrama UNIX simple,
implementable en stdlib puro:

```python
import socket

def sd_notify(state: str) -> None:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return  # corriendo fuera de systemd (debug local) -- no-op
    if addr[0] == "@":
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(state.encode())
    except OSError:
        pass  # no fatal -- si falla el notify, que decida el watchdog de systemd
```

En `tail_alerts()`:
- `sd_notify("READY=1")` una sola vez al iniciar el loop (obligatorio con
  `Type=notify` — systemd espera este mensaje para considerar el arranque
  exitoso; si no llega, systemd trata el arranque como fallido).
- `sd_notify("WATCHDOG=1")` cada 30-60s dentro del loop principal, reusando el
  mismo patrón de throttle por `time.monotonic()` que ya tiene el heartbeat de
  Redis (se puede compartir el mismo tick, ver "Reuso" abajo).

### Reuso del heartbeat existente

El heartbeat de Redis (`write_heartbeat()`, ya desplegado) y el ping de
`sd_notify` cubren necesidades distintas pero corren en el mismo punto del
loop. Al implementar esto, fusionar ambos ticks en una sola función interna
(ej. `_tick_liveness()`) que llama a los dos, para no duplicar el manejo de
`last_*` timestamps ni el `try/except` de "no fatal".

## Por qué no se implementa hoy

1. **Type=notify cambia el contrato de arranque.** Si `sd_notify("READY=1")`
   no se llama exactamente cuando corresponde (ej. antes de que
   `open(ALERTS_FILE)` termine, si esa apertura tarda), systemd puede matar el
   proceso por timeout de arranque (`TimeoutStartSec`, default 90s) — un modo
   de falla nuevo que no existe hoy con `Type=simple`.
2. **`WatchdogSec` mal calibrado es peor que no tenerlo.** Si algo legítimo
   bloquea el loop más de 120s (ej. una ráfaga de alertas grande, o
   `trigger_quarantine()` colgado esperando la API de Wazuh sin timeout
   efectivo — revisar si el `timeout=6` de `requests` realmente cubre todos
   los casos), systemd mataría un proceso que en realidad iba a recuperarse
   solo, causando restarts innecesarios y posible pérdida de líneas de
   `alerts.json` en tránsito.
3. **Necesita testing en carga real**, no solo en idle. Antes de habilitar
   `WatchdogSec` en producción, correr el watcher con tráfico de ataque
   simulado (`~/tesis/ataques/campana_automatica.sh` ya existe para esto) y
   confirmar que el ping de watchdog nunca se atrasa más de `WatchdogSec/2`
   incluso bajo ráfaga.

## Plan de implementación futura (post-defensa)

1. Implementar `sd_notify()` + los dos call sites en una rama separada.
2. Cambiar el unit a `Type=notify` con `WatchdogSec` generoso primero (ej. 300s)
   en un entorno de prueba o en horario de bajo tráfico.
3. Correr `campana_automatica.sh` con el watchdog activo, confirmar cero
   restarts espurios durante la ráfaga.
4. Bajar `WatchdogSec` gradualmente (300s → 180s → 120s) solo si cada paso
   corre limpio al menos 48h en producción real antes de bajar más.
5. Documentar el valor final elegido y el motivo en `docs/BITACORA_TECNICA.md`.
