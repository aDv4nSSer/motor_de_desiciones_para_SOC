# Pipeline de Ingesta y Normalización — Golden Subset

Componente de **infraestructura** del proyecto de tesis "Motor de decisión
basado en riesgo para SOAR en SOC". Transforma logs crudos de Suricata
(EVE JSON) a las 11 features del Golden Subset, compatibles con el esquema
de entrenamiento del modelo ML (NF-*-v3 de University of Queensland).

## Arquitectura

En desarrollo local, el source es `stdin` para iteración rápida.
En producción, el source es el archivo `eve.json` de Suricata.

## Golden Subset: 11 features

| # | Feature | Tipo | Fuente Suricata |
|---|---------|------|-----------------|
| 1 | PROTOCOL | int16 | `proto` (mapeo string→int) |
| 2 | IN_BYTES | int32 | `flow.bytes_toserver` |
| 3 | IN_PKTS | int32 | `flow.pkts_toserver` |
| 4 | OUT_BYTES | int32 | `flow.bytes_toclient` |
| 5 | OUT_PKTS | int32 | `flow.pkts_toclient` |
| 6 | TCP_FLAGS | int16 | `tcp.tcp_flags` (hex→int) |
| 7 | CLIENT_TCP_FLAGS | int16 | `tcp.tcp_flags_ts` (hex→int) |
| 8 | SERVER_TCP_FLAGS | int16 | `tcp.tcp_flags_tc` (hex→int) |
| 9 | FLOW_DURATION_MILLISECONDS | int32 | `flow.end - flow.start` (ms) |
| 10 | SRC_TO_DST_SECOND_BYTES | float64 | `IN_BYTES / (duración/1000)` |
| 11 | DST_TO_SRC_SECOND_BYTES | float64 | `OUT_BYTES / (duración/1000)` |

## Uso (desarrollo local)

```bash
cat samples/sample_eve.json | vector --config configs/vector.toml 2>/dev/null | jq -c .
```

## Validación

```bash
vector validate configs/vector.toml
vector test configs/vector.toml
```

## Decisiones técnicas

- **Vector + VRL** (no Logstash, no script Python): rendimiento, tipado, tests.
- **`flow.start` y `flow.end` parseados, no `flow.age`**: `flow.age` viene en
  segundos enteros y pierde la precisión sub-segundo que el modelo necesita.
- **`||` para defaults de campos ausentes** (no `??`): `??` solo cubre errores
  de funciones falibles; el acceso a campos inexistentes devuelve `null`.
- **Sin nProbe**: herramienta comercial, costo prohibitivo. El Golden Subset
  está diseñado para ser 100% derivable desde Suricata open source.

## Pendientes de verificación

- [ ] Confirmar mapeo `tcp_flags_ts/tc` ↔ `CLIENT/SERVER_TCP_FLAGS` con
      pcap real de handshake TCP conocido.
- [ ] Validar distribuciones del pipeline vs dataset NF-CSE-CIC-IDS2018-v3
      (KS test + PSI).
- [ ] Alinear timeouts de Suricata con los de nProbe usados por Queensland.

## Estructura
