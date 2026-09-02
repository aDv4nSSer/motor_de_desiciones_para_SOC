# Motor de decisión basado en riesgo para SOAR en SOC

[![Seguridad (DevSecOps)](https://github.com/aDv4nSSer/motor_de_desiciones_para_SOC/actions/workflows/security.yml/badge.svg?branch=develop)](https://github.com/aDv4nSSer/motor_de_desiciones_para_SOC/actions/workflows/security.yml)

Tesis UBO 2026 — *"Motor de decisión basado en riesgo para SOAR en SOC:
integración de Machine Learning calibrado con orquestación de respuesta
automatizada."* Sistema en operación real sobre un laboratorio propio de 3
servidores, no solo una prueba de concepto: Suricata inline + LightGBM
calibrado deciden en milisegundos, un worker asíncrono enriquece con
threat intel y contexto histórico, y Wazuh ejecuta la respuesta.

**Estado:** semillero ~95% (sept 2026) · cierre de documento 16 oct 2026 ·
defensa 30 oct 2026 · branch activo `develop`.

## Qué hace

```
[FAST PATH — síncrono, <100ms]
Suricata → Vector → Feature Eng → IsolationForest → LightGBM (Golden 4 v7.1)
         → lookup O(1) Redis known-bad → decisión provisional (T0–T3)

[ENRICHMENT PATH — async, segundos]
Threat Intel (AbuseIPDB) + Contexto histórico → re-scoring + acumulación de riesgo
         → SHAP + rules.yaml → Wazuh Active Response | soc-decisions (hash-chain) | Dashboard
```

El score de LightGBM es una probabilidad real de ataque (calibración
isotónica verificada, Brier 0.058). Suricata y LightGBM son detectores
**complementarios** (AUC 0.38 entre ambos es esperado, no un defecto): uno
detecta firmas, el otro patrones generales — ver
[`.claude/rules/model-contract.md`](.claude/rules/model-contract.md) para
el contrato completo del modelo y los thresholds operacionales.

## Stack

| Capa | Herramienta |
|---|---|
| Detección IDS | Suricata 8.0.5 (inline, NFQUEUE) |
| Pipeline de ingesta | Vector 0.55.0 (VRL) |
| ML | LightGBM + Isolation Forest + calibración isotónica |
| Backend | FastAPI + Pydantic v2 + Python 3.11+ |
| Cola / caché / contadores | Redis (Streams + KV) |
| SIEM / Active Response | Wazuh Manager 4.14.5 |
| Indexación / auditoría | OpenSearch (hash-chain append-only) |
| Contenedores | Docker + Docker Compose |
| CI / Quality Gate | pre-commit: bandit + detect-secrets + ruff |

## Componentes del repo

- **`motor/`** — Núcleo del motor: FastAPI (`main.py`), carga de modelo
  (`model.py`, LightGBM + Isolation Forest calibrados), indexador con
  hash-chain a OpenSearch (`opensearch_indexer.py`), auth (`auth.py`) y
  dashboard operativo (`dashboard.py`/`dashboard.html`).
- **`api/`** — Endpoints y schemas Pydantic v2 del Fast Path
  (`api/endpoints/predict.py`).
- **`pipeline-ingesta/`** — Normaliza EVE JSON de Suricata al Golden Subset
  (11 features NF-*-v3). Ver su propio `pipeline-ingesta/README.md`.
- **`vigilante/`** — FIM + respuesta activa en `.138` (cuarentena de
  archivo, casos, heartbeat, notificación por correo).
- **`infra/`** — Configuración desplegada: systemd, Suricata, Vector,
  nginx (reverse proxy), DuckDNS.
- **`scripts/training/`** — Reentrenamiento LightGBM (etiquetador,
  relabeling con GroupKFold host-disjunto).
- **`tests/`** — Unitarios e integración (`pytest --cov`).

Responsables: Antonio Ayala (infraestructura, motor, integración) ·
Joaquín Arias (modelo ML, entrenamiento, calibración).

## Ampliación en curso — R-SOAR como apoyo de cumplimiento (set 2026)

Por pedido del profesor guía, el sistema se está ampliando para funcionar
también como apoyo de gestión de seguridad de la información (SGSI) y
cumplimiento ante la ANCI (Ley 21.663), no solo como motor técnico.
Decisiones cerradas el 1-sep-2026, detalle completo en
[`docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`](docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md):

- **R1 (enriquecimiento):** se suma OTX/AlienVault, CrowdSec y contexto
  nativo de Wazuh (FIM, privilegios, rootcheck).
- **R2 (respuesta):** repertorio graduado — log, alertar + caso, bloqueo
  de IP, rate-limiting, cuarentena de host vía switch SG350 — con
  aprobación humana obligatoria para las acciones de alto impacto.
- **Roles y acceso:** Operador N1/N2 y CISO/Gerencia, JWT, mínimo
  privilegio, cada acceso y acción queda en el hash-chain de auditoría.
- **Dashboards:** Operativo (alertas, casos vía Iris Web, aprobaciones) y
  Gerencial/CISO (cumplimiento Ley 21.663, métricas de valor, historial).
- **Iris Web** pasa a ser dependencia core desde semana 1-2 del ciclo.

## Documentación

| Documento | Contenido |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Arquitectura, decisiones inamovibles, prohibiciones, stack completo |
| [`docs/BITACORA_TECNICA.md`](docs/BITACORA_TECNICA.md) | Registro cronológico de hallazgos (H1–H22): dataset, modelo, red, infraestructura |
| [`docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`](docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md) | Especificación de la ampliación SOAR (R1/R2, roles, dashboards) |
| [`docs/PLAN_SPRINTS.md`](docs/PLAN_SPRINTS.md) | Plan semana a semana hasta la defensa |
| [`docs/BACKLOG_INFRA.md`](docs/BACKLOG_INFRA.md) / [`docs/BACKLOG_DASHBOARD.md`](docs/BACKLOG_DASHBOARD.md) | Pendientes técnicos abiertos |
| [`.claude/rules/model-contract.md`](.claude/rules/model-contract.md) | Contrato del modelo ML activo (Golden 4 v7.1): features, thresholds, versiones descartadas |

## Equipo

- **Antonio Ayala** — infraestructura, motor de decisiones, integración, deploy
- **Joaquín Arias** — modelo ML: entrenamiento, calibración, reentrenamiento
- **Miguel Castillo** — profesor guía

## Calidad y seguridad

Pre-commit obligatorio en cada commit: `bandit` (SAST), `detect-secrets`,
`ruff`. CI corre el mismo gate en cada push (badge arriba). Git flow:
`feature/*` → `develop` → `main` (solo vía PR revisado). Ver
[`.claude/rules/security.md`](.claude/rules/security.md) y
[`.claude/rules/testing.md`](.claude/rules/testing.md) para los estándares
completos.
