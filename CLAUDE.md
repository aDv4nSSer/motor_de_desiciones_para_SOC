# Motor de Decisiones SOAR para SOC

Tesis UBO: "Motor de decisión basado en riesgo para SOAR en SOC: integración de Machine
Learning calibrado con orquestación de respuesta automatizada."
Semillero: julio 2026 (~90%) | Defensa: noviembre 2026 | Branch activo: develop

<!-- Roles: Antonio = infra/integración/backend | Joaquín = ML | Asesor: Prof. Miguel Castillo -->
<!-- Reglas extendidas: .claude/rules/model-contract.md | security.md | observability.md -->

---

## Contexto reciente (semana del 18–25 ago 2026)

La red del laboratorio migró de subred plana a NAT/VLANs con `.139` como
bastion/gateway obligatorio, y se corrigió un bug de firewall que dejaba a
Suricata casi ciego pese a estar activo. No afecta al modelo, a los features
ni al pipeline de entrenamiento — es infraestructura de red pura, a cargo de
Antonio. Detalle completo en `docs/BITACORA_TECNICA.md` (H16–H21); estado
operativo resumido en la sección Infraestructura más abajo.

---

## Para Joaquín — tu parte esta semana

Tus tareas actuales, con dueño y fecha, viven en `docs/PLAN_SPRINTS.md`
(Sprint 1 en adelante) — ahí está el detalle semana a semana de
reentrenamiento LightGBM (Camino E, GroupKFold host-disjunto), tablas/
gráficos comparativos de métricas, y las secciones de Marco Teórico y
Resultados que te corresponden. Referencias técnicas de apoyo:
`.claude/rules/model-contract.md` (contrato de features y versión activa del
modelo — verificar siempre ahí antes de tocar el feature set o los
thresholds) y los hallazgos H1–H10 de `docs/BITACORA_TECNICA.md` (domain
shift, data leakage, etiquetado, límites del Isolation Forest).

**No necesitás tocar** red, VLANs, Suricata, bastion host ni la sección
Infraestructura de este documento — eso lo maneja Antonio. Si algo de esa
parte te bloquea (por ejemplo, acceso a `.140` para correr un
reentrenamiento), avisale a él directamente en vez de intentar resolverlo
por tu cuenta.

---

## Stack

| Capa | Herramienta / Versión |
|---|---|
| Detección IDS | Suricata 8.0.5 |
| Pipeline ingestión | Vector 0.55.0 (VRL) |
| ML | LightGBM + Isolation Forest + calibración isotónica |
| Backend | FastAPI + Pydantic v2 + Python 3.11+ |
| Cola / Caché / Contadores | Redis Streams + Redis KV |
| SIEM / Active Response | Wazuh Manager 4.14.5 |
| Indexación / Auditoría | OpenSearch |
| Contenedores | Docker + Docker Compose |
| CI Quality Gate | pre-commit: bandit + detect-secrets + ruff |

---

## Arquitectura: decisiones inamovibles

```
[FAST PATH — síncrono, <100ms]
Suricata → Vector → Feature Eng → IsolationForest → LightGBM (Golden 4 v7.1)
         → lookup O(1) Redis known-bad
         → Decisión PROVISIONAL + publish(event, trace_id) → Redis Stream

[ENRICHMENT PATH — async, worker consume Redis Stream, segundos]
Historical Context Svc ─┐
Threat Intel Svc ────────┼─→ Decision Engine re-scoring + risk accumulation
                         └─→ Explainability (SHAP + rules.yaml)
                             → Wazuh | soc-decisions (audit, append-only) | Dashboard
```

**Principios inamovibles:**
- **Correlación en el motor**, no en Vector. Vector solo transforma y enruta.
- **Flows y alertas procesados separados** — nunca combinar en Vector.
- **Fast Path nunca bloquea por IO** — cero OpenSearch, APIs externas o Redis scan en path crítico.
- **`trace_id`** nace en Fast Path y viaja en TODO: header `X-Trace-Id`, campos OpenSearch, logs.
  Permite reconstruir cualquier decisión con una sola query por `trace_id`.
- **Redis triple rol:** cola (Streams), caché L1 (TI + contexto), contadores rodantes por entidad.
- **Degradación con gracia:** servicio externo caído → campo `"unavailable"`, decisión continúa.
- **Acumulación de riesgo por entidad:** sorted set Redis con decaimiento temporal.
  No decidir sobre un evento aislado — esperar convergencia de señales.
- **Suricata y LightGBM son detectores complementarios:** AUC 0.38 entre ellos es correcto
  y esperado. Suricata detecta firmas; LightGBM detecta patrones sospechosos generales.

---

## Tiers de Decisión y ATT&CK

| Tier | Criterio base | Override |
|---|---|---|
| T0 | Score bajo, sin señales adicionales | — |
| T1 | Score medio O anomalía leve | — |
| T2 | Score medio + señal adicional (TI o contexto) | — |
| T3 | Score alto + señal adicional O classtype crítico | Suricata classtype → T3 sin importar ML |

Toda decisión T2+ genera `rules_fired[]` y `reasoning[]` desde `rules.yaml`.
Los 38 classtypes de Suricata se mapean a técnicas MITRE ATT&CK — propagar el tag ATT&CK
desde el classtype hasta la evidencia en `soc-decisions` y hasta Wazuh.
**No usar threshold global 0.5.** Ver `.claude/rules/model-contract.md` para thresholds por dataset.

---

## Servicios en construcción

**`decision-engine`** — núcleo del sistema (worker async + FastAPI)
- Fast Path: `POST /api/v1/decide` → decisión provisional en ms.
- Worker: consume Redis Stream → re-scoring con contexto + TI.
- `rules.yaml`: cada regla `{id, when, text, weight}` → `rules_fired[]` + `reasoning[]`.
- SHAP TreeExplainer: instancia única en memoria; calcular solo para score > `SHAP_THRESHOLD`.
- Acumular riesgo: `risk:{entity_type}:{entity_id}` sorted set Redis con decaimiento TTL.
- Hash chain audit: `hash = sha256(contenido + prev_hash)` en cada doc de `soc-decisions`.
- Feedback loop: `POST /api/v1/decisions/{id}/feedback` → persiste etiqueta TP/FP/benigno
  para reentrenamiento futuro. Almacenar en `soc-feedback` OpenSearch.

**`historical-context-svc`** — FastAPI async
- `GET /api/v1/context/{entity_type}/{entity_id}` → `ContextResponse`.
- Redis-first: buckets `ctx:{type}:{id}:h:{YYYYMMDDHH}` TTL 25h; `MGET` de 24 keys = events_24h.
- Trend: media histórica vs última hora → ratio + z-score en Python (no plugin OpenSearch).
- Recidivismo: query `soc-decisions` filtrada por T2/T3 en los últimos 30d para la entidad.
- Fallback OpenSearch si Redis frío; cachear resultado en Redis TTL 60s.

**`threat-intel-svc`** — FastAPI async, patrón adapter
- `GET /api/v1/enrich?indicator=&type=ip|domain|hash` → `NormalizedTI`.
- Cascada: `ti-feeds` L0 → Redis L1 (TTL: malicioso 6h / limpio 1h / desconocido 30min) →
  `ti-cache` L2 → API externa. Negative caching obligatorio.
- Circuit breaker por proveedor + token bucket por API. Stale-while-revalidate activado.
- Schema: `{indicator, type, verdict, score 0-100, sources[], cache{hit, level, stale}}`.
- Proveedores: AbuseIPDB + AlienVault OTX. VirusTotal solo para hashes puntuales. MISP diferido.

---

## Índices OpenSearch

| Índice | Propósito | Retención | Restricción crítica |
|---|---|---|---|
| `soc-events-*` | Flows Suricata | 7–14d | ISM rollover diario |
| `soc-alerts-*` | Alertas Wazuh | 30d | — |
| `soc-decisions` | Evidencia + auditoría hash-chain | 90d | **APPEND-ONLY. Sin UPDATE/DELETE jamás.** |
| `soc-feedback` | Etiquetas analista (TP/FP) | 180d | Insumo para reentrenamiento |
| `ti-cache` | Caché TI normalizada L2 | 7–30d | — |
| `ti-feeds` | Known-bad feeds locales | Refresco continuo | — |

Todos los índices: `number_of_replicas: 0`, `index.codec: best_compression`. ISM obligatorio.

---

## Estándares de Calidad Empresarial

**Contratos de API:**
- URLs versionadas: `/api/v1/...` en todos los endpoints sin excepción.
- Error response uniforme: `{"error": {"code": "STR", "message": "...", "trace_id": "...", "timestamp": "ISO"}}`.
- Header `X-Trace-Id` presente en TODA respuesta, sin excepción.
- `GET /health` → `{status, version, dependencies: [{name, status, latency_ms}]}`.
- `GET /metrics` → formato Prometheus. Ver `.claude/rules/observability.md`.

**Código:**
- Type hints en todas las funciones públicas. Docstring con `Args`, `Returns`, `Raises`.
- Pydantic v2: sin `@validator` ni `__fields__` (sintaxis v1).
- `httpx.AsyncClient` con `timeout=httpx.Timeout(connect=2.0, read=5.0)` — nunca `requests`.
- `asyncio.sleep()` — nunca `time.sleep()` en código async.
- Constantes en `constants.py` nombradas — sin magic numbers en lógica de negocio.
- Sin `except Exception: pass` — cada excepción tiene fallback documentado y logeado.
- Tests unitarios para lógica de decisión y de scoring. Tests de integración para flujos end-to-end.

---

## Infraestructura

| Host | IP pública / privada | Rol | Estado migración |
|---|---|---|---|
| Gen 10 (`.139`) | 200.54.12.139 (SSH puerto 2222) | Bastion/NAT gateway in-line, Suricata, Wazuh Manager, honeypot Cowrie | Migrado — trunk VLAN vía `eno2` |
| Lenovo (`.140`) | 10.10.10.3 (VLAN 10) | Motor FastAPI + Redis + OpenSearch (Docker) | Migrado — SSH puerto 2222 |
| Gen 9 A (`.138`) | 200.54.12.138 (pública, aún directa) | Web: nginx + WordPress + MariaDB (fuente de tráfico real) | Pendiente (requiere acceso físico) |
| `.141` (Eliecer, IA) | 10.20.20.2 (VLAN 20, aún no operativo) | Servidor de terceros | Pendiente |
| `.142` (Agustín, emprendedores) | 10.20.20.3 (VLAN 20, aún no operativo) | Servidor de terceros | Pendiente, falta cablear al switch |

> **Nota de migración (ago 2026):** la topología pasó de subred plana `200.54.12.136/29`
> compartida por todos los hosts a NAT/gateway con VLANs sobre `.139` (in-line, ya no
> sensor pasivo con SPAN). `.139` mantiene IP pública directa (bastion/jump host
> obligatorio); `.140` ya vive solo en VLAN 10 (`10.10.10.0/24`) sin IP pública propia.
> `.138`, `.141`, `.142` siguen con su acceso viejo hasta que se migren físicamente.
> Detalle completo, verificación por SSH y hallazgos (H17–H20) en `docs/BITACORA_TECNICA.md`.
> Reemplaza la nota de jul 2026 sobre migración de Motor/Redis a `.140`, que sigue vigente
> a nivel de servicio pero ya no a nivel de red (ese host ya no tiene IP pública).

**Acceso SSH — bastion obligatorio para todo host detrás de VLAN:**

```bash
# Directo al bastion (.139) — sigue con IP pública
ssh -i ~/.ssh/tesis_ubo_aiayala -p 2222 aiayala@200.54.12.139

# A cualquier host en VLAN (ejemplo .140 en VLAN 10) — jump host via .139
# OJO: especificar -p 2222 tanto para el jump como para el destino final,
# el SSH interno de cada host migrado corre en 2222, no en el 22 estándar.
ssh -i ~/.ssh/tesis_ubo_aiayala -p 2222 -J aiayala@200.54.12.139:2222 aiayala@10.10.10.3
```

`.138`, `.141`, `.142` (no migrados aún) se siguen alcanzando por su IP pública/ruta vieja
directa — no aplican el flujo de jump host hasta que se migren.

Servicios nuevos en Docker, red interna Docker. Solo dashboard expuesto externamente
(nginx reverse proxy en `.139` → `proxy_pass` a la IP privada de cada host, ej.
`motor-soc-ubo.duckdns.org` → `10.10.10.3:8000`).
Redis: `maxmemory-policy allkeys-lru`. Uvicorn: ≤2 workers por servicio (RAM limitada).
OpenSearch heap: `Xms = Xmx ≤ 8GB`. ISM policy activa en todos los índices.

---

## Git Flow

| Branch | Propósito | Merge hacia |
|---|---|---|
| `main` | Producción estable | Solo desde develop vía PR revisado |
| `develop` | Integración continua | — |
| `feature/{servicio}-{descripcion}` | Trabajo en curso | → develop |

Commits semánticos: `feat:` `fix:` `refactor:` `test:` `docs:` `chore:`.
Pre-commit obligatorio: `bandit`, `detect-secrets`, `ruff`. Sin bypass salvo emergencia documentada.
Cambio de arquitectura → actualizar `ROADMAP.md` en el mismo commit.

---

## PROHIBICIONES — Leer antes de cualquier cambio

1. **No combinar flows y alertas en Vector** — correlación es responsabilidad exclusiva del motor.
2. **No usar threshold global 0.5** — thresholds por dataset. Ver `.claude/rules/model-contract.md`.
3. **No agregar features ausentes en NF-v3**: `FLOW_STATE`, `APP_PROTO`, derivadas de byte-rate.
4. **No usar `L4_SRC_PORT` como señal** — data leakage documentado y validado.
5. **No hacer IO síncrono en Fast Path** — cero OpenSearch/API bloqueante en path crítico.
6. **No hacer UPDATE ni DELETE en `soc-decisions`** — append-only, parte del audit hash-chain.
7. **No usar `requests` síncronos** — siempre `httpx.AsyncClient` con timeout explícito.
8. **No hardcodear secrets, IPs ni credenciales** — siempre desde variables de entorno vía Settings.
9. **No comparar API keys con `==`** — usar `secrets.compare_digest()` (timing-safe).
10. **No proponer MISP ni LLMs como trabajo activo** — fuera de alcance de hardware y plazo.
11. **No proponer réplicas en OpenSearch** — single node, `replicas: 0`.
12. **No tocar la red TI universitaria (25 PCs)** — fuera de alcance absoluto.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
