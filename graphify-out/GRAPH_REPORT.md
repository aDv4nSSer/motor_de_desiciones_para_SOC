# Graph Report - motor_de_desiciones_para_soc  (2026-09-29)

## Corpus Check
- 71 files · ~77,003 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 22 file(s) not represented in the graph (top: .service 7, .conf 5, (none) 4)

## Summary
- 727 nodes · 1292 edges · 38 communities (25 shown, 13 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 180 edges (avg confidence: 0.91)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ebe4a7e9`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- EnrichmentResult
- motor/main.py
- etiquetador_diario.py
- Bitácora Técnica — Motor de Decisiones SOC
- response/schemas.py
- watcher.py
- ResponseSettings
- pathlib
- logging
- predict.py
- TestClient
- retrain_isolation_forest.py
- shadow_detect.py
- MotorModel
- README.md
- Motor de Decisiones SOAR para SOC
- Runbook: Pipeline de Ingesta Golden Subset v4
- test_decide_executor.py
- Especificación técnica: ampliación de la respuesta SOAR de R-SOAR
- Plan de Sprints — Tesis "Motor de decisión basado en riesgo para SOAR"
- Pipeline de Ingesta y Normalización — Golden Subset
- Contrato del Modelo ML — Golden 4 v7.1
- Estándares de Seguridad
- Motor de decisión basado en riesgo para SOAR en SOC
- Backlog — infraestructura (no dashboard)
- campana_ataques_soc.sh
- update.sh

## God Nodes (most connected - your core abstractions)
1. `Bitácora Técnica — Motor de Decisiones SOC` - 46 edges
2. `EnrichmentResult` - 33 edges
3. `ResponseSettings` - 30 edges
4. `enrich()` - 18 edges
5. `process_task()` - 18 edges
6. `_otx_lookup()` - 17 edges
7. `count_corroborating_sources()` - 16 edges
8. `main()` - 15 edges
9. `Motor de Decisiones SOAR para SOC` - 14 edges
10. `respond_block()` - 13 edges

## Surprising Connections (you probably didn't know these)
- `9. Pendientes de implementación` --references--> `_otx_lookup()`  [INFERRED]
  docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md → motor/response/enrichment.py
- `FASE 1 — diseño y código` --references--> `process_event()`  [INFERRED]
  docs/BITACORA_TECNICA.md → motor/main.py
- `H30 (continuación) — mitigación estructural aplicada y validada con evidencia real` --references--> `ResponseSettings`  [INFERRED]
  docs/BITACORA_TECNICA.md → motor/response/config.py
- `H29 — `r2_min_tier=2` permitía bloqueo automático en T2, contra la sección 4 de la especificación` --references--> `respond_block()`  [INFERRED]
  docs/BITACORA_TECNICA.md → motor/response/enforcer.py
- `H24 — `response-worker.service` caído ~9 días desde H22, nunca reiniciado; gap real de R1/R2 es de ~17 días` --references--> `enqueue_response_task()`  [INFERRED]
  docs/BITACORA_TECNICA.md → motor/response/queue.py

## Import Cycles
- None detected.

## Communities (38 total, 13 thin omitted)

### Community 0 - "EnrichmentResult"
Cohesion: 0.07
Nodes (42): FASE 0 — diagnóstico en `.139` antes de instalar, FASE 1 — instalación del agente (sin bouncer de enforcement), FASE 2 (mismo día) — bouncer de solo lectura, adapter creado y probado de forma aislada, FASE 3 (mismo día) — CrowdSec integrado como señal REGISTRADA, deliberadamente NO gatillante, H23 — OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1), H28 — Continuación de H23: la corroboración multi-fuente de R1 no influía en la decisión; R1 en producción enriquece IPs privadas post-migración VLAN, H37 — Integración de CrowdSec como fuente de corroboración (Fase 1: agente instalado y validado; Fases 2-4 pendientes), _abuseipdb_lookup() (+34 more)

### Community 1 - "motor/main.py"
Cohesion: 0.05
Nodes (61): asyncio, base64, concurrent_futures, Ajuste — 8 → 10 workers, FASE 0 — datos antes de diseñar, FASE 1 — diseño y código, FASE 2 — validación de correctitud (encontró un bug real, no solo confirmó que todo andaba bien), FASE 3 — despliegue (con un segundo bug encontrado y corregido antes de dejarlo andando) (+53 more)

### Community 2 - "etiquetador_diario.py"
Cohesion: 0.06
Nodes (50): csv, glob, json, compute_hash(), ensure_consumer_group(), get_redis(), index_decision(), load_state() (+42 more)

### Community 3 - "Bitácora Técnica — Motor de Decisiones SOC"
Cohesion: 0.05
Nodes (51): Bitácora Técnica — Motor de Decisiones SOC, H10 — Feature contract rechaza sesiones largas: limitación del Golden 4, H11 — API de Wazuh: payload incompatible en Active Response on-demand, H12 — FIM ampliado a WordPress + bugs de sintaxis restrict y limitación de tiempo real, H13 — Segunda forma de respuesta activa: cuarentena de archivo para compromiso interno, H14 — Timeout de systemd insuficiente en wazuh-manager.service, H15 — Caída de Redis expone falta de supervisión de proceso en response.worker, H16 — Punto ciego estructural: Suricata no ve tráfico directo al uplink ISP de .138 (+43 more)

### Community 4 - "response/schemas.py"
Cohesion: 0.08
Nodes (36): H29 — `r2_min_tier=2` permitía bloqueo automático en T2, contra la sección 4 de la especificación, Enum, ActionType, BlockResult, CrowdSecDecision, Any, BaseModel, response/schemas.py — Contratos de datos de la capa de respuesta SOAR. Define… (+28 more)

### Community 5 - "watcher.py"
Cohesion: 0.07
Nodes (38): datetime, H33 — `vigilante/cases.py` (heartbeat + casos del FIM en `.139`) nunca pudo alcanzar Redis en `.140`, con o sin la rotación de hoy, Sprint 3 — Bastion host + roles/JWT + Metodología, 1. Unit file (`motor-watcher.service`), 2. Código (`watcher.py`), Contexto, Diseño, Plan de implementación futura (post-defensa) (+30 more)

### Community 6 - "ResponseSettings"
Cohesion: 0.08
Nodes (28): BaseSettings, ipaddress, ResponseSettings, _block_key(), build_enforcer(), DryRunEnforcer, Enforcer, is_blocked() (+20 more)

### Community 7 - "pathlib"
Cohesion: 0.06
Nodes (30): ast, DataFrame, importlib, io, _code_only(), response/tests/test_crowdsec_adapter_readonly.py — H37: evidencia automatizada…, Descarta comentarios y strings (docstrings incluidos) del código fuente -- el…, Confirma que el módulo no expone ninguna función con nombre sugestivo de… (+22 more)

### Community 8 - "logging"
Cohesion: 0.08
Nodes (27): BaseEstimator, ClassifierMixin, contextlib, fastapi_middleware_cors, httpx, do_add(), do_delete(), is_allowed() (+19 more)

### Community 9 - "predict.py"
Cohesion: 0.09
Nodes (30): _features_to_array(), _load_supervised_model(), predict_anomaly(), predict_supervised(), Any, post, Carga lazy del modelo supervisado desde la ruta configurada por env., AnomalyPredictionResponse (+22 more)

### Community 10 - "TestClient"
Cohesion: 0.10
Nodes (13): fastapi_testclient, fixture, numpy, pytest_mock, TestClient, client(), mock_model(), MockerFixture (+5 more)

### Community 11 - "retrain_isolation_forest.py"
Cohesion: 0.13
Nodes (27): joblib, backup_current(), derive(), get_current_f1(), load_corpus_resp(), log(), main(), retrain_isolation_forest.py — Reentrenamiento seguro semiautomático Tesis UBO —… (+19 more)

### Community 12 - "shadow_detect.py"
Cohesion: 0.11
Nodes (27): collections, H27 — Credenciales de OpenSearch desincronizadas en 4 lugares por falta de `load_dotenv()` y nombres de variable inconsistentes, math, tldextract, _bump_occurrence(), check(), dns_findings(), domain_label_without_tld() (+19 more)

### Community 13 - "MotorModel"
Cohesion: 0.13
Nodes (12): Health Check estándar — implementar en todos los servicios, Logging estructurado con structlog, Middleware de tracing — trace_id en toda respuesta, Métricas Prometheus (GET /metrics), Observabilidad — Logging Estructurado, Tracing y Health, Performance budgets, Propagación del trace_id en el pipeline, H31 — `motor/model.py` real en producción usa una lógica de features distinta a la documentada en `model-contract.md` y no versionada en el repo (+4 more)

### Community 14 - "README.md"
Cohesion: 0.15
Nodes (6): Cobertura mínima aceptable, Estructura de tests por servicio, Estándares de Testing, Patrones obligatorios, Backlog — mejoras futuras del dashboard, Latencia mediana real (p50) en el tile de latencia

### Community 15 - "Motor de Decisiones SOAR para SOC"
Cohesion: 0.14
Nodes (14): Ampliación de respuesta SOAR (set 2026), Arquitectura: decisiones inamovibles, Contexto reciente (actualizado 1 sep 2026), Estándares de Calidad Empresarial, Git Flow, graphify, Infraestructura, Motor de Decisiones SOAR para SOC (+6 more)

### Community 16 - "Runbook: Pipeline de Ingesta Golden Subset v4"
Cohesion: 0.14
Nodes (13): Archivos importantes, Deploy en ProLiant Gen 10, El archivo JSONL no se crea, Iniciar el pipeline, Modo desarrollo (stdin, para testing), Modo producción (lee eve.json de Suricata en tiempo real), Permisos de Suricata, Requisitos previos (+5 more)

### Community 17 - "test_decide_executor.py"
Cohesion: 0.21
Nodes (7): _client(), Continuación de H30: motor/main.py::decide() corre process_event() vía…, Confirma que process_event ya no se llama directo en el event loop — debe pasar…, TestDecideBatch, TestDecideMalformedInput, TestDecideSingleEvent, TestDecideUsesExecutor

### Community 18 - "Especificación técnica: ampliación de la respuesta SOAR de R-SOAR"
Cohesion: 0.20
Nodes (10): 1. Alcance del perímetro protegido, 2. Enriquecimiento (R1) — alcance final, 3. Defensa en profundidad: dónde actúa cada capa, 4. Repertorio de respuesta y `accion_recomendada`, 5. Control de acceso, roles y estructura de la aplicación, 6. Iris Web — dependencia core, 7. Métricas de valor para el CISO — alcance escalonado, 8. Trabajo futuro (declarar explícitamente en la tesis) (+2 more)

### Community 19 - "Plan de Sprints — Tesis "Motor de decisión basado en riesgo para SOAR""
Cohesion: 0.20
Nodes (10): Cómo usar este plan, Plan de Sprints — Tesis "Motor de decisión basado en riesgo para SOAR", Reglas simples para que esto funcione, Sprint 0 — Cierre de infraestructura base, Sprint 1 — Suricata in-line + arranque de tesis, Sprint 2 — WAF + R1 ampliado + Marco Teórico, Sprint 4 — Datos reales + `accion_recomendada` + primer borrador de Resultados, Sprint 5 — Dashboards + cierre de Resultados (+2 more)

### Community 20 - "Pipeline de Ingesta y Normalización — Golden Subset"
Cohesion: 0.22
Nodes (8): Arquitectura, Decisiones técnicas, Estructura, Golden Subset: 11 features, Pendientes de verificación, Pipeline de Ingesta y Normalización — Golden Subset, Uso (desarrollo local), Validación

### Community 21 - "Contrato del Modelo ML — Golden 4 v7.1"
Cohesion: 0.25
Nodes (8): Contrato del Modelo ML — Golden 4 v7.1, Features activos (4 únicos — Golden 4), Features rechazados — nunca agregar, Modelo activo, Métricas del modelo (producción validada), Thresholds operacionales — NO usar 0.5 global, Tracking obligatorio en soc-decisions, Versiones históricas — NUNCA usar en producción

### Community 22 - "Estándares de Seguridad"
Cohesion: 0.25
Nodes (7): Análisis estático (bandit), Autenticación inter-servicio, Dependencias externas (APIs de Threat Intelligence), Estándares de Seguridad, Gestión de secrets y configuración, Logging seguro — qué NO registrar, Validación de inputs — toda entrada externa es untrusted

### Community 23 - "Motor de decisión basado en riesgo para SOAR en SOC"
Cohesion: 0.25
Nodes (8): Ampliación en curso — R-SOAR como apoyo de cumplimiento (set 2026), Calidad y seguridad, Componentes del repo, Documentación, Equipo, Motor de decisión basado en riesgo para SOAR en SOC, Qué hace, Stack

### Community 24 - "Backlog — infraestructura (no dashboard)"
Cohesion: 0.40
Nodes (4): Backlog — infraestructura (no dashboard), `eve.json` de Suricata (.139) sin rotar — 14.6 GB y creciendo, Falta puerto espejo (SPAN/mirror) hacia `eno2` de `.139` — punto ciego de Suricata, `soc-events-*` documentado en `CLAUDE.md` pero nunca implementado

## Knowledge Gaps
- **116 isolated node(s):** `update.sh script`, `Modelo activo`, `Features activos (4 únicos — Golden 4)`, `Métricas del modelo (producción validada)`, `Thresholds operacionales — NO usar 0.5 global` (+111 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 301 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Bitácora Técnica — Motor de Decisiones SOC` connect `Bitácora Técnica — Motor de Decisiones SOC` to `EnrichmentResult`, `motor/main.py`, `response/schemas.py`, `watcher.py`, `shadow_detect.py`, `MotorModel`, `README.md`?**
  _High betweenness centrality (0.217) - this node is a cross-community bridge._
- **Why does `ResponseSettings` connect `ResponseSettings` to `EnrichmentResult`, `motor/main.py`, `Bitácora Técnica — Motor de Decisiones SOC`, `response/schemas.py`, `logging`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `H28 — Continuación de H23: la corroboración multi-fuente de R1 no influía en la decisión; R1 en producción enriquece IPs privadas post-migración VLAN` connect `EnrichmentResult` to `Bitácora Técnica — Motor de Decisiones SOC`, `response/schemas.py`, `MotorModel`, `ResponseSettings`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `EnrichmentResult` (e.g. with `FASE 3 (mismo día) — CrowdSec integrado como señal REGISTRADA, deliberadamente NO gatillante` and `H23 — OTX/AlienVault como segunda fuente de R1 (ampliación SOAR, punto 1)`) actually correct?**
  _`EnrichmentResult` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `ResponseSettings` (e.g. with `H30 (continuación) — mitigación estructural aplicada y validada con evidencia real` and `ResponseMode`) actually correct?**
  _`ResponseSettings` has 24 INFERRED edges - model-reasoned connections that need verification._
- **What connects `update.sh script`, `Modelo activo`, `Features activos (4 únicos — Golden 4)` to the rest of the system?**
  _116 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `EnrichmentResult` be split into smaller, more focused modules?**
  _Cohesion score 0.07067307692307692 - nodes in this community are weakly interconnected._