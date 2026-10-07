# Especificación técnica: ampliación de la respuesta SOAR de R-SOAR

**Fecha:** 1 septiembre 2026
**Estado:** cerrado para pasar a implementación. Fuente de verdad de las decisiones de arquitectura tomadas para ampliar R1 (enriquecimiento), R2 (repertorio de respuesta) y la intervención humana, más control de acceso y dashboards por rol.
**Relación con este repo:** complementa `docs/BITACORA_TECNICA.md` (hallazgos H1-H21+) y `docs/PLAN_SPRINTS.md`. Ver también el resumen en `CLAUDE.md`, sección "Ampliación de respuesta SOAR".

---

## 1. Alcance del perímetro protegido

R-SOAR protege activamente: `.138` (web genérica, VLAN 30), `.139` (Suricata inline + NAT gateway), `.140` (motor de decisiones, VLAN 10), `.141` (servidor de Eliecer Peña, IA, VLAN 20, en migración).

`.142` (servidor de Agustín Díaz, emprendedores) queda explícitamente fuera del perímetro interno de R-SOAR en esta fase, manteniendo su IP pública actual sin cambios. Se declara como limitación de alcance deliberada.

Switch SG350 (`switch56ed45`, gestión `10.10.10.254`, VLAN 10): se creará una VLAN de cuarentena dedicada (sin ruteo hacia el resto de la red) para ejecutar la acción de aislamiento de host. Falta: número de VLAN a asignar y configuración del switch.

Puertos del SG350: gi1→`.138` (VLAN 30 access), gi2→`.140` (VLAN 10 access), gi3→`.141` (VLAN 20 access, cableado), gi4→`.142` (VLAN 20 access, sin cablear), gi6→`.139` (trunk 10/20/30).

**Nota de seguridad para pruebas:** VLAN 20 NO es un entorno vacío, tiene servidores de terceros (Eliecer y Agustín). No probar acciones de cuarentena ahí sin coordinar. Eliecer confirmó que no hay problema; Agustín queda fuera del perímetro por ahora.

---

## 2. Enriquecimiento (R1) — alcance final

**Se implementa en este ciclo:** AbuseIPDB (activo), OTX/AlienVault (se cierra ahora), CrowdSec como corroboración comunitaria adicional, y contexto desde detecciones nativas de Wazuh (FIM, escalamiento de privilegios, rootcheck) sin entrenar nada nuevo.

**Queda como trabajo futuro (decidido con Antonio; consultar con Joaquín, dominio ML):** Isolation Forest (u otro modelo no supervisado) sobre telemetría de host para comportamiento anómalo (exfiltración, ediciones de archivo ilógicas, privilegios extraños). Espacio de features distinto al Isolation Forest de red ya validado (Golden 4 / v2_retrain); no se modifica ese modelo. Motivo: no existe dataset de comportamientos anómalos de host realista para validar empíricamente, mismo tipo de problema que domain shift/fuga de datos ya resuelto en H1/H2. Documentar en Trabajo futuro (Cap. V tesis) con preguntas de investigación explícitas: qué eventos de Wazuh se convierten en features, cómo se validaría sin dataset realista, modelo separado o unificado.

---

## 3. Defensa en profundidad: dónde actúa cada capa

1. **CrowdSec** (bouncer en `.139`): descarta tráfico de mala reputación comunitaria antes de Suricata.
2. **Suricata inline, modo drop**: solo firmas de altísima confianza y bajísima tasa de falso positivo (exploits de CVE confirmados, patrones de malware/C2 bien establecidos). Bloqueo a nivel de paquete, sin pasar por el motor.
3. **Suricata inline, modo alert**: todo lo demás (firmas heurísticas, escaneos genéricos, anomalías de protocolo) pasa al flujo completo: motor (LightGBM + Isolation Forest de red) + enriquecimiento (sección 2) → tier → `accion_recomendada` (sección 4).

Pendiente: clasificar firmas activas de `threshold.conf` según este criterio.

---

## 4. Repertorio de respuesta y `accion_recomendada`

La acción no depende solo del tier: depende de tier + origen del hallazgo (red vs. host) + nivel de corroboración entre fuentes de enriquecimiento. La reversibilidad determina si se ejecuta automática o requiere aprobación humana, y de qué nivel de operador.

| Tier | Origen | Ejemplo | Acción recomendada | Ejecución |
|---|---|---|---|---|
| T0-T1 | Red/Host | Tráfico normal, hallazgo menor sin corroboración | Ninguna / log | Automática |
| T2 | Red | IP con reputación media en 1 sola fuente, sin confirmar | Alertar + enriquecer; crea caso automático para revisión, NO bloquea | Automática (solo notifica/crea caso) |
| T2 | Host | Evento FIM en archivo no crítico, login fuera de horario | Alertar + crear caso para revisión | Automática (notifica, no bloquea) |
| T3 | Red | IP confirmada maliciosa en 2+ fuentes, firma clara | Bloqueo de IP (Wazuh Active Response, ya validado) | Automática (bajo impacto, reversible) |
| T3 | Red | Ataque volumétrico sostenido (posible DDoS) | Rate-limiting + notificación inmediata al NOC | Automática (impacto medio, reversible) |
| T3 | Red | Score alto pero 1 sola fuente débil (caso real: crawler Bing/msnbot, ver H-hallazgos) | Alertar, NO bloquear automáticamente | Requiere confirmación de Operador N1 o superior |
| T3 | Host | FIM crítico (binarios de sistema, config crítica) o indicio de malware | Cuarentena de host vía SG350 | Requiere aprobación de Operador N2 o CISO |
| T3 | Host | Escalamiento de privilegios no autorizado confirmado | Cuarentena + caso prioritario | Requiere aprobación de Operador N2 o CISO |

La fila del crawler de Bing convierte ese hallazgo documentado en regla de diseño explícita: útil para Cap. IV/V de la tesis (hallazgo propio → decisión arquitectónica).

---

## 5. Control de acceso, roles y estructura de la aplicación

Principio: mínimo privilegio desde el diseño. Refuerza el marco teórico de SGSI/ISO 27001 ya presente en la tesis.

Roles (inspirado en tiering L1/L2/L3 de analistas SOC):

| Rol | Puede | No puede |
|---|---|---|
| Operador N1 | Monitorear alertas, ver decisiones, ver casos, aprobar acciones de bajo/medio impacto | Aprobar cuarentena / acciones que afecten disponibilidad |
| Operador N2 | Todo N1 + aprobar acciones de alto impacto (cuarentena, escalamiento) | Reportes de cumplimiento / métricas gerenciales (salvo permiso extra) |
| CISO / Gerencia | Todo lo anterior + reportes ANCI + métricas de valor + historial/auditoría completo | — |

Estructura de aplicación (no landing page, navegación por secciones):
- Vista Operador: Inicio, Monitoreo (alertas/decisiones en tiempo real), Monitoreo de servidores (infra), Casos (vía Iris), Acciones pendientes de aprobación.
- Vista CISO: Inicio (resumen de riesgo), Cumplimiento (Ley 21.663, generador de reporte ANCI), Métricas de valor (sección 7), Historial/Auditoría completo.

Implementación: JWT sobre FastAPI, contraseñas hasheadas, tabla de usuarios con rol, protección de rutas por dependencia. Cada acceso (éxito/fallo) y cada acción restringida por rol se registra en el mismo hash-chain de `soc-decisions` / auditoría: el control de acceso es también evidencia auditable.

Los dos dashboards leen la misma capa de datos (decisiones, casos en Iris, hash-chain); solo cambian vista y permisos. Grafana se mantiene aparte como consola NOC/SOC existente, alimentando al dashboard gerencial como evidencia de soporte (monitoreo continuo, Art. 8 Ley 21.663).

---

## 6. Iris Web — dependencia core

Iris Web debe estar listo e integrado desde el inicio (semana 1-2), sin módulo de casos propio como respaldo. Cada caso en Iris referencia el registro ya hasheado en `soc-decisions`, no lo duplica.

---

## 7. Métricas de valor para el CISO — alcance escalonado

**Fase 1 (medible ahora):** fatiga de alertas (% resuelto automático sin revisión, ya medido ~68% pre-migración a confirmar); tiempos de respuesta MTTD/MTTR (latencia ya medida + tiempo de aprobación humana cuando aplica). Pendiente: buscar fuente académica/industria que respalde que los SOC tradicionales tardan semanas/meses en detectar brechas, antes de citarlo.

**Fase 2 (mecanismo implementado ahora, resultado longitudinal es trabajo futuro):** disponibilidad operativa (línea base desde el despliegue vía Prometheus/Zabbix; comparación año a año es lo que el sistema *habilita* a futuro, no un resultado ya demostrado). Extender el mismo principio a Confidencialidad e Integridad, cerrando el círculo con la triada CID.

**Fase 3 (trabajo futuro, no se mide en este ciclo):** reducción de costos operacionales (comparación de largo plazo, un año de operación real, metodología TCO propuesta pero sin cifra reclamada en esta tesis).

---

## 8. Trabajo futuro (declarar explícitamente en la tesis)

- Isolation Forest de comportamiento de host (sección 2).
- MISP como capa de agregación de inteligencia de amenazas (ya excluido de este ciclo, ver `CLAUDE.md` prohibiciones).
- Shuffle SOAR: excluido por duplicar R1/R2 del motor propio (escucha Redis Stream, consulta TI, pide inferencia, ejecuta bloqueo — es exactamente lo que ya hace el motor).
- Segregación de funciones más estricta (rol aprobador dedicado, separado de Operador N2).
- Comparación de disponibilidad y costos año a año, una vez exista un año de operación real.

---

## 9. Pendientes de implementación

1. ~~Cerrar integración OTX/AlienVault.~~ **Hecho (2026-09-03)** — `_otx_lookup()` en `motor/response/enrichment.py`, ver [H23](BITACORA_TECNICA.md#h23). La API key real ya está cargada en el `.env` de `.140`, pendiente solo el deploy del código.
2. Instalar CrowdSec (agente + bouncer) en `.139`.
3. Consulta del motor a eventos recientes de Wazuh (FIM, privilegios, rootcheck) por host.
4. Clasificar firmas de `threshold.conf` (drop vs. alert).
5. Crear VLAN de cuarentena dedicada en el SG350.
6. Script de automatización (Netmiko, SSH desde `.139` respetando el bastion) para mover un puerto a la VLAN de cuarentena.
7. Implementar `accion_recomendada` en la salida del motor, con nivel de operador requerido.
8. Autenticación JWT + tabla de usuarios con rol + protección de rutas.
9. Panel de aprobación en el dashboard Operativo.
10. Dashboard Gerencial/CISO: cumplimiento, métricas de valor, historial/auditoría. **Implementado en `develop` (2026-10-03/04), despliegue pendiente de coordinar** — ver [H43](BITACORA_TECNICA.md#h43). Pendiente: exportar el reporte ANCI a PDF y medir el tiempo de respuesta humana.
11. Confirmar puertos SSH internos de `.141` una vez migrado.
12. Citar fuente para tiempos típicos de detección de brechas en SOC tradicionales.
13. Redactar sección de Trabajo futuro con las preguntas de investigación del Isolation Forest de host.
14. **CONDICIÓN FORMAL (agregada 2026-10-07, H52): `corroboration_band == "high"` NO puede usarse como gate real de autobloqueo en R2** mientras AbuseIPDB siga sin cuota y no haya un segundo proveedor de TI realmente redundante. El score de corroboración ponderado (`motor/scoring/corroboration.py`) corre solo en modo sombra; el gate vigente sigue siendo `corroboration_count >= 2` (fila T3 "IP confirmada maliciosa en 2+ fuentes" de la sección 4).
    - **Por qué:** con los grupos de firma y de contexto todavía sin instrumentar (sin classtype en el Fast Path, H50; sin acumulador por entidad), el score se renormaliza sobre los grupos disponibles. Si además falta TI, queda solo el ML: un T3 típico (`risk_score` ≈ 0,83) da 82,8 → `high` sin ninguna corroboración externa. Pasó en producción con `200.54.12.139`, el propio bastion, al que hoy protege solo la safelist de `respond_block`. En la primera ventana de sombra, el 89% de los T3 salió `high` y ninguno tenía 2+ fuentes. Usar `band == "high"` como gate equivaldría a autobloquear casi todo T3 decidiendo con ML solo, que es justo lo que la corroboración multi-fuente de esta sección 4 existe para evitar.
    - **Condición de salida (las dos, en orden):**
      1. **TI disponible de verdad**, de una de dos formas: (a) cuota de AbuseIPDB suficiente para el volumen real, medida como `abuseipdb_available = true` en ≥ 95% de los T3 de la ventana (hoy la cuota diaria de 1.000 se agota a las ~2 h del reset de las 00:00 UTC; que la cuota se reponga todos los días no cumple la condición), o (b) OTX cubriendo solo, con `corr_otx_pulse_saturation` calibrada con datos reales y no con el valor inicial de 5, y `otx_available = true` en ≥ 95% de los T3. Con (b) no hay redundancia de proveedor: hay que decidir explícitamente si eso alcanza para bloquear.
      2. **Período de sombra repetido con esa TI disponible de punta a punta** (criterio en `docs/PENDIENTES_MODO_SOMBRA.md`). La primera ventana (2026-10-07, AbuseIPDB sin cuota, OTX caído en ~16% de los T3) no sirve para validar el gate.
    - **Para la tesis (Resultados o Discusión):** es una limitación del enfoque en este entorno (plan gratuito de TI y grupos de evidencia sin instrumentar), no un bug de `corroboration.py`. La renormalización hace lo que dice su diseño (un grupo ausente no cuenta como evidencia negativa); el efecto lateral es que, con un solo grupo disponible, el score expresa solo la confianza de ese grupo. Nota técnica completa en `docs/BITACORA_TECNICA.md`, H52.
    - **Avance (H53, 2026-10-07, también en sombra):** P3 implementado, así que `"high"` ya no sale de una sola familia de evidencia (ML solo, o ML + recidivismo, quedan como máximo en `"medium"`). Se instrumentaron `signature` (correlación del worker con `suricata-alerts-*`, ~1% de los T3) y `context` (recidivismo acotado por IP). La condición de este punto **sigue vigente**: TI disponible en ≥ 95% de los T3 sigue siendo prerrequisito, y queda abierto el tratamiento de `context`/`signature` en el chequeo de desacuerdo (P4 en `docs/PENDIENTES_MODO_SOMBRA.md`). Kill-chain progression queda como extensión futura del acumulador de recidivismo.
    - **Bloqueante adicional del período de sombra:** la API key de AbuseIPDB marcada "OBLIGATORIO rotar (estuvo expuesta)" (`motor/response/config.py`, desde 2026-07-06) no se rotó: es la misma en todos los `.env` y backups de `.140` desde el 2026-09-03 (H52). Rotarla antes de repetir el período.
