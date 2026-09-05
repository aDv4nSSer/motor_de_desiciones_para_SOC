# Plan de Sprints — Tesis "Motor de decisión basado en riesgo para SOAR"

**Periodo:** 20 de agosto → segunda semana de octubre 2026 (≈7-8 semanas)
**Equipo:** Antonio Ayala (infraestructura, motor, redacción técnica) / Joaquín Arias (ML, métricas, documentación de modelos)
**Meta:** Tesis completa y defendible, con resultados reales extraídos de la nueva arquitectura en producción.

> **Nota de calendario (25-ago-2026):** el Sprint 0 se extendió por diagnósticos de red no
> previstos (migración NAT/VLAN, punto ciego de Suricata — ver `docs/BITACORA_TECNICA.md`
> H16-H21). Se corrió el calendario completo comprimiendo el Sprint 7 (colchón) de una
> semana a tres días, para no mover la fecha límite final de la tesis.

> **Replanificación (02-sep-2026):** el 1-sep se cerraron con el profesor guía las
> decisiones de ampliación SOAR (`docs/ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`) — 13
> tareas nuevas (R1 ampliado, `accion_recomendada`, roles/JWT, dos dashboards, Iris Web)
> que no existían cuando se escribió este plan el 25-ago. Se redistribuyen en los Sprints 2-6
> a partir de esta fecha, sin tocar Sprint 0/1 (ya cerrados o en curso). Dos ajustes de fondo:
> - **Shuffle sale del Sprint 5.** `CLAUDE.md` (prohibición 14, agregada el 1-sep) descarta
>   implementarlo — duplicaría R1/R2 del motor propio. Ya no es "si el tiempo alcanza": se
>   documenta directo como trabajo futuro, liberando esos días para las tareas nuevas.
> - **Se asume desarrollo asistido por Claude Code** para las tareas de código/config
>   (adaptadores de enriquecimiento, JWT, lógica de `accion_recomendada`, paneles de
>   dashboard) — de ahí que quepa más por sprint que en una estimación de desarrollo solo
>   manual. Esto **no** acelera lo que depende de terceros o de hardware: acceso físico al
>   switch SG350, cableado de `.141`, revisión del profesor Miguel. Esos tiempos se mantienen
>   tal cual porque no dependen de quién escribe el código.

---

## Cómo usar este plan

- Cada sprint dura 1 semana (lunes a domingo), salvo el Sprint 0 (extendido) y el Sprint 7 (comprimido).
- Cada tarea tiene un dueño único. Nada de "los dos", eso diluye responsabilidad.
- "Definición de terminado" (DoD) por tarea: qué evidencia concreta demuestra que está lista (un commit, un archivo, una entrada de bitácora, un gráfico).
- Reunión corta semanal (15-20 min) entre ustedes dos, al cierre de cada sprint, para revisar qué se hizo, qué no, y por qué. No reemplaza la comunicación diaria, es solo el checkpoint formal.
- Si algo no se cumple, se mueve al sprint siguiente y se anota la razón. No se acumula silenciosamente.

---

## Sprint 0 — Cierre de infraestructura base

**20 - 28 agosto** *(extendido — semana original más 4 días por los diagnósticos de red)*

| Tarea | Dueño | DoD | Estado (25-ago) |
|---|---|---|---|
| Resolver acceso SSH al 140 (verificar UFW/puerto tras cambio de IP) | Antonio | ssh exitoso al 140 vía jump host desde el 139 | ✅ **Completado** — verificado en vivo: `ssh -i ~/.ssh/tesis_ubo_aiayala -p 2222 -J aiayala@200.54.12.139:2222 aiayala@10.10.10.3` funciona. El puerto interno real es **2222**, no 22 como suponía la tarea original — corregido. |
| Migrar 138 a IP privada VLAN 30 (`10.30.30.2`) | Antonio | ping y ssh funcionando desde 139 | ❌ **Pendiente** — requiere acceso físico. `.138` sigue con su IP pública vieja (`200.54.12.138`). |
| Conectar físicamente 142 al switch (puerto access VLAN 20) | Antonio | Puerto activo, IP asignada `10.20.20.2` | ❌ **Pendiente** — sin cablear al switch. |
| Actualizar `proxy_pass` de Nginx (138, 140) a IPs privadas nuevas | Antonio | curl a los 3 subdominios duckdns responde 200/302, no 502 | ⚠️ **Parcial** — `motor-soc-ubo` ya apunta a `10.10.10.3:8000` (confirmado en `.139`). `web-soc-ubo` sigue apuntando a la IP pública vieja de `.138`; no se puede actualizar hasta que `.138` tenga IP privada asignada. |
| Bitácora: entradas H21+ de la migración de 138/140/142 | Antonio (con Claude Code) | Commit en `docs/BITACORA_TECNICA.md` | ⚠️ **Parcial** — H17-H21 redactados (migración de `.139`/`.140`, fix de Suricata), cubriendo lo que ya ocurrió. `.138`/`.142` aún no migran, así que no hay nada que documentar de esos dos todavía. **Cambios en working tree, aún sin commit.** |

> **Nota:** `.141` tampoco tiene tarea propia en este sprint (omisión del plan original), pero
> comparte el mismo estado pendiente que `.138` y `.142` — ver tabla de Infraestructura en
> `CLAUDE.md`.

**No entra en este sprint:** Suricata in-line, Shuffle, nada de ML. Es puramente cerrar la red.

---

## Sprint 1 — Suricata in-line + arranque de tesis

**29 agosto - 4 septiembre**

| Tarea | Dueño | DoD | Estado (25-ago) |
|---|---|---|---|
| Suricata en modo in-line con NFQUEUE en el 139 | Antonio | Tráfico real bloqueado por firma, verificado con prueba controlada | ⚠️ **Parcial** — causa raíz del "cero alertas" encontrada y corregida (H21: orden de reglas en `/etc/ufw/before.rules`, el fast-path `RELATED,ESTABLISHED ACCEPT` estaba antes que la desviación a NFQUEUE). Falta la prueba controlada que confirme **bloqueo** real por firma — el DoD pide bloqueo, no solo visibilidad. |
| Revisar cuáles firmas de `threshold.conf` pasan a drop vs quedan en alert | Antonio | Documento/lista con la decisión de cada firma | ❌ **Pendiente** — sin decidir. |
| Repetir prueba de H16 sobre la nueva topología (confirmar que Suricata genera alertas) | Antonio | Log de Suricata mostrando detección real post-migración | ✅ **Completado** — H21 registra el retest confirmado el mismo 25-ago (SID 2100498 disparando sobre tráfico posterior al primer paquete de la conexión, tras reordenar `before.rules`), cerrando el pendiente que la propia entrada había dejado abierto. |
| Subir tesis de referencia (años anteriores) al chat de tesis | Antonio | Archivos cargados, estructura identificada | *(sin información desde la bitácora técnica — confirmar directamente)* |
| Armar índice completo de capítulos (formato UBO) | Antonio + Claude (chat tesis) | Índice aprobado, compartido con Joaquín | *(sin información desde la bitácora técnica — confirmar directamente)* |
| Reentrenamiento LightGBM — Camino E (4 features genuinas + GroupKFold host-disjunto) | Joaquín | Script corrido, métricas nuevas guardadas en `models/` | *(sin información desde la bitácora técnica — confirmar con Joaquín)* |
| Empezar borrador Capítulo 1 — Importancia del Problema | Antonio | Primer borrador completo (no editado aún) | *(sin información desde la bitácora técnica — confirmar directamente)* |

> **Incidente no planificado (02-sep):** `redis-server` en `.140` quedó inoperante por un
> `bind` a la IP pública vieja tras la migración de H17, y por dependencia eso dejó
> `motor-soc.service` (el motor real) caído desde el 26-ago — casi 6 días sin que nadie lo
> notara. Diagnosticado y resuelto el mismo día (ver `docs/BITACORA_TECNICA.md` H22), sin
> necesidad de extender el sprint. Queda pendiente un hueco real: no hay monitoreo de
> `motor-soc`/`redis-server`, así que se agrega explícitamente al Sprint 2 abajo.
>
> **Corrección (04-sep, ver H24/H25):** el diagnóstico de H22 cubría solo `motor-soc`/Redis.
> Investigación posterior encontró que `response-worker.service` (R1/R2) quedó caído por la
> misma causa pero nunca se reinició al resolver H22 (H24), y que la causa raíz real del gap
> de ingesta era un sink de Vector en `.139` apuntando a la IP pública obsoleta de `.140`
> (H25) — el hueco real sin ningún evento procesado es 2026-08-18 a 2026-09-04, ≈17 días, no
> los ≈6 días de este incidente. La tarea de monitoreo del Sprint 2 (abajo) debe cubrir
> también `response-worker` y los sinks de Vector, no solo `motor-soc`/`redis-server`.

---

## Sprint 2 — WAF + R1 ampliado + Marco Teórico

**5 - 11 septiembre**

> Se agrupan aquí todas las instalaciones nuevas sobre `.139` (WAF, CrowdSec) en la misma
> semana — más fácil de coordinar y de aislar si algo sale mal, que repartirlas en sprints
> distintos. Deja libre el resto del calendario para no tocar `.139`/`.140` durante la
> semana de recolección de métricas (Sprint 4).

| Tarea | Dueño | DoD |
|---|---|---|
| Instalar ModSecurity + reglas OWASP CRS en Nginx (139) | Antonio | WAF bloqueando payload de prueba (SQLi/XSS simulado) |
| Conectar eventos de WAF como fuente de enriquecimiento al motor | Antonio | Evento de WAF visible en Redis/OpenSearch |
| **[SOAR R1] Cerrar integración OTX/AlienVault** en `threat-intel-svc` (mismo patrón adapter/circuit-breaker que AbuseIPDB) | Antonio + Claude Code | Indicador consultado responde `NormalizedTI` con `sources: [abuseipdb, otx]`, verificado con un IOC real |
| **[SOAR R1] Instalar CrowdSec** (agente + bouncer) en `.139` | Antonio | `cscli metrics` muestra decisiones activas; una IP de mala reputación comunitaria se bloquea antes de llegar a Suricata |
| **[SOAR — infra core] Desplegar Iris Web** e integración mínima (crear caso desde `vigilante/cases.py` o directo desde el motor) | Antonio + Claude Code | Un caso de prueba visible en Iris, referenciando el `trace_id`/hash de `soc-decisions` (sin duplicar el registro) |
| **[H22/H24/H25] Monitoreo de `motor-soc.service`/`redis-server.service`/`response-worker.service`/sinks de Vector** en `.140`/`.139`, independiente de Redis (a diferencia del heartbeat actual) | Antonio + Claude Code | Alerta por correo si `motor-soc`, `redis-server`, `response-worker` caen o si un sink de Vector deja de entregar — probado apagándolos/desconectándolos a propósito |
| Documentar métricas nuevas del reentrenamiento (precisión/recall/AUC comparado con v7.1) | Joaquín | Tabla comparativa lista para insertar en tesis |
| Redactar sección de Marco Teórico — SOAR, SOC tradicional, ML en ciberseguridad | Joaquín | Borrador de 3-5 páginas con citas APA |
| Revisar/editar Capítulo 1 (feedback de Antonio sobre el borrador) | Antonio | Capítulo 1 cerrado, listo para Miguel |
| Enviar Capítulo 1 a revisión del profesor Miguel | Antonio | Confirmación de envío |

**Si no alcanza:** CrowdSec pasa primero a Sprint 3 antes que WAF, OTX o Iris — es el único
de los tres nuevo-en-este-proyecto y el que más probablemente esconda una sorpresa de
integración (mismo patrón que H9/H16-H21).

---

## Sprint 3 — Bastion host + roles/JWT + Metodología

**12 - 18 septiembre**

> La VLAN de cuarentena entra aquí, no más cerca de la defensa, porque depende de acceso
> físico al switch SG350 — el tipo de tarea que históricamente esconde sorpresas de días
> (H16-H21). Mejor absorber ese riesgo ahora, con margen, que en Sprint 5-6.

| Tarea | Dueño | DoD |
|---|---|---|
| Configurar bastion host SSH en 139 hacia los 4 servidores internos | Antonio | Acceso documentado y probado por cada dueño (equipo tesis, Eliecer, Agustín) |
| Conectar ALERT (tier=2) a `open_case()` en `vigilante/cases.py` | Antonio | Dashboard ya no muestra "0 cases" con ALERT activos |
| Implementar allowlist de crawlers (DNS reversa+directa) | Antonio | Bing/Googlebot ya no bloqueados, confirmado en logs |
| **[SOAR — roles] JWT + tabla de usuarios con rol** (Operador N1/N2, CISO) + protección de rutas por dependencia FastAPI | Antonio + Claude Code | Endpoint protegido rechaza sin token válido; login emite JWT con rol; acceso registrado en el hash-chain |
| **[SOAR R1] Consulta del motor a eventos recientes de Wazuh** (FIM, privilegios, rootcheck) por host, como fuente de contexto | Antonio + Claude Code | `ContextResponse` incluye hallazgos Wazuh de las últimas 24h para un host de prueba |
| Auditar Capa 3 (Wazuh HIDS más allá de FIM: rootcheck, auditd/whodata) | Antonio | Estado documentado: qué está activo, qué falta — insumo directo de la tarea de arriba |
| **[SOAR R2] Crear VLAN de cuarentena dedicada en el SG350** (sin ruteo hacia el resto de la red) | Antonio | VLAN creada, puerto de prueba aislado confirmado con `ping`/`arp` desde otro segmento |
| **[SOAR R2] Script de automatización (Netmiko)** para mover un puerto a la VLAN de cuarentena, ejecutado desde `.139` respetando el bastion | Antonio + Claude Code | Script mueve un puerto de prueba y lo revierte, sin acceso manual al switch |
| Redactar Metodología — arquitectura, pipeline, decisión de tiers | Antonio | Borrador completo del capítulo 3 |
| Generar gráficos de métricas (matriz de confusión, curvas ROC, comparativa v7.1 vs Camino E) | Joaquín | Gráficos en alta resolución, listos para insertar |

**Si no alcanza:** la VLAN de cuarentena y su script son lo primero que se corre a Sprint 4
— tienen la menor dependencia de lo demás y el mayor margen de tiempo restante antes de
que el R2 graduado (Sprint 4) los necesite de verdad.

---

## Sprint 4 — Datos reales + `accion_recomendada` + primer borrador de Resultados

**19 - 25 septiembre**

> **Regla dura esta semana: nada de instalaciones ni reinicios nuevos en `.139`/`.140`
> fuera de lo estrictamente necesario.** La semana de datos reales para el DoD de abajo no
> puede convivir con más riesgo de caída como el de H22 — cualquier cambio de
> infraestructura de este sprint que no sea la propia `accion_recomendada` (que es lógica
> nueva en el motor, no una reinstalación) se corre a Sprint 5.

| Tarea | Dueño | DoD |
|---|---|---|
| Extraer métricas operativas de la nueva arquitectura (latencia, autonomía, tasa de detección este-oeste) | Antonio | Dataset/tabla con al menos 1 semana de datos reales post-migración — **contar desde el 04-sep** (fix de H25), no desde el 02-sep como se asumía cuando se escribió esta fila: H24/H25 confirmaron que el Fast Path no recibió ningún evento real entre el 18-ago y el 04-sep (Vector con el sink apuntando a la IP pública obsoleta de `.140`, no solo la caída de Redis de H22) — excluir ese rango completo, no solo la ventana de 6 días que cubría H22 |
| **[SOAR R2] Implementar `accion_recomendada`** en la salida del motor (tabla tier × origen × corroboración de la sección 4 de `ESPECIFICACION_TECNICA_SOAR_AMPLIADA.md`), con nivel de operador requerido | Antonio + Claude Code | Para cada fila de esa tabla, un evento de prueba produce la acción y el nivel de aprobación esperado |
| Auditoría liviana de "viabilidad como producto": qué falta para multi-tenant, qué existe hoy | Antonio | Documento de 1-2 páginas, honesto, sin exagerar |
| Redactar Capítulo 4 — Resultados y Discusión (primera mitad, con datos de red/motor) | Antonio | Borrador con al menos 3 secciones de resultados |
| **Citar fuente académica/industria** para "SOC tradicionales tardan semanas/meses en detectar brechas" (pendiente #12 de la especificación ampliada) | Antonio | Cita APA incorporada a la sección de métricas de valor del Cap. 4 |
| Terminar tabla de métricas ML final para el capítulo de resultados | Joaquín | Tabla + interpretación de cada métrica en 1 párrafo |
| Armar bibliografía completa en formato APA | Joaquín | Archivo de referencias, sin duplicados, formato correcto |
| Enviar avance completo (cap. 1-3) a Miguel | Antonio | Confirmación de envío + feedback recibido |

---

## Sprint 5 — Dashboards + cierre de Resultados

**26 septiembre - 2 octubre**

> Shuffle sale de este sprint: `CLAUDE.md` (prohibición 14, 1-sep) ya lo descarta —
> duplicaría R1/R2 del motor propio — así que se documenta directo como trabajo futuro sin
> gastar tiempo de implementación, y ese tiempo se reasigna a los dos dashboards.

| Tarea | Dueño | DoD |
|---|---|---|
| Documentar Shuffle como trabajo futuro (ya decidido, no evaluado — ver `CLAUDE.md` prohibición 14) | Antonio | Un párrafo en la sección de trabajo futuro de la tesis, con la razón (duplicaría R1/R2) |
| **[SOAR — dashboards] Panel de aprobación en el dashboard Operativo** — acciones de alto impacto esperando aprobación de Operador N2/CISO | Antonio + Claude Code | Una acción `accion_recomendada` de alto impacto queda "pendiente" hasta que un usuario con rol válido la aprueba o rechaza, registrado en el hash-chain |
| **[SOAR — dashboards] Dashboard Gerencial/CISO** — primera versión: cumplimiento Ley 21.663 (estructura), métricas de valor (sección 7), historial/auditoría | Antonio + Claude Code | Login con rol CISO ve una vista distinta a la del Operador, con al menos cumplimiento + historial funcionando |
| Cerrar Capítulo 4 completo | Antonio | Capítulo de Resultados y Discusión terminado |
| Revisar consistencia de métricas citadas en todo el documento (no conflatar LightGBM/Isolation Forest/82.1%) | Joaquín | Checklist de coherencia de números pasado |
| Preparar narrativa de viabilidad de negocio (TCO, roles, diferenciador) para Miguel | Antonio | Slide o documento de 1 página con los argumentos clave |

**Si no alcanza:** el dashboard Gerencial/CISO es lo que se recorta primero — el panel de
aprobación es más importante para la tesis (es la evidencia concreta de "aprobación humana
graduada" de R2) y ya tiene su propio slot protegido arriba.

---

## Sprint 6 — Conclusiones + formato final

**3 - 9 octubre**

| Tarea | Dueño | DoD |
|---|---|---|
| Redactar Capítulo 5 — Conclusiones (confirmar/rechazar hipótesis) | Antonio | Capítulo completo |
| **Redactar sección de Trabajo futuro — Isolation Forest de comportamiento de host** (pendiente #13), con las preguntas de investigación explícitas (qué eventos de Wazuh se convierten en features, cómo se validaría sin dataset realista, modelo separado o unificado) | Antonio | Subsección de Cap. 5 con las 3 preguntas de investigación redactadas |
| **Confirmar puertos SSH internos de `.141`** — solo si ya se cableó al switch para entonces | Antonio | `ss -tlnp \| grep ssh` documentado en `docs/BITACORA_TECNICA.md` — **si `.141` sigue sin cablear, se marca explícitamente como no completado por bloqueo externo, no se fuerza ni bloquea nada más del sprint** |
| Aplicar formato oficial UBO completo (si ya llegó del director de programa) | Joaquín | Documento con formato aplicado de principio a fin |
| Revisión cruzada completa del documento (Antonio revisa lo de Joaquín y viceversa) | Ambos | Lista de correcciones cerrada |
| Generar versión de PDF/Word final para revisión de Miguel | Antonio | Archivo entregado |
| Enviar tesis completa a Miguel para revisión final | Antonio | Confirmación de envío |

---

## Sprint 7 — Buffer y preparación de defensa

**10 - 12 octubre** *(colchón comprimido — 3 días en vez de la semana completa del plan original)*

| Tarea | Dueño | DoD |
|---|---|---|
| Incorporar feedback final de Miguel | Ambos | Todos los comentarios resueltos o respondidos |
| Armar presentación de defensa (slides) | Antonio | Presentación completa |
| Preparar respuestas a preguntas esperadas (metodología, viabilidad, limitaciones) | Ambos | Documento de preguntas/respuestas ensayado |
| Ensayo de defensa completo | Ambos | Al menos 1 ensayo cronometrado |

Este sprint es colchón. Si algo de los sprints anteriores se atrasó, se recupera aquí antes de noviembre. Al comprimirse de una semana a tres días, hay bastante menos margen que en el plan original — cualquier atraso de los Sprints 1-6 debe recuperarse dentro de esos mismos sprints en la medida de lo posible, no asumir que "se arregla en el 7".

---

## Reglas simples para que esto funcione

1. Una tarea, un dueño. Si algo requiere a los dos, se parte en dos tareas separadas con entregables distintos.
2. Nada se marca "hecho" sin evidencia. Un commit, un archivo, un link, una captura. No vale "ya casi".
3. Si Joaquín no entiende una tarea de ML/métricas, ese es tu chat técnico normal con él. Estas tareas están elegidas porque están dentro de lo que ya maneja (calibración del modelo), así que la barrera de entrada es baja.
4. Shuffle no se implementa, punto — decisión cerrada el 1-sep (`CLAUDE.md` prohibición 14, duplicaría R1/R2 del motor propio), no un corte de fecha. Documentarlo como trabajo futuro en Sprint 5 y no volver a evaluarlo.
5. La reunión semanal no es opcional. Aunque sea de 15 minutos, es lo que evita que se acumulen malentendidos hasta la semana 6.
6. Para las tareas nuevas de SOAR ampliado (Sprints 2-5): si el diagnóstico de un problema en infraestructura real (switch, red, servicio) toma más de 1 día, se documenta en `docs/BITACORA_TECNICA.md` como hallazgo (formato H[N]) igual que H16-H22, no se oculta como "atraso" genérico — el patrón de este proyecto es que esos diagnósticos *son* resultado de tesis, no tiempo perdido.
