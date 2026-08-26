# Plan de Sprints — Tesis "Motor de decisión basado en riesgo para SOAR"

**Periodo:** 20 de agosto → segunda semana de octubre 2026 (≈7-8 semanas)
**Equipo:** Antonio Ayala (infraestructura, motor, redacción técnica) / Joaquín Arias (ML, métricas, documentación de modelos)
**Meta:** Tesis completa y defendible, con resultados reales extraídos de la nueva arquitectura en producción.

> **Nota de calendario (25-ago-2026):** el Sprint 0 se extendió por diagnósticos de red no
> previstos (migración NAT/VLAN, punto ciego de Suricata — ver `docs/BITACORA_TECNICA.md`
> H16-H21). Se corrió el calendario completo comprimiendo el Sprint 7 (colchón) de una
> semana a tres días, para no mover la fecha límite final de la tesis.

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
| Repetir prueba de H16 sobre la nueva topología (confirmar que Suricata genera alertas) | Antonio | Log de Suricata mostrando detección real post-migración | ❌ **Pendiente** — H21 dejó esto explícitamente abierto en su sección de Evidencia: falta repetir el payload de prueba de H16 y confirmar la alerta en `eve.json`. |
| Subir tesis de referencia (años anteriores) al chat de tesis | Antonio | Archivos cargados, estructura identificada | *(sin información desde la bitácora técnica — confirmar directamente)* |
| Armar índice completo de capítulos (formato UBO) | Antonio + Claude (chat tesis) | Índice aprobado, compartido con Joaquín | *(sin información desde la bitácora técnica — confirmar directamente)* |
| Reentrenamiento LightGBM — Camino E (4 features genuinas + GroupKFold host-disjunto) | Joaquín | Script corrido, métricas nuevas guardadas en `models/` | *(sin información desde la bitácora técnica — confirmar con Joaquín)* |
| Empezar borrador Capítulo 1 — Importancia del Problema | Antonio | Primer borrador completo (no editado aún) | *(sin información desde la bitácora técnica — confirmar directamente)* |

---

## Sprint 2 — WAF + Marco Teórico

**5 - 11 septiembre**

| Tarea | Dueño | DoD |
|---|---|---|
| Instalar ModSecurity + reglas OWASP CRS en Nginx (139) | Antonio | WAF bloqueando payload de prueba (SQLi/XSS simulado) |
| Conectar eventos de WAF como fuente de enriquecimiento al motor | Antonio | Evento de WAF visible en Redis/OpenSearch |
| Documentar métricas nuevas del reentrenamiento (precisión/recall/AUC comparado con v7.1) | Joaquín | Tabla comparativa lista para insertar en tesis |
| Redactar sección de Marco Teórico — SOAR, SOC tradicional, ML en ciberseguridad | Joaquín | Borrador de 3-5 páginas con citas APA |
| Revisar/editar Capítulo 1 (feedback de Antonio sobre el borrador) | Antonio | Capítulo 1 cerrado, listo para Miguel |
| Enviar Capítulo 1 a revisión del profesor Miguel | Antonio | Confirmación de envío |

---

## Sprint 3 — Bastion host + Metodología

**12 - 18 septiembre**

| Tarea | Dueño | DoD |
|---|---|---|
| Configurar bastion host SSH en 139 hacia los 4 servidores internos | Antonio | Acceso documentado y probado por cada dueño (equipo tesis, Eliecer, Agustín) |
| Conectar ALERT (tier=2) a `open_case()` en `vigilante/cases.py` | Antonio | Dashboard ya no muestra "0 cases" con ALERT activos |
| Implementar allowlist de crawlers (DNS reversa+directa) | Antonio | Bing/Googlebot ya no bloqueados, confirmado en logs |
| Redactar Metodología — arquitectura, pipeline, decisión de tiers | Antonio | Borrador completo del capítulo 3 |
| Generar gráficos de métricas (matriz de confusión, curvas ROC, comparativa v7.1 vs Camino E) | Joaquín | Gráficos en alta resolución, listos para insertar |
| Auditar Capa 3 (Wazuh HIDS más allá de FIM: rootcheck, auditd/whodata) | Antonio | Estado documentado: qué está activo, qué falta |

---

## Sprint 4 — Datos reales + primer borrador de Resultados

**19 - 25 septiembre**

| Tarea | Dueño | DoD |
|---|---|---|
| Extraer métricas operativas de la nueva arquitectura (latencia, autonomía, tasa de detección este-oeste) | Antonio | Dataset/tabla con al menos 1 semana de datos reales post-migración |
| Auditoría liviana de "viabilidad como producto": qué falta para multi-tenant, qué existe hoy | Antonio | Documento de 1-2 páginas, honesto, sin exagerar |
| Redactar Capítulo 4 — Resultados y Discusión (primera mitad, con datos de red/motor) | Antonio | Borrador con al menos 3 secciones de resultados |
| Terminar tabla de métricas ML final para el capítulo de resultados | Joaquín | Tabla + interpretación de cada métrica en 1 párrafo |
| Armar bibliografía completa en formato APA | Joaquín | Archivo de referencias, sin duplicados, formato correcto |
| Enviar avance completo (cap. 1-3) a Miguel | Antonio | Confirmación de envío + feedback recibido |

---

## Sprint 5 — Shuffle (si el tiempo alcanza) + cierre de Resultados

**26 septiembre - 2 octubre**

| Tarea | Dueño | DoD |
|---|---|---|
| Instalar Shuffle en el 139 o servidor dedicado | Antonio | Shuffle accesible vía dashboard propio |
| Armar 1-2 workflows de respuesta automatizada de ejemplo (ej. bloqueo + notificación + ticket) | Antonio | Workflow ejecutándose ante un evento real o simulado |
| Si no alcanza el tiempo: documentar Shuffle como "trabajo futuro" en vez de forzarlo | Antonio | Decisión tomada antes del viernes de este sprint, no a último minuto |
| Cerrar Capítulo 4 completo | Antonio | Capítulo de Resultados y Discusión terminado |
| Revisar consistencia de métricas citadas en todo el documento (no conflatar LightGBM/Isolation Forest/82.1%) | Joaquín | Checklist de coherencia de números pasado |
| Preparar narrativa de viabilidad de negocio (TCO, roles, diferenciador) para Miguel | Antonio | Slide o documento de 1 página con los argumentos clave |

---

## Sprint 6 — Conclusiones + formato final

**3 - 9 octubre**

| Tarea | Dueño | DoD |
|---|---|---|
| Redactar Capítulo 5 — Conclusiones (confirmar/rechazar hipótesis) | Antonio | Capítulo completo |
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
4. Corte duro de fecha para Shuffle: si al **2 de octubre** (fin del Sprint 5 ya recalendarizado) no está funcionando, se documenta como trabajo futuro y no se sigue insistiendo. Mejor una tesis completa sin Shuffle que una tesis incompleta por perseguirlo.
5. La reunión semanal no es opcional. Aunque sea de 15 minutos, es lo que evita que se acumulen malentendidos hasta la semana 6.
