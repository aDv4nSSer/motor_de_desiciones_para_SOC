# Ponderación de detección por firma (ATT&CK-mapeada) frente a ML/TI en motores híbridos

## ¿Cómo usan Sigma/Elastic el mapeo ATT&CK para asignar severidad/confianza?

### Takeaway
Ni Sigma ni Elastic Security acoplan formalmente "técnica ATT&CK" con un nivel de confianza/severidad: el campo `level` de Sigma y el `risk_score`/`severity` de Elastic son **propiedades independientes** que el autor de la regla asigna a mano, basadas en el impacto estimado del patrón detectado, no en una fórmula que derive severidad desde la táctica/técnica ATT&CK mapeada. La correlación multi-técnica (varias tácticas ATT&CK distintas en el mismo host) sí se usa explícitamente como señal para subir prioridad de triage, pero Elastic documenta que esto genera falsos positivos y requiere revisión humana — no es un override automático de alta confianza.

### Cited Findings
- Elastic Security define `risk_score` como "a numerical value between 0 and 100 that indicates the risk of events detected by the rule", con bandas fijas: 0–21 Low, 22–47 Medium, 48–73 High, 74–100 Critical. — [Elastic common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
- Las cuatro severidades de Elastic tienen definiciones operativas explícitas: Low = "alerts that are of interest but generally are not considered to be security incidents"; Medium = "require investigation"; High = "require an immediate investigation"; Critical = "it is highly likely a security incident has occurred". — [Elastic common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
- La documentación de Elastic permite que las reglas incluyan tácticas/técnicas/subtécnicas MITRE ATT&CK relevantes, pero **no establece un acoplamiento formal** entre esa anotación ATT&CK y el valor de `risk_score`/`severity` — son propiedades configuradas independientemente por el autor de la regla. — [Elastic common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
- `risk_score` puede sobreescribirse dinámicamente con valores del evento fuente ("risk scores can be overridden using source event values"), es decir, el score final puede ajustarse en runtime, no es solo un campo estático de la regla. — [Elastic common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
- La regla prediseñada de Elastic "Multiple alerts in different ATT&CK tactics on a single host" asigna `risk_score: 73` (High) y usa un enfoque de threshold: dispara cuando hay alertas con distintas `tactic.id` ATT&CK en el mismo host dentro de 24h, bajo el argumento de que "these hosts are more likely to be compromised" — pero **no documenta la fórmula matemática** detrás del valor 73, y advierte explícitamente que "false positives can occur because the rules may be mapped to a few MITRE ATT&CK tactics" sin que eso implique compromiso real. — [Elastic detection rule doc](https://elastic.co/guide/en/security/8.x/multiple-alerts-in-different-att-ck-tactics-on-a-single-host.html)

### Inferences
- La convención real en la industria no es "ATT&CK define confianza"; es al revés: el analista/autor de la regla define confianza/severidad primero (basado en el patrón específico y su tasa de falsos positivos conocida), y la etiqueta ATT&CK es metadata descriptiva para triage/cobertura, no un input al cálculo de score.
- Esto es relevante para R-SOAR: no existe un estándar público que diga "técnica X de ATT&CK ⇒ confianza Y". El mapeo `classtype → ATT&CK` que ya tienes en `motor/classtype_attack.yaml` es válido como metadata de triage, pero no puede usarse solo, por convención de la industria, para derivar automáticamente un nivel de confianza numérico sin pasar por una decisión explícita de diseño propia (igual que hace Elastic al asignar 73 "a mano" a esa regla).
- La correlación multi-técnica SÍ es un patrón real usado para subir prioridad (no para autorizar bloqueo autónomo sin revisión) — alinea con la idea de "kill chain progression" de la siguiente pregunta.

### Gaps
- No se encontró el texto exacto del `Sigma_specification.md` de SigmaHQ (WebFetch bloqueado por política de proveniencia de URL); no pude confirmar si el campo `level` de Sigma tiene guía textual sobre su relación con "certeza de detección" vs. severidad de impacto. Basado en conocimiento general de la comunidad Sigma, `level` (informational/low/medium/high/critical) se documenta como indicador de **severidad del hallazgo si es TP**, no de la probabilidad de que sea TP — pero esto no quedó verificado con fuente primaria en esta sesión.
- No se encontró una página oficial de "Elastic risk scoring engine" (el "Risk Score" a nivel de entidad/host, distinto del `risk_score` por regla) con fórmula de agregación multi-señal citable.

---

## ¿Qué es "kill chain progression"/"multi-stage detection" y cómo se usa para subir confianza sin fuentes externas?

### Takeaway
La correlación de múltiples técnicas/tácticas ATT&CK relacionadas en una ventana de tiempo sobre la misma entidad (host/IP) es un patrón de detección documentado y ampliamente usado (Elastic, XDR vendors) para aumentar la confianza de que hay compromiso real, funcionando como una forma de "corroboración interna" que no depende de threat intel externa — pero la propia industria la trata como señal de **prioridad de triage**, no como autorización automática de respuesta de alto impacto, precisamente porque arrastra falsos positivos de sus componentes individuales.

### Cited Findings
- La regla Elastic ya citada formaliza este patrón: múltiples alertas con `tactic.id` ATT&CK distintos en el mismo host dentro de una ventana de 24h se correlacionan como señal de que "estos hosts son más probablemente comprometidos", sin requerir fuente de TI externa — es corroboración puramente interna (telemetría propia + mapeo ATT&CK). — [Elastic detection rule doc](https://elastic.co/guide/en/security/8.x/multiple-alerts-in-different-att-ck-tactics-on-a-single-host.html)
- La misma documentación reconoce el límite: "false positives can occur because the rules may be mapped to a few MITRE ATT&CK tactics" — es decir, el simple hecho de que dos reglas distintas mencionen dos tácticas distintas no garantiza una progresión real de ataque; requiere revisión analista. — [Elastic detection rule doc](https://elastic.co/guide/en/security/8.x/multiple-alerts-in-different-att-ck-tactics-on-a-single-host.html)
- Vendors de XDR (Stellar Cyber) discuten explícitamente si el "kill chain" clásico necesita actualizarse para encajar con detección y correlación moderna multi-etapa, lo que indica que la industria trata la progresión de kill chain como marco de correlación activo, en evolución, no un estándar cerrado con pesos fijos. — [Does XDR Need A New Kill Chain?](https://stellarcyber.ai/does-xdr-need-a-new-kill-chain/)
- Investigación académica sobre detección de ataques multi-etapa contextual en infraestructuras críticas (smart grids) trata explícitamente la "kill chain progression" como mecanismo para reducir falsos positivos individuales al exigir que varias etapas relacionadas ocurran en secuencia, antes de escalar la confianza de la detección global. — [Towards an Approach to Contextual Detection of Multi-Stage Cyber Attacks in Smart Grids (arXiv)](https://arxiv.org/pdf/2109.02336)

### Inferences
- El patrón "kill chain progression" es conceptualmente el más cercano a lo que el usuario propone (firma crítica + técnica ATT&CK como evidencia fuerte), pero la convención de la industria lo usa como **multiplicador de prioridad de revisión humana**, no como sustituto de corroboración externa para acción automática de alto impacto (bloqueo). La literatura no documenta ningún caso donde una sola etapa de kill chain (una sola firma, aunque crítica) se trate como equivalente a progresión multi-etapa.
- Esto sugiere una vía de diseño alternativa para R-SOAR: en lugar de "firma crítica sola = evidencia suficiente", podría formalizarse "firma crítica (classtype T3) + evidencia de otra etapa ATT&CK distinta en la misma entidad en ventana corta (ya sea de Suricata, Wazuh FIM/rootcheck, o acumulación de riesgo Redis)" como el umbral equivalente a "2 fuentes externas corroborando" — manteniendo la exigencia de corroboración pero moviendo la fuente de corroboración de "externa (TI)" a "interna (otra etapa de ataque observada)". Esto es coherente con el principio ya inamovible de R-SOAR de "acumulación de riesgo por entidad... esperar convergencia de señales" en `CLAUDE.md`.

### Gaps
- No se encontró un paper o estándar que cuantifique "cuántas etapas de kill chain equivalen a X puntos de confianza" de forma reproducible — es un área donde cada vendor implementa su propio umbral no publicado.

---

## ¿Cómo documenta MITRE (ATT&CK/CAR/D3FEND) la relación entre detección analítica y nivel de confianza?

### Takeaway
MITRE CAR (Cyber Analytics Repository) documenta analíticas por técnica ATT&CK con metadata de implementación y pseudocódigo, pero no pude confirmar en esta sesión que incluya un campo explícito de "confianza" o "tasa de falsos positivos" estandarizado por analítica; D3FEND no se pudo investigar en profundidad por límite de llamadas. Esta es una de las preguntas con mayor brecha de evidencia directa en esta investigación.

### Cited Findings
- MITRE CAR existe como repositorio público de analíticas de detección organizadas por técnica ATT&CK, con el propósito declarado de "ayudar a frustrar a los hackers analizando sus acciones" (framing de detección basada en comportamiento documentado). — [A New Resource Helps Thwart Hackers by Analyzing their Actions (MITRE)](https://kde.mitre.org/?p=3875)
- El repositorio CAR está disponible en `car.mitre.org` y en GitHub como estructura de analíticas versionadas por técnica. — [Welcome to the Cyber Analytics Repository](https://car.mitre.org/)

### Inferences
- No hay evidencia suficiente recolectada en esta sesión para afirmar que MITRE estandariza un campo de "confianza" por analítica. Dado que esto es una pregunta clave del research y quedó débilmente cubierta, se recomienda que el report writer marque esto explícitamente como punto sin resolver, en lugar de asumir que CAR/D3FEND tienen un estándar de confianza — no lo pude verificar.

### Gaps
- No se leyó el contenido real de `car.mitre.org` ni de D3FEND (solo snippets de búsqueda) — falta fetch directo de una analítica CAR concreta (ej. CAR-2013-01-002) para confirmar si incluye campos de confianza/falsos positivos documentados.
- No se investigó D3FEND en absoluto por restricción de llamadas — queda como brecha total, no se debe inferir nada sobre D3FEND.

---

## ¿Hay evidencia de que SOC trata firma determinística como evidencia "fuerte" comparable a 2 fuentes de TI coincidiendo?

### Takeaway
Sí: existe una corriente clara en la industria (y una base académica previa en fusión de evidencia de IDS) que trata la detección determinística (firma exacta contra un patrón de exploit conocido) como una **categoría de evidencia cualitativamente distinta y de mayor confianza inmediata** que la detección probabilística (ML/anomalía) — con la recomendación explícita de que las detecciones deterministas puedan disparar respuesta automática de alta confianza por sí solas, mientras que las probabilísticas requieren revisión antes de automatizarse. No se encontró, sin embargo, ningún sistema documentado públicamente que ponga un **peso numérico explícito** comparando firma vs. 2-fuentes-TI vs. ML-score en una fórmula concreta.

### Cited Findings
- Proofpoint argumenta explícitamente la superioridad de confianza inmediata de detecciones deterministas: "high accuracy for known threats" y "low false positive rate" porque hacen "exact matches with known signatures", mientras que las probabilísticas "will produce false positives" al interpretar "comportamiento inusual pero benigno" como amenaza potencial. — [Deterministic vs. Probabilistic Threat Detection (Proofpoint)](https://www.proofpoint.com/us/blog/identity-threat-defense/deterministic-vs-probabilistic-threat-detection)
- La misma fuente recomienda explícitamente el patrón de automatización diferenciada: "deterministic detections drive immediate, high-confidence automated responses since when they are tripped you can be quite certain you have a real threat actor", mientras que "probabilistic detections require human review and tuning to manage false positives before automating responses". — [Deterministic vs. Probabilistic Threat Detection (Proofpoint)](https://www.proofpoint.com/us/blog/identity-threat-defense/deterministic-vs-probabilistic-threat-detection)
- La recomendación final de esa misma fuente no es "elegir una", sino usar ambas como complementarias, ya que cubren riesgos "known and unknown" distintos — lo cual es consistente con el principio ya documentado en el `CLAUDE.md` del proyecto: "Suricata y LightGBM son detectores complementarios: AUC 0.38 entre ellos es correcto y esperado." — [Deterministic vs. Probabilistic Threat Detection (Proofpoint)](https://www.proofpoint.com/us/blog/identity-threat-defense/deterministic-vs-probabilistic-threat-detection)
- Wazuh, en su propio motor de Active Response, trata un **único** disparo de regla determinista (ej. Regla 5712, nivel 10, por intentos repetidos de fuerza bruta SSH) como suficiente por sí solo para ejecutar bloqueo automático de IP, sin exigir corroboración de una segunda fuente externa — el umbral de disparo se define por nivel de regla (`level`) o por `rule_id`/`group`, no por conteo de fuentes independientes. — [Blocking attacks with Active Response (Wazuh)](https://wazuh.com/blog/blocking-attacks-active-response/)
- Trabajo académico anterior (PNNL, "Alert Confidence Fusion in Intrusion Detection Systems with Extended Dempster-Shafer Theory") extiende explícitamente la Teoría de Dempster-Shafer para "incluir ponderaciones diferenciales de alertas provenientes de múltiples fuentes", con el objetivo declarado de producir "confidence ratings más realistas" que soporten "respuesta automatizada (y manual) a la amenaza" — es decir, la idea de ponderar deferencialmente firma vs. anomalía vs. reputación por "tipo de fuente" tiene precedente académico formal desde al menos la literatura de fusión Dempster-Shafer en IDS. — [PNNL: Alert Confidence Fusion in IDS with Extended Dempster-Shafer Theory](https://www.pnnl.gov/publications/alert-confidence-fusion-intrusion-detection-systems-extended-dempster-shafer-theory)
- Existe literatura relacionada (IEEE S&P poster) sobre "Prioritizing Intrusion Analysis Using Dempster-Shafer Theory", confirmando que el uso de teoría de evidencia para combinar fuentes heterogéneas de detección (no solo promediar scores) es un enfoque reconocido en la comunidad de investigación de IDS. — [Prioritizing Intrusion Analysis Using Dempster-Shafer Theory (IEEE S&P 2011 poster)](https://www.ieee-security.org/TC/SP2011/posters/Prioritizing_Intrusion_Analysis_Using_Dempster-Shafer_Theory.pdf)

### Inferences
- Hay soporte razonable en fuentes de industria y precedente académico (aunque antiguo — Dempster-Shafer en IDS es principalmente literatura de los 2000s-2011, no reciente) para el argumento central del usuario: una firma determinística contra un patrón de exploit conocido es, por tipo, una categoría de evidencia distinta y de mayor confianza inmediata que un score de ML o una reputación de TI agregada por terceros.
- El caso Wazuh es el ejemplo más concreto y directamente aplicable al stack de R-SOAR (ya es una dependencia core): confirma que un sistema SOAR real, ampliamente desplegado, ya trata un disparo determinista único como autosuficiente para ejecutar bloqueo, sin exigir una segunda fuente. Esto es evidencia de práctica real, no solo de opinión de blog.
- Sin embargo, ninguna fuente de industria solidifica esto en "firma crítica SOLA siempre basta, sin matices" — Proofpoint condiciona la alta confianza a que el patrón sea "known threat" con firma madura y de bajo FP histórico, no a cualquier classtype crítico sin importar el contexto. Esto conecta directamente con la siguiente pregunta (riesgo de FP en firmas "críticas").

### Gaps
- No se encontró ningún documento público con una **tabla de pesos numéricos concreta** (ej. "firma = 0.9, TI = 0.4 por fuente, ML = score crudo") en un sistema SOAR/SIEM real y nombrado. El hallazgo de Dempster-Shafer confirma el concepto cualitativo pero no entrega números reutilizables directamente; habría que acceder al paper completo (no solo abstract) para extraer fórmulas, lo cual no se logró en esta sesión (solo abstract/resumen disponible vía WebFetch).

---

## ¿Qué dice la literatura sobre falsos positivos de firmas "críticas" (escáneres benignos) y cómo se mitiga?

### Takeaway
La documentación oficial de Suricata confirma que `classtype` es una **categoría de impacto del ataque**, no una medida de certeza de que el tráfico sea realmente malicioso dirigido — la prioridad/severidad se asigna por tipo de ataque, y el propio foro de Suricata reconoce que no hay relación documentada entre `classtype` y confianza de detección. Esto valida el riesgo que el usuario señala: un classtype "crítico" (ej. `web-application-attack`) puede calzar igual con un escaneo automatizado benigno que con un exploit dirigido real, y la mitigación documentada pasa por contexto adicional (prioridad explícita override, extensión/`priority` keyword, o reglas de threshold/supresión), no por el classtype en sí.

### Cited Findings
- La documentación oficial de Suricata define `classtype` como metadata que asigna una prioridad por defecto vía `classification.config`, pero aclara que esa prioridad puede ser sobreescrita con la keyword `priority` en la firma individual — es decir, el propio framework reconoce que el classtype por sí solo no es suficiente y se espera ajuste caso por caso. — [Suricata meta keywords docs](https://docs.suricata.io/en/suricata-8.0.6/_sources/rules/meta.rst.txt)
- En el foro oficial de Suricata, el desarrollador principal (Victor Julien) confirma que la severidad de una alerta viene o bien explícitamente del keyword `priority`, o implícitamente del `classtype` vía `classification.config` — reforzando que es un sistema de **categorización de impacto**, no un indicador de certeza probabilística. — [Suricata forum: how to map and interrelate the severity level code](https://forum.suricata.io/t/how-to-map-and-interrelate-the-severity-level-code/6197)
- La misma discusión de foro referencia convenciones de categorización de ataque tipo "Probe, DoS, R2L, U2R" (heredadas de datasets clásicos de IDS como KDD) para organizar `classtype`, lo que confirma que el eje de diseño es "qué tipo/impacto de ataque es" y no "qué tan seguro estoy de que es un ataque real dirigido". — [Suricata forum: how to map and interrelate the severity level code](https://forum.suricata.io/t/how-to-map-and-interrelate-the-severity-level-code/6197)
- Existe un hilo específico de la comunidad Emerging Threats reportando un bug donde una regla (SID 2064326) tenía `severity:1` pero estaba etiquetada como "ET INFO" — evidencia concreta y documentada de que la asignación de severidad/classtype en reglas reales de producción puede estar desalineada o mal mantenida, reforzando que no debe tratarse como señal de confianza automática sin verificación. — [Bug: SID 2064326 has severity:1 but is labeled "ET INFO" (Emerging Threats community)](https://community.emergingthreats.net/t/bug-sid-2064326-has-severity-1-but-is-labeled-et-info/3171)

### Inferences
- El riesgo que plantea el usuario (escáner automatizado benigno calzando con firma "crítica") está bien fundado en cómo Suricata diseña `classtype`: el sistema nunca prometió que "crítico" = "ataque dirigido real"; prometió "crítico" = "si es verdadero, el impacto potencial es alto". Confundir ambas cosas es exactamente el error que el diseño de R-SOAR debe evitar al decidir si "firma crítica sola" basta para autorizar bloqueo.
- La mitigación de facto en la industria no es "exigir 2 fuentes de TI" per se, sino **ajuste de contexto específico de la firma/regla** (destino, frecuencia, supresión de hosts conocidos, threshold de repetición) — es decir, la respuesta correcta al riesgo de FP de firma no es necesariamente "agregar TI externa", sino "agregar contexto de la propia detección" (que de hecho R-SOAR ya contempla parcialmente vía `historical-context-svc` y acumulación de riesgo Redis).

### Gaps
- No se obtuvo una lista completa y oficial de `classtype` → prioridad default de Suricata (el fetch solo devolvió 2 ejemplos de la tabla, no la lista completa de `classification.config`) — el report writer no debe asumir valores numéricos de prioridad por classtype sin verificar directamente el archivo `classification.config` real usado en el proyecto (`.139`).
- No se encontró literatura académica reciente (2021+) específica sobre "tasa de falsos positivos de firmas IDS por classtype" con números concretos — la evidencia recolectada es cualitativa/de diseño, no estadística.

---

## ¿Existen pesos/puntajes concretos documentados públicamente (firma vs TI vs ML)?

### Takeaway
No se encontró ningún sistema documentado públicamente (open source o académico reciente) que publique una fórmula o tabla de pesos numéricos explícitos comparando "signature match" vs. "TI reputation" vs. "ML score" como categorías. Lo más cercano es la línea de investigación de fusión Dempster-Shafer para IDS (principio de ponderación diferencial por tipo de fuente), y el propio diseño implícito de Wazuh/Elastic donde severidad y risk_score se configuran manualmente por el autor de la regla, no mediante una fórmula publicada de combinación de fuentes.

### Cited Findings
- El trabajo de PNNL sobre Dempster-Shafer extendido declara explícitamente el objetivo de "incluir ponderaciones diferenciales de alertas extraídas de múltiples fuentes" para intrusion detection — confirmando que el *concepto* de pesos distintos por tipo de fuente existe en la literatura, pero el detalle numérico no es accesible desde el abstract disponible. — [PNNL: Alert Confidence Fusion in IDS with Extended Dempster-Shafer Theory](https://www.pnnl.gov/publications/alert-confidence-fusion-intrusion-detection-systems-extended-dempster-shafer-theory)
- Elastic Security no publica una fórmula de combinación multi-fuente para `risk_score`; cada regla define su propio valor estático (o lo sobreescribe con valores del evento), configurado por el autor de la regla caso por caso, no mediante un cálculo estandarizado publicado. — [Elastic common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings)
- Wazuh Active Response documenta el disparo por `level`, `rule_id` o `group`, pero no documenta ponderación entre tipos de evidencia (firma vs. correlación vs. externa) — el umbral de activación es binario por regla/nivel, no una suma ponderada de fuentes. — [Blocking attacks with Active Response (Wazuh)](https://wazuh.com/blog/blocking-attacks-active-response/)

### Inferences
- La ausencia de un estándar público de pesos numéricos significa que cualquier esquema que R-SOAR adopte (ej. "firma crítica con ATT&CK confirmado = autoriza bloqueo sin 2 fuentes de TI, pero con 1 corroboración interna de otra etapa de kill chain") sería una **decisión de diseño propia justificable por la literatura cualitativa citada arriba**, no la implementación de un estándar reconocido preexistente — lo cual es correcto documentarlo como tal en la tesis, en vez de presentarlo como si siguiera una convención de la industria ya establecida.

### Gaps
- No se accedió al texto completo de los papers Dempster-Shafer (solo abstracts/resúmenes vía WebFetch) — si se requiere una fórmula citable concreta, haría falta conseguir el PDF completo (ej. vía biblioteca institucional UBO) del paper PNNL/OSTI o del poster IEEE S&P 2011.
- No se investigaron ejemplos recientes (2021+) de "SOAR playbooks" open source (ej. Shuffle, TheHive/Cortex, n8n security templates) que pudieran tener reglas de decisión explícitas tipo "si signature_critical AND attck_mapped then skip_TI_requirement" — esto quedó fuera del alcance de los ~15 tool calls disponibles y es una brecha real que el report writer debería señalar si otro researcher no la cubrió.
