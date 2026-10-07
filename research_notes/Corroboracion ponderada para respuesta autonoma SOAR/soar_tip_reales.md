# Cómo plataformas SOAR/TIP reales calculan corroboración/confianza multi-fuente y deciden automatización vs. escalado humano

## ¿Cómo calcula Cortex XSOAR (Demisto) severity/confidence a partir de múltiples integraciones de threat intel, y cómo decide automatización vs. aprobación humana?

### Takeaway
XSOAR no usa un esquema "N fuentes deben coincidir": usa **DBotScore**, un objeto estandarizado por vendor/indicador en escala 0-3 (Unknown/Good/Suspicious/Bad) que se reconcilia por **reliability del source** (no por conteo de fuentes), y luego un playbook documentado de severidad combina ese veredicto con reputación externa (ej. Qualys) y listas de activos críticos — sin que la documentación pública detalle una fórmula de reconciliación cuando hay conflicto entre vendors.

### Cited Findings
- Cada DBotScore es un objeto por indicador que incluye `Vendor`, `Indicator`, `Type` y un `Score` entero 0-3 (0=Unknown, 1=Good, 2=Suspicious, 3=Bad) — [DBotScore docs](https://xsoar.pan.dev/docs/integrations/dbot)
- Documentación oficial afirma explícitamente: *"When merging indicators, the reliability of an intelligence-data source impacts the reputation of an indicator and the values assigned to indicator fields"* — es decir, la reliability (no el número de fuentes coincidentes) es la variable que XSOAR usa al fusionar indicadores — [DBotScore docs](https://xsoar.pan.dev/docs/integrations/dbot)
- El playbook público "Automate Incident Severity Assignment" de Palo Alto Networks describe un proceso de 3 pasos: (1) consultar primero una herramienta externa de vulnerability management (ej. Qualys) y adoptar su severidad si existe; (2) si no hay score externo, evaluar la "Reputation" de los indicadores asociados (IPs, URLs, hashes), definida textualmente como *"an amalgamation of scores from other threat intelligence platforms that a user integrates with"*, para asignar High/Medium/Low; (3) verificar si usuarios/hostnames asociados están en listas de activos críticos, lo que puede escalar la severidad a "Critical" — [Security Orchestration Use Case: Automate Incident Severity Assignment](https://www.paloaltonetworks.com/blog/security-operations/security-orchestration-use-case-automate-incident-severity-assignment/)
- El mismo artículo describe el resultado como totalmente automático: *"all these actions are performed automatically, freeing analyst time"* — no se documenta públicamente, en las fuentes revisadas, un umbral explícito de confianza que dispare aprobación humana vs. ejecución automática dentro de este playbook de severidad — [Security Orchestration Use Case](https://www.paloaltonetworks.com/blog/security-operations/security-orchestration-use-case-automate-incident-severity-assignment/)
- Existe un playbook de referencia público llamado "Calculate Severity - Cortex XDR Risky Assets" en el repositorio de contenido XSOAR, lo que confirma que la lógica de cálculo de severidad está modelada como playbook componible y reutilizable (no hardcodeada en el core) — [Calculate Severity - Cortex XDR Risky Assets](https://xsoar.pan.dev/docs/reference/playbooks/calculate-severity---cortex-xdr-risky-assets)
- Existe también un playbook público "Check Point - IOC Enrichment and Triage" que combina enriquecimiento de múltiples fuentes antes de triage, confirmando el patrón de "enrich-then-decide" en playbooks reales publicados — [Check Point - IOC Enrichment and Triage](https://xsoar.pan.dev/docs/reference/playbooks/check-point---ioc-enrichment-and-triage)

### Inferences
- XSOAR trata el "¿cuántas fuentes coinciden?" como una pregunta mal planteada: el diseño correcto según su propia documentación es ponderar por **reliability declarada del source** (configurable por el admin, no por conteo), de forma análoga a lo que CTIX y OpenCTI hacen explícitamente (ver más abajo). Esto es evidencia directa contra el enfoque "2 fuentes deben coincidir" del R-SOAR actual.
- La automatización vs. aprobación humana en XSOAR vive en la capa de playbook (condiciones sobre el valor de severidad resultante), no en una regla fija global — lo que sugiere que el "T3 override" del motor debería poder construirse igual: severidad agregada → condición de playbook → rama automática o rama de aprobación, en vez de depender de contar fuentes externas disponibles.

### Gaps
- No se encontró documentación pública que detalle el algoritmo exacto de reconciliación cuando dos vendors reportan DBotScores contradictorios para el mismo indicador (ej. uno dice Bad=3, otro Good=1) — solo se confirma que la reliability del source "impacta" el resultado, sin fórmula publicada.
- No se encontró un umbral numérico público (ej. "severity > X → bloqueo automático sin aprobación") en los playbooks de severidad revisados; la fuente indica que la lógica vive en el playbook pero no publica el valor de corte usado en producción por Palo Alto.
- No se pudo acceder a la documentación completa de "Indicator Verdict" (6.9/8) por restricciones de fetch (redirect bloqueado); posible fuente adicional para profundizar manualmente: `https://cortex-docs.paloaltonetworks.com/r/Cortex-XSOAR/6.9/Cortex-XSOAR-Administrator-Guide/Indicator-Verdict`.

---

## ¿Cómo lo hace Splunk SOAR (Phantom)? ¿Severity scoring multi-fuente documentado públicamente?

### Takeaway
No se encontró documentación pública específica de Splunk SOAR (Phantom) sobre un algoritmo de "severity scoring" multi-fuente; la búsqueda dirigió consistentemente hacia Splunk Enterprise Security / Mission Control (un producto relacionado pero distinto), lo cual en sí mismo es una señal de que este mecanismo no está documentado abiertamente del mismo modo que DBotScore en XSOAR.

### Cited Findings
- La documentación disponible públicamente sobre observables y threat intelligence en el ecosistema Splunk corresponde a **Splunk Enterprise Security / Mission Control** ("Investigate observables in Splunk Mission Control", "Threat Intel Management"), no a Splunk SOAR (Phantom) propiamente — [Investigate observables in Splunk Mission Control](https://docs.splunk.com/Documentation/MC/latest/Detect/Intelligence); [Splunk Enterprise Security Threat Intel Management](https://docs.splunk.com/Documentation/ES/8.0.0/User/ThreatIntelManagement)

### Inferences
- A diferencia de XSOAR (que publica DBotScore como concepto central y documentado) y TheHive/Cortex (que publica su taxonomy), Splunk SOAR parece exponer la lógica de scoring multi-fuente principalmente dentro de playbooks Python personalizados por el cliente, no como un framework nombrado y documentado públicamente — esto limita lo que se puede citar con evidencia concreta.

### Gaps
- No se encontró documentación pública (manual técnico, whitepaper o blog oficial) que describa un mecanismo nombrado de "severity scoring" multi-fuente específico de Splunk SOAR/Phantom, distinto del motor de correlación general de Splunk ES. Se recomienda, si esto es crítico para el documento de tesis, buscar directamente en el repositorio de "Community Playbooks" de Splunk SOAR en GitHub (`github.com/splunk-soar-connectors`) o en session recordings de `.conf` (Splunk's annual conference), que no se alcanzaron a revisar dentro del presupuesto de esta investigación.

---

## TheHive/Cortex: agregación de "analyzers" en "taxonomy level" (info/safe/suspicious/malicious) y uso para decidir respuesta

### Takeaway
Cortex formaliza el resultado de cada analyzer como un **taxonomy** con 4 niveles de severidad estándar — **info, safe, suspicious, malicious** — y cada analyzer puede emitir uno o más "taxonomy entries" (namespace:predicate=value) por ejecución; TheHive consume esos resultados por observable, pero la evidencia pública recolectada no detalla una fórmula explícita de "si 2 analyzers dicen malicious entonces X" — el patrón documentado es más bien "el analista/caso ve todas las taxonomies lado a lado" y algunas integraciones permiten disparar acciones automáticas directamente sobre un veredicto "malicious" individual (no sobre un consenso numérico).

### Cited Findings
- Los cuatro niveles de taxonomy de Cortex Analyzer se confirman explícitamente como: **Malicious** ("flags an immediate threat"), **Suspicious** ("tells you to keep a close eye on the activity"), **Benign/Safe** ("confirms the data is safe"), y un cuarto nivel "info" (mencionado como parte del esquema estándar aunque no detallado en profundidad en esta fuente) — [12 Questions and Answers About Cortex Analyzer](https://www.securityscientist.net/blog/12-questions-and-answers-about-cortex-analyzer/)
- La misma fuente indica que los veredictos de Cortex pueden disparar **acciones de bloqueo de bajo riesgo inmediatamente** sin esperar verificación manual: *"Your system can react immediately rather than waiting for you to manually verify... trigger low-risk blocking actions immediately"* — evidencia de que, en al menos un patrón documentado, un solo veredicto "malicious" de un analyzer puede bastar para una acción de bajo impacto, sin necesidad de corroboración de una segunda fuente — [12 Questions and Answers About Cortex Analyzer](https://www.securityscientist.net/blog/12-questions-and-answers-about-cortex-analyzer/)
- El ecosistema de analyzers de Cortex está publicado como repositorio abierto con decenas de integraciones (blog histórico de TheHive Project documenta lanzamientos recurrentes de "Fresh CortexUtils, New Cortex Analyzers"), confirmando que cada analyzer es efectivamente equivalente a una fuente de threat intel independiente, tal como se plantea en la pregunta de investigación — [All Fresh CortexUtils, New Cortex Analyzers (blog TheHive Project)](https://blog.thehive-project.org/tag/cert-at)

### Inferences
- El patrón de Cortex/TheHive es relevante como contraejemplo directo al diseño actual del R-SOAR: en vez de exigir "2 fuentes externas coincidan", Cortex permite que **un solo analyzer con taxonomy=malicious** autorice una acción de bajo impacto automáticamente, delegando la exigencia de corroboración solo a acciones de alto impacto — esto valida mover de un umbral de conteo fijo a un esquema donde el **peso/confiabilidad de la fuente individual** (no la cantidad de fuentes) determina si basta sola para actuar.

### Gaps
- No se pudo acceder a la documentación técnica actual de StrangeBee (mantenedor actual de TheHive/Cortex tras la reestructuración del proyecto) sobre el mecanismo exacto de agregación de múltiples taxonomies en un mismo caso/observable (ej. si existe un "short summary" que resuma el peor nivel, o un conteo) — los intentos de búsqueda (`docs.strangebee.com`) no devolvieron resultados indexados accesibles en esta sesión. Se recomienda acceso directo a `docs.strangebee.com` o al código fuente de `TheHive-Project/cortexutils` (`analyzer.py`, clase `Taxonomy`) para confirmar la estructura exacta `namespace:predicate=value` y si existe lógica de agregación server-side más allá de mostrar todas las taxonomies.
- No se encontró evidencia pública sobre cómo (o si) TheHive calcula automáticamente la severidad de un **caso** a partir del conjunto de taxonomies de todos sus observables — la fuente consultada se centra en el analyzer individual, no en la agregación a nivel de caso.

---

## Shuffle (SOAR open source): lógica condicional para decidir ejecución automática, y playbooks publicados que combinen múltiples fuentes antes de bloquear

### Takeaway
No se encontró evidencia concreta y citable — ni en documentación oficial ni en playbooks publicados — sobre cómo Shuffle implementa lógica condicional multi-fuente antes de una acción de bloqueo; las búsquedas no devolvieron páginas de Shuffle con detalle técnico suficiente dentro del presupuesto de esta investigación.

### Cited Findings
(Ninguno con fuente verificada y específica a Shuffle encontrado en esta sesión de investigación.)

### Inferences
(No aplica — sin hallazgos suficientes para inferir con confianza.)

### Gaps
- Esta es la pregunta clave con **menor cobertura** de todo el research. Se requiere investigación adicional dirigida directamente a: (1) `github.com/Shuffle/Shuffle` — específicamente la carpeta de ejemplos/plantillas de workflows (`.json` de workflow con múltiples nodos de enriquecimiento convergiendo en un nodo condicional antes de una acción de firewall/blocklist); (2) la documentación oficial en `shuffler.io/docs` sobre el nodo "Condition"/"If" y cómo combina múltiples outputs de apps distintas (ej. VirusTotal + AbuseIPDB) en una sola expresión booleana; (3) posibles blog posts o videos de demos de Shuffle (su canal es muy activo en mostrar casos de uso concretos de SOC) que muestren un playbook real de "bloqueo de IP condicionado a 2+ fuentes". No se debe asumir ningún mecanismo específico de Shuffle sin esta verificación adicional.

---

## OpenCTI: cálculo de "confidence level" (0-100) para un Indicator/Observable y combinación cuando múltiples fuentes/conectores reportan sobre el mismo IOC

### Takeaway
OpenCTI separa explícitamente dos ejes — **Reliability** (confianza en la fuente/autor/conector, basada en capacidad técnica e historial) y **Confidence** (credibilidad de la información en sí, 0-100) — y cuando hay valores de confianza en conflicto al fusionar/actualizar un mismo indicador, aplica una **regla conservadora explícita de tomar siempre el valor más bajo**, no un promedio ni un conteo de fuentes coincidentes.

### Cited Findings
- Confidence es *"a numerical value between 0 and 100"*, personalizable con "ticks" etiquetados; OpenCTI ofrece 3 templates de escala: **Admiralty** (basada en la escala de credibilidad de la OTAN), **Objective** (categorías "Witnessed", "Deduced", "Induced", "Told") y **Standard** (Low/Medium/High) — [OpenCTI docs: Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- OpenCTI distingue **Reliability** (evalúa la confianza en la fuente/autor/conector según capacidad técnica e historial) de **Confidence** (evalúa la credibilidad de la información misma); ambos se muestran juntos en la vista de la entidad para evaluación holística — [OpenCTI docs: Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- Regla explícita de fusión conservadora documentada textualmente: *"in a conservative approach, when 2 confidence levels are possible, we would always take the lowest one"* — es decir, ante conflicto entre fuentes, OpenCTI no promedia ni cuenta coincidencias: se queda con el valor de confianza más bajo entre los disponibles — [OpenCTI docs: Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- OpenCTI permite configurar **umbrales máximos de confianza por usuario o grupo**, para evitar que analistas junior asignen niveles de confianza altos de forma inapropiada — control de gobernanza más que de agregación automática — [OpenCTI docs: Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- Como contraejemplo comercial de una TIP con motor de scoring multi-fuente más elaborado y explícito, **Cyware CTIX** calcula un "Confidence Score" 0-100 mediante **promedio ponderado** de 4 parámetros: Source Sightings (10-75 pts, número de feeds distintos que reportan el mismo indicador), Relations Score (relaciones STIX con otros objetos de amenaza), Source Confidence Score (aplicando un "peso" configurable por el analista a cada feed/fuente) y Enrichment Policy Score (datos de herramientas de enriquecimiento de terceros, ponderados por antigüedad/recencia); el resultado final se clasifica en bandas **Low (0-29) / Medium (30-69) / High (70-100)** — [Cyware CTIX Confidence Score Engine docs](https://techdocs.cyware.com/en/299670-302546-ctix-confidence-score-engine.html)

### Inferences
- El par Reliability/Confidence de OpenCTI es directamente aplicable al R-SOAR: en vez de "2 de N fuentes externas deben responder", se podría declarar una reliability fija por fuente (CrowdSec, OTX, Wazuh-native) y dejar que el score de un solo conector de alta reliability sea suficiente, igual que hace OpenCTI al tomar el mínimo conservador en vez de exigir coincidencia de conteo.
- CTIX es la evidencia más concreta encontrada de un **esquema de pesos explícito y documentado públicamente** (peso por fuente configurable, 0-100 final, bandas Low/Medium/High) que resuelve exactamente el problema planteado en el objetivo de este research: decidir sin depender de que dos fuentes externas coincidan, usando en cambio una combinación ponderada donde la ausencia/caída de una fuente simplemente reduce el score en vez de bloquear la decisión.

### Gaps
- La documentación de CTIX confirma las 4 variables y las bandas de salida, pero **no detalla la fórmula matemática exacta de combinación** (qué pesos relativos tiene cada uno de los 4 parámetros entre sí) ni mapea explícitamente las bandas Low/Medium/High a una acción automática vs. revisión de analista — el documento fuente indica que el enrichment policy score "puede tardar en calcularse" y que la confianza se actualiza en dos fases, lo cual sugiere un diseño orientado a validación por analista más que a bloqueo 100% automático, pero esto es una inferencia, no una cita textual sobre mapeo a acción.
- No se encontró en esta sesión el modelo de datos interno completo de OpenCTI (el JSON schema de `Indicator`/`StixCyberObservable` con el campo `confidence` y cómo interactúa con el GraphQL API cuando dos conectores distintos hacen upsert sobre el mismo IOC) — sería valioso para la tesis revisar directamente `docs.opencti.io` sección de modelo de datos o el código del "playbook"/"connector" de OpenCTI en GitHub.

---

## Casos documentados (whitepapers, charlas, blogs de SOC reales) de cambio de umbral fijo "N fuentes deben coincidir" a esquema ponderado, con resultados (FP, reducción de intervención humana)

### Takeaway
No se encontró un caso documentado, con nombre de organización y métricas concretas (tasa de FP, % de reducción de intervención humana), de un SOC real que haya migrado explícitamente de un umbral fijo "N fuentes deben coincidir" a un esquema ponderado; la evidencia más cercana encontrada es un framework de gobernanza (matriz blast-radius × confidence) que resuelve el mismo problema conceptual pero sin datos cuantitativos de "antes/después", más el ejemplo cuantificable pero no métricamente comparado de Cortex XDR SmartScore.

### Cited Findings
- Un artículo de 2026 ("Automated SOC remediation needs a defensible rule for trust") propone explícitamente reemplazar el "gut check" del analista por **un umbral de confianza documentado por cada acción automatizada**, y presenta un framework de dos ejes — **blast radius** (impacto de negocio si la acción falla) × **detection confidence** (calidad de la evidencia) — en vez de cualquier regla de conteo de fuentes: *"Automated remediation only works when the team can classify each action by the harm caused if it fires incorrectly"* — [Automated SOC remediation needs a defensible rule for trust](https://nhimg.org/articles/automated-soc-remediation-needs-a-defensible-rule-for-trust/)
- El mismo framework propone automatización **escalonada por nivel de impacto**, no por conteo de fuentes: acciones de bajo impacto (ej. cuarentena de email) → completamente autónomas; acciones de impacto medio → ejecución automática con notificación inmediata y rollback de un clic; acciones de alto impacto (ej. deshabilitar identidad, revocar sesión) → requieren aprobación humana — [Automated SOC remediation needs a defensible rule for trust](https://nhimg.org/articles/automated-soc-remediation-needs-a-defensible-rule-for-trust/)
- Palo Alto Networks documenta **Cortex XDR SmartScore** como un score unificado calculado por un ensemble de modelos Gradient Boosting sobre 4 categorías de features (contextuales por alerta, agregadas por incidente, estadísticas de prevalencia vía Cortex Data Lake, y modelos independientes por aspecto como árbol de procesos) — reemplazando conteo de reglas/fuentes coincidentes por un score ML continuo expuesto vía UI/API para integrarse a SOAR — [Beating Alert Fatigue with Cortex XDR SmartScore Technology](https://www2.paloaltonetworks.com/blog/security-operations/beating-alert-fatigue-with-cortex-xdr-smartscore-technology.md)

### Inferences
- La ausencia de casos con métricas públicas de "antes (umbral fijo) / después (ponderado)" es, en sí, un hallazgo relevante para la tesis: la industria parece haber saltado directamente del umbral fijo a scores ML/ponderados sin publicar benchmarks comparativos abiertos — lo que deja espacio para que el R-SOAR documente su propia comparación como contribución, en vez de solo citar literatura externa.
- El patrón **blast radius × confidence** (en vez de "fuentes que coinciden") es el marco conceptual más transferible encontrado: el R-SOAR podría formalizar sus tiers T0-T3 explícitamente como combinación de (a) confianza agregada ponderada del score + señales disponibles y (b) impacto/reversibilidad de la acción de R2 (log < alertar+caso < bloqueo IP < cuarentena), replicando casi literalmente esta matriz.

### Gaps
- No se encontró, dentro del presupuesto de esta investigación, una charla específica de DEF CON, BSides o SANS (con nombre de ponente, SOC/MSSP real y cifras de reducción de falsos positivos o de intervención humana) que documente este cambio de umbral fijo a esquema ponderado. Se recomienda una búsqueda dirigida adicional en: archivo de YouTube de SANS DFIR/SOC Summit, programa de charlas de BSides (bsidesarchive), y `media.defcon.org` (transcripciones/slides), usando términos en inglés como "alert correlation weighted scoring" o "threat intel source reliability SOAR case study", que no se alcanzaron a cubrir en esta sesión.
- No se pudo verificar cuantitativamente el impacto de SmartScore (reducción de FP o de carga del analista) — el blog de Palo Alto Networks consultado no publica cifras, solo beneficios cualitativos ("reduce MTTR", "speeds triage").

---

## ¿Cómo gradúan estas plataformas el nivel de autonomía de respuesta según la confianza (similar a tiers T0-T3)?

### Takeaway
El patrón transversal encontrado en todas las plataformas/fuentes revisadas es gradar la autonomía por una combinación de **(confianza del veredicto) × (impacto/reversibilidad de la acción)**, no por conteo de fuentes coincidentes: desde el gating cualitativo de Cortex/TheHive (un solo "malicious" habilita bloqueo de bajo riesgo) hasta el framework explícito de blast-radius/confidence, pasando por las bandas Low/Medium/High de CTIX y la regla "lowest value wins" de OpenCTI.

### Cited Findings
- Cortex (TheHive): un veredicto "malicious" de un analyzer individual puede disparar **acciones de bloqueo de bajo riesgo inmediatamente**, sin esperar verificación manual — la graduación está en el tipo de acción (bajo riesgo = autónoma), no en el conteo de analyzers — [12 Questions and Answers About Cortex Analyzer](https://www.securityscientist.net/blog/12-questions-and-answers-about-cortex-analyzer/)
- Framework genérico de gobernanza SOC (2026): 3 niveles de autonomía según blast radius — **bajo impacto → autónomo total**; **impacto medio → automático con notificación + rollback de un clic**; **alto impacto (identidad, sesiones) → aprobación humana obligatoria** — [Automated SOC remediation needs a defensible rule for trust](https://nhimg.org/articles/automated-soc-remediation-needs-a-defensible-rule-for-trust/)
- CTIX (Cyware): bandas de confianza explícitas **Low (0-29) / Medium (30-69) / High (70-100)** como clasificación de salida del score multi-fuente ponderado — [Cyware CTIX Confidence Score Engine docs](https://techdocs.cyware.com/en/299670-302546-ctix-confidence-score-engine.html)
- OpenCTI: regla conservadora de "tomar siempre el valor de confianza más bajo" cuando hay conflicto, como mecanismo de graduación hacia el lado seguro — [OpenCTI docs: Reliability and Confidence](https://docs.opencti.io/latest/usage/reliability-confidence/)
- XSOAR: severidad calculada vía cascada de 3 fuentes (herramienta externa de vulnerability mgmt → reputación amalgamada de indicadores vía DBotScore → listas de activos críticos), con el resultado final (High/Medium/Low/Critical) siendo la variable que un playbook puede usar para condicionar ramas automáticas vs. de aprobación — [Security Orchestration Use Case: Automate Incident Severity Assignment](https://www.paloaltonetworks.com/blog/security-operations/security-orchestration-use-case-automate-incident-severity-assignment/)

### Inferences
- Ninguna de las plataformas revisadas documenta públicamente un esquema de "N de M fuentes externas deben responder/coincidir" como criterio de graduación de autonomía — el criterio documentado consistentemente es **score/veredicto agregado (ponderado o conservador) cruzado contra el impacto de la acción**, lo cual respalda directamente la dirección de que R-SOAR abandone el requisito de corroboración por conteo de fuentes disponibles y lo reemplace por un score ponderado (ej. a la CTIX) combinado con el impacto de R2 (log/caso/bloqueo IP/cuarentena) como ya esboza el framework blast-radius × confidence.
- La arquitectura de tiers T0-T3 ya existente en el motor es estructuralmente compatible con este patrón de la industria; el cambio necesario no es "agregar más tiers" sino **cambiar el insumo del tier** de "conteo de fuentes coincidentes" a "score ponderado por reliability de fuente", preservando T3 como el nivel que requiere más señal (equivalente a "alto impacto → aprobación humana" o, en el caso Cortex, "sigue siendo autónomo pero con el veredicto de mayor confianza individual").

### Gaps
- No se encontró un ejemplo público con fórmula matemática completa y pesos numéricos reales de ninguna plataforma comercial (CTIX es el más cercano, pero no publica los pesos relativos entre sus 4 parámetros) — para la tesis, el peso exacto por fuente probablemente deberá definirse de forma original y justificarse, no copiarse de un caso documentado.
