# Estado del 10-oct (mañana): D2 para las 21:00 y paquete del 11-oct (H59)

Trabajo del 10-oct, de 02:00 a 03:00 -03. No hubo push, deploy, restart ni escrituras en producción. Sobre producción solo hubo lecturas, en tres conexiones SSH (una por tanda) más una para leer huellas.

## Ramas (todas locales)

| Rama | Punta | Contenido nuevo | Tests | Pre-commit |
|---|---|---|---|---|
| `feature/d2-bucket-rafaga` | `27830f2` | D2 rebasado sobre `develop` (`43a62bd`) | 778 passed; foto fija de R2 sin cambios | limpio |
| `feature/cumplimiento` | (este commit) | Régimen R4 (`bd27c8f`), H59, PENDIENTES, script del IF del domingo, este informe | ver el final | limpio |
| `feature/explicabilidad` | sobre `feature/cumplimiento` | Traza v1 y endpoint `explain`, tabla ATT&CK por SID, métricas | 821 passed (antes de las métricas); 28 nuevos | limpio |

Probé rebasar `cumplimiento` + `explicabilidad` sobre D2 en una rama descartable: **sin conflictos, 849 passed**.

## 1. Chequeo del régimen R4 (solo lectura)

| Medida | Desde el corte (9-oct 11:21) | Día UTC 10-oct (desde las 21:00) | Línea base 9-oct (24 h) |
|---|---|---|---|
| Hora de la medición (-03) | 02:03:21 (14,7 h) | 02:03:21 (5,1 h) | 9-oct 02:50 |
| Consultas reales a AbuseIPDB | 323, todas `tier=3` | 30, todas `tier=3` | no aplica |
| `tier=2` / HTTP 429 / consumo externo | **0 / 0 / 0** | 0 / 0 / 0 | no aplica |
| Gauge restante | 970/1000 a las 02:01 | 970/1000 | no aplica |
| T3 "presupuesto agotado" | 2.906 docs, **288 IPs**; 46 de 89 ventanas de 10 min, máximo 96 IPs por ventana, la última a las 19:00 -03 | 0 | no aplica |
| Aprobaciones creadas (IPs) | 290 (272) = **19,7/h** | 16 (16) | 1.625 = 67,7/h |
| Aprobadas / rechazadas / expiradas / pendientes | 0 / 0 / 277 / 13 | 0 / 0 / 3 / 13 | 0 / 0 / 1.439 / 186 |
| IPs T3 / IPs con bloqueo automático | 386 / 307 | 304 / 287 | no aplica |
| Conciliación | diferencia explicada (874 ≤ 1.660) | diferencia explicada (1 ≤ 27) | diferencia explicada |
| Redis | 854 MB de 1,5 GB, evicted 72.205 | igual a las 02:25 | 830 MB |
| Lag del indexador | 0; pending 12 momentáneo (2 de 8 lecturas) | igual | 0 |

**Regla de conciliación:** "cierra" exige igualdad exacta en creadas y recurrencias. "Diferencia explicada" significa creadas iguales y 0 ≤ diferencia de recurrencias ≤ Σ(ocurrencias − 1) de las aprobaciones abiertas antes de la ventana. Cualquier otro resultado es "no cierra". El Art. 8 e) solo queda "Con evidencia" si cierra.

Las 3 coincidencias de "429" desde el corte eran el gauge "restan 429/1000" y dos `case_id`: no hubo ninguna respuesta 429.

## 2. D2: decisión a las 21:00

**Simulación offline.** Usé los 18.598 docs T3 desde el corte y las consultas reales por hora del log. Parámetros reales de D2: capacidad 288, recarga 6 cada 10 min, techo 864 − 432·(1 − f) y arranque conservador. El score de las IPs denegadas es el observado en otros docs; si no hay, se imputa con p(score ≥ 50) = 0,95.

| Escenario | IPs denegadas que D2 consulta | De aprobación a bloqueo automático, observado | Imputado | Máximo usado en el día |
|---|---|---|---|---|
| A: 9-oct real (arranque a mitad de día, 522 ya usadas) | 9 | 7 IPs (67 docs) | +1,9 IPs | 824 |
| B: día UTC limpio, misma demanda (bucket lleno a las 00:00Z, noche a ~6/h) | 273 | **234 IPs** (2.715 docs, cota superior) | +36 IPs | 652 |

El 9-oct, la ráfaga no habría ayudado: con 522 consultas gastadas antes del corte, el límite fue el ritmo de 36/h. D2 sirve en un día limpio. La noche se consume a ~6/h, así que el bucket llega lleno a la tarde, que es cuando la demanda supera 36/h (12:00 a 18:00 -03).

**Regla de decisión** (sobre el día UTC del 10-oct, medida a las 20:30 -03 con una conexión):

| # | Criterio | Umbral para activar D2 |
|---|---|---|
| 1 | IPs T3 con "presupuesto agotado" / IPs T3 del día | ≥ 15% |
| 2 | Consultas reales del día | ≤ 600 (al menos 264 sin usar bajo el techo de 864, una ráfaga) |
| 3 | IPs que pasarían de aprobación a bloqueo (simulación B con el día, solo observadas) | ≥ 20 |
| 4 | Seguridad: HTTP 429, `tier=2`, consumo externo, evicted, lag | todos en 0 o sin crecer |

Si se cumplen las 4, se activa. Si falla alguna, D2 queda como trabajo futuro con esta simulación como evidencia.

**Riesgo de agotar la cuota:** bajo. El techo duro es 864/día (136 de margen sobre las 1.000 para timeouts y consumo externo), el bucket se resincroniza con el gauge real si la cuota real va peor, y el escenario B llega a 652.

**Riesgo metodológico:** activar D2 es el **corte R5 dentro del período 2**. R4 quedaría en 33,6 h, menos que las 72 h de la sección 2. **Mi recomendación:** si la regla se cumple, desplegar el **12-oct a las 11:21**, al cierre del período 2 y antes del freeze de las 21:00. Desplegar hoy a las 21:00 solo si preferís priorizar los bloqueos del domingo sobre la comparabilidad del período 2.

**Comandos** (los restarts los ejecutás vos):

```bash
# Mac
git push origin feature/d2-bucket-rafaga:develop && git branch -f develop feature/d2-bucket-rafaga   # 43a62bd..27830f2
# .140
cd ~/tesis/repo && git status -sb && git pull --ff-only && git log --oneline -1      # 27830f2
grep -c '^ABUSEIPDB_BURST_CAPACITY=' /home/aiayala/tesis/motor-runtime/.env            # 0: rige el default 288
date '+%F %T %z'; sudo systemctl restart response-worker; date '+%F %T %z'            # CORTE R5
# motor-soc y response-audit-indexer NO: D2 solo cambia el worker
```

Después de cada restart se registra R5 en `motor/regimes.py` y en PENDIENTES §6, y se rebasan `cumplimiento` y `explicabilidad` sobre `27830f2`.

**Verificación a +10 y +60 min:**
- `AbuseIPDB API tier=3` sigue y `tier=2` queda en 0.
- Notas "ráfaga agotada" o "techo diario" presentes, y "presupuesto de la ventana agotado" desaparece.
- 0 HTTP 429.
- `GET ti:rate:abuseipdb:day:<día>` existe (O(1)).
- Gauge decreciente.

**Rollback:**
- Rápido, sin tocar código: `echo 'ABUSEIPDB_BURST_CAPACITY=0' >> /home/aiayala/tesis/motor-runtime/.env` y `sudo systemctl restart response-worker` vuelven a las ventanas de H52.
- Completo: `git switch --detach 43a62bd`, quitar esa línea y reiniciar el worker.

## 3. Explicabilidad (paquete del 11-oct, solo lectura)

| Pieza | Estado |
|---|---|
| Traza v1 (`motor/explain.py`, `GET /api/v1/dashboard/explain/{trace_id}`, N2) | Señales y pesos (0,70 ml + 0,30 anomaly, comparados por test contra `model.py`), regla de tier (`FP-TIER-*`, `FP-T3-CLASSTYPE`), fuentes de R1 con su umbral, regla de R2 (`R2-CORROBORADO`, `R2-PENDIENTE-APROBACION`, `R2-STALE`, `R2-SAFELIST`, `T2-*`), score de sombra marcado "no decide", ATT&CK e integridad del documento. Marca `consistente=False` si no reproduce lo guardado |
| No regresión | En los 180 docs reales, la regla de la traza produce la acción exacta de `process_task`. Ningún camino de decisión importa `explain.py`. La foto fija de R2 sigue igual |
| Tabla ATT&CK por SID (`scripts/attack/`, 30 días) | 375 SIDs y 201.458 alertas. **Solo el 4,0% tiene técnica:** Misc Attack (listas DROP/CINS/COMPROMISED) 73,6%, Generic Protocol Command Decode 18,5%, Potentially Bad Traffic 3,9%. Archivo: `reports/metricas/2026-10-10/attack_por_sid_30d.csv` |
| `verify_chain.py` | Ya era único para las cadenas vigentes desde H57; el legado conserva su script (fórmula distinta) |
| SHAP | Pendiente; declarado como limitación dentro de cada traza |
| Frontend de la traza | No se hizo; el endpoint está listo |

## 4. Preparados para tu OK de la mañana (no ejecutados)

| Ítem | Estado medido (02:24 -03) | Comando y rollback |
|---|---|---|
| Cuentas `smoke-ciso`, `smoke-n1`, `smoke-n2` | **Ya deshabilitadas** desde el 4-oct 03:52 (H44), 0 sesiones, fuera del índice. Contraseñas generadas dentro del proceso, nunca guardadas (H44). Ninguna credencial vigente en el historial (sección 5). Accesos en la cadena: 13, 11 y 9 eventos, todos el 4-oct entre 03:52:06 y 03:52:45 | **Nada que ejecutar.** No recomiendo borrar los registros: la cadena los referencia |
| Réplicas a 0 | 183 shards sin asignar en 183 índices: `security-auditlog` 101, `suricata-alerts` 72, ISM y sistema 9, `soc-experimental-detections` 1. Todos con rep 1. Sin plantilla para `suricata-alerts-*` ni para `security-auditlog-*` | Ver el bloque de abajo. Se espera bajar de 183 a 9 shards sin asignar. Los 9 de sistema (`.opendistro-*`) quedan aparte: probablemente requieren el certificado de admin |
| `soc:users:index` | SCARD 0. Usuarios en la cadena: `aiayala` (CISO, habilitado), las 3 `smoke-*` y `cli:aiayala` (actor del CLI, no es usuario). **Dry-run:** agregaría `aiayala` y excluiría las 3 `smoke-*` | `SADD soc:users:index aiayala` (rollback `SREM`). Otra opción: después del deploy del 11-oct, el próximo login de `aiayala` lo re-registra (`_ensure_indexed`). Ojo: `h57_reparar_indice_usuarios.py` no debe correrse por stdin, porque tomaría `~/tesis/motor` viejo |
| Reentrenamiento del IF | Cron `0 4 * * 0` (domingo 11-oct 04:00 -03) desde `~/tesis/motor/training`. Corpus 2026-06-20 13:52:20 (correcto). Hash `4958eb4be015c2fd`, modelo del 4-oct 04:00:46 | Después de las 04:00: `bash ~/tesis/repo/scripts/mantenimiento/h59_verificar_if_domingo.sh` (llega con el deploy del 11-oct; si no, va por stdin). Hash igual = evento; distinto = corte |

```bash
cd ~/tesis/repo/motor && python3 - <<'EOF'
from dashboard import _os_request as q
h = q("GET", "/_cluster/health"); print("antes", h["status"], h["unassigned_shards"])
print(q("PUT", "/_index_template/h59-replicas-cero", {"index_patterns": ["suricata-alerts-*", "security-auditlog-*"],
        "priority": 10, "template": {"settings": {"index": {"number_of_replicas": 0}}}}))
print(q("PUT", "/suricata-alerts-*,security-auditlog-*,soc-experimental-detections/_settings", {"index": {"number_of_replicas": 0}}))
h = q("GET", "/_cluster/health"); print("después", h["status"], h["unassigned_shards"])
EOF
# rollback: el mismo PUT de _settings con "number_of_replicas": 1 y q("DELETE", "/_index_template/h59-replicas-cero")
```

## 5. Escaneo de secretos (repo público; solo lectura)

**Método:**
- 217 commits, todas las ramas locales y remotas, incluidos los mensajes de commit.
- Búsqueda por patrones.
- Comparación de las huellas sha256 de los 7 secretos vigentes del `.env` de `.140` y de la key de `.139` contra todas las subcadenas del historial (103.770 líneas).
- Control positivo: una credencial de test conocida aparece 9 veces.

**Ningún secreto vigente aparece en el historial.**

| Tipo | Archivo | Primer commit | Lectura |
|---|---|---|---|
| Nombre del `CONFIG` renombrado | `docs/BITACORA_TECNICA.md` | `41f1f57` (5-sep) | **Real y vigente**; en `main`, `develop` y 3 ramas más. Pendiente §7 |
| Password de Redis hardcodeada (`password=` en 8 archivos) | `motor/redis_client.py`, `opensearch_indexer.py`, `response/queue.py`, `vigilante/*.py` | `a151560` y siguientes (jun-ago) | Rotada en H32; no coincide con la vigente |
| Valores en `.env.example` | `.env.example` | `76bd905` (1-jun) | No coinciden con ningún secreto vigente; parecen ficticios (mismo valor en dos claves) |
| Credenciales de test | `tests/...`, `frontend/.../shell.test.tsx` | `a82fac1`, `4edfd3b` | Ficticias, marcadas `allowlist` |
| Topología | `CLAUDE.md`, bitácora, `config.py`, `nginx/motor-soc.conf`, tests | desde `6cd7905` (10-jun) | IP pública de `.139` con puerto SSH 2222, VLANs, dominio duckdns |
| Falsos positivos (URL `host:puerto`) | `vector.production.toml`, `observability.md`, bitácora | no aplica | No son credenciales |

`FASTAPI_SECRET_KEY` no se verificó: no está en ese `.env`.

## 6. Auditoría de la documentación (sin editar)

| Falta | Ya no es cierto | No verificable |
|---|---|---|
| **La decisión de descartar Iris:** no está en ningún documento | CLAUDE.md: "Iris Web es dependencia core desde semana 1-2" y "casos vía Iris" (también en la especificación ampliada §6 y en el borrador final sin versionar) | Fecha y responsable de la decisión sobre Iris |
| Restarts del 9-oct en la bitácora (están solo en PENDIENTES §6): worker 11:21:00, motor-soc 11:27:01, maxmemory en caliente 11:12:54 | Especificación: "~68% resuelto automático". Medido en IPs distintas: **34%** promedio del 4 al 9-oct (entre 28% y 37% por día; bloqueadas y derivadas pueden solaparse); 94% en la noche del 10-oct (parcial, R4) | Origen del "~68% pre-migración" |
| La exclusión del hueco de H54 (8-oct 03:32:41 a 03:32:45Z) en las instrucciones de CLAUDE.md: solo pide excluir H25 | Borrador final: "p95 ~47 ms". H57 da 57,79 ms (24 h); por día: 91 a 92 ms del 3 al 5-oct y 57 a 60 ms del 6 al 9-oct | Versiones del stack (Suricata, Vector, Wazuh) |
| `soc-responses-*` en la tabla de índices de CLAUDE.md | CLAUDE.md: "Todos los índices: replicas 0, ISM obligatorio". Hay 183 shards con rep 1 y sin ISM en `suricata-alerts-*`, `security-auditlog-*` y el legado | Estado de `.141`/`.142` |
| R4 y el período 2 en CLAUDE.md "Contexto reciente" (sigue fechado el 1-sep) | CLAUDE.md: `T3_CLASSTYPES` en `motor/main.py:78`; está en `motor/constants.py:15` | Dónde vive `FASTAPI_SECRET_KEY` |
| La traza v1 en CLAUDE.md y en PROHIBICIÓN 15 ("rules.yaml sin empezar"; la traza cubre `rules_fired`/`reasoning` en versión v1) | Bitácora H57: deploy de la robustez el 11-oct y `595fda7`; entró el 9-oct y es `43a62bd` (H58 lo aclara) | Qué ruta escribe el reentrenamiento del IF frente a `MODEL_DIR` (lo verifica el script del domingo) |
| | Skill `soc-audit`: ".138 no migrado aún"; migró el 1-sep | |
| | Pendiente de la bitácora "Persistir `soc:response:audit` (H39)"; hecho (`soc-responses-*`) | |
| | `main` como "producción estable": `origin/main` está 99 commits detrás de `develop` | |

## 7. Métricas de tesis (`reports/metricas/2026-10-10/`)

| Archivo | Contenido |
|---|---|
| `tiers_por_hora.csv/.png` | Decisiones por hora y tier desde el 3-oct, con los cortes R0 a R4 |
| `latencia_por_dia.csv/.png` | p50 ~51 ms todos los días; p95 de 91 a 92 ms (3 al 5-oct) y de 57 a 60 ms (6 al 9-oct) |
| `respuesta_por_dia.csv/.png` | IPs distintas por día: bloqueadas, derivadas y expiradas; 0 o 1 resueltas por humanos |
| `abuseipdb_por_dia.csv/.png` | Consultas por día y tier desde R4: 312 (9-oct local) y 16 (10-oct hasta las 02:24), todas tier 3 |
| `attack_por_sid_30d.csv` | Tabla ATT&CK por SID |

Para reproducir: `extraer_metricas.py` en `.140` y `graficar_metricas.py` en local (matplotlib 3.9.2). Antes del 3-oct, el log no permite separar las consultas cobradas: las líneas con `api.abuseipdb.com` incluyen reintentos y 429 (16.000 a 107.000 por día).

## Ambigüedades y lectura conservadora

1. **"Desactivar las cuentas smoke":** ya lo están. No propongo borrarlas, porque la cadena las referencia.
2. **Mapeo ATT&CK por SID:** sin técnica por SID en el YAML, no inventé técnicas para las listas de reputación. La tabla dice la fuente de cada mapeo.
3. **D2:** la regla decide si conviene activarlo; el cuándo lo dejo como recomendación (12-oct 11:21) por el corte en el período 2.
4. **Escaneo:** "IPs y puertos" se reportan como topología, no como secreto; no cambié la visibilidad ni reescribí la historia.

Espero tu OK. No hice push ni deploy.
