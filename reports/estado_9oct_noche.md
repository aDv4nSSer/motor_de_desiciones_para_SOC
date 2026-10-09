# Estado del 9-oct (noche): ramas para las dos ventanas, conciliación real y esquema de las cadenas (H58)

Trabajo del 9-oct-2026, de 02:00 a 03:00 -03 aprox. Todo quedó en ramas locales, sin push ni deploy ni restart. Sobre producción hubo solo lecturas: consultas paginadas con pausas y aborto por heap o latencia, más `git status` y `systemctl show`. No se consultó AbuseIPDB.

## 1. Ramas y commits

### `feature/fase3a-cuota`: ventana del 9-oct, 21:00 -03

La base es `origin/develop` = `d0c8f93`, que es lo que corre hoy en `.140`. Encima van los 8 commits locales de `develop`, sin push (H56):

| Commit | Contenido |
|---|---|
| `724cbb8` | Fase 3 A: AbuseIPDB solo cuando puede cambiar R2, con tier en enrich, cupo no decisivo 0 y TTL asimétrico |
| `7b25f07`, `f922df5`, `e6f4fab`, `1555d11` | Documentación de H56 |
| `917abc5` | `HONEYPOT_PORTS`: el puerto 2223 cuenta como honeypot (cambio de definición) |
| `9dc45bb` | Propuesta de hardening de Cowrie (no desplegada, solo archivo) |
| `ad49017` | Test: la infraestructura propia nunca llega al enforcer |

Después van los cherry-picks desde `feature/mvp-cierre`:

| Original | En la rama | Contenido |
|---|---|---|
| `c209526` | `afa62bf` | 1.1 casos: dedup por IP pública, TTL y listado acotado |
| `64cb845` | `d0d7d37` | 1.3 recorte del stream de auditoría solo de lo confirmado |
| `13e8601` | `e11cd8d` | 1.2 script de TTL escalonado para casos viejos (no se ejecuta en el deploy) |
| `2dd46e2` | `85e9761` | Corte de régimen de H55 en PENDIENTES |
| `9934255` | `cb30bd9` | Colchón de 48 h en el recorte |
| `b792e2b` | `a0750a6` | Función guarda de SCAN |
| `595fda7` | `43a62bd` | Foto fija de las decisiones de R2 (180 docs reales) |

La punta es `43a62bd`. La rama no incluye cumplimiento, sesiones, usuarios, login, frontend, ROADMAP, `regimes.py`, `audit_gaps.yaml` ni `verify_chain.py`: lo verifiqué con `git diff --stat` contra `origin/develop`.

### `feature/cumplimiento`: ventana del 11-oct

Parte de `feature/fase3a-cuota` y le suma 6 cherry-picks:

| Original | En la rama |
|---|---|
| `c1946dc` | `92e9724` |
| `f02655f` | `b02995e` |
| `d456195` | `9bd560c` |
| `a2ad153` | `56dedfe` |
| `4f49cdb` | `de0559f` |
| `f7c9184` | `37cccf2` |

Con eso su árbol quedó idéntico al de `feature/mvp-cierre`. Después se agregaron los commits nuevos de H58:

| Commit | Contenido |
|---|---|
| `b5866e5` | Test de cadena con esquema mixto |
| `1af95de` | Conciliación por dos caminos con diferencia explicada |
| `8fb2258` | Art. 8 d) parcial y alcance explícito de la verificación |
| `82b61a5` | Frontend con estado de conciliación y alcance de la cadena |
| `docs` | Este informe, H58 y PENDIENTES |

### Commits mixtos y cómo se resolvieron

1. **`a2ad153` (vista Cumplimiento)** también toca dos archivos compartidos:
   - `motor/main.py`: agrega `approval_created_at` en el evento `manual_approval` y en el `detail` de `approval_rejected`.
   - `motor/response/config.py`: agrega `organizacion_es_oiv`, con default `None`.

   Queda entero en `feature/cumplimiento`. Efecto: el campo nuevo de la cadena empieza a escribirse el 11-oct, con el restart de `motor-soc`, no el 9-oct. El worker no lee `organizacion_es_oiv`, así que el 11-oct no necesita restart del worker.
2. **`f7c9184` (bitácora H57)** describe las dos partes y queda en `feature/cumplimiento`. Por eso `feature/fase3a-cuota` sale sin la entrada H57 de la bitácora. Es solo documentación: el código va completo.
3. **`c209526` (casos, 1.1)** está en fase3a y toca `motor/dashboard.py` (`list_cases`), que corre dentro de `motor-soc`. Por eso la ventana del 9-oct también reinicia `motor-soc`, con unos 15 s sin Fast Path.

### Qué se sube y cuándo

| Rama | Cuándo | Cómo |
|---|---|---|
| `feature/fase3a-cuota` | 9-oct, antes de las 21:00 -03, con tu OK | `git push origin feature/fase3a-cuota:develop` (fast-forward `d0c8f93..43a62bd`) y deploy (sección 3) |
| `feature/cumplimiento` | 11-oct, ventana de solo lectura, con tu OK | `git push origin feature/cumplimiento:develop` (fast-forward desde `43a62bd`), pull, bundle del frontend y restart de `motor-soc` |

Hoy no se subió nada.

## 2. Tests y pre-commit por rama

| Rama | Backend | Frontend | Pre-commit | Foto fija de R2 |
|---|---|---|---|---|
| `feature/fase3a-cuota` (`43a62bd`) | **758 passed** | no aplica (la rama no toca el frontend) | limpio | pasa |
| `feature/cumplimiento` (`82b61a5`) | **797 passed** | **48 passed**, `tsc` y build sin errores, oxlint 0 errores (1 warning previo en `AuthContext.tsx`) | limpio | pasa |

## 3. Ventana del 9-oct: diff, comandos, verificación y rollback

### Diff final contra `origin/develop`

Son 25 archivos (+4.580, −44). La mayor parte son fixtures y tests: `h56_replay_docs.json` y `h57_r2_decisiones.json` suman unas 3.000 líneas.

| Archivo | Proceso que lo usa | Cambio |
|---|---|---|
| `motor/response/enrichment.py` | response-worker | Tier en enrich, cupo no decisivo 0, TTL asimétrico, log `AbuseIPDB API tier=N` |
| `motor/response/config.py` | response-worker | `abuseipdb_cache_ttl` 86400, `abuseipdb_cache_ttl_below_threshold` 21600, `case_ttl_seconds`, `case_dedup_window_seconds` |
| `motor/response/worker.py` | response-worker | Pasa el tier a enrich y el TTL y la ventana de dedup a `open_case` |
| `motor/response/cases.py` | response-worker | Dedup por IP pública, TTL de 7 días desde la última ocurrencia, `net24`, ZSET `soc:cases:recent` |
| `motor/dashboard.py` | motor-soc | `list_cases` lee el ZSET acotado (ya no `SMEMBERS` del índice completo); `HONEYPOT_PORTS` |
| `motor/constants.py` | motor-soc | Puertos honeypot |
| `motor/response_audit_indexer.py` | response-audit-indexer | `XTRIM MINID ~` de lo confirmado, con colchón de 48 h |
| `motor/redis_guard.py` | (scripts) | Función guarda de SCAN |
| `scripts/mantenimiento/h57_ttl_casos_existentes.py` | (manual) | No se ejecuta en el deploy; requiere OK aparte |
| `docs/*`, `infra/systemd/propuestas/cowrie-hardening.conf` | ninguno | Documentación y propuesta no desplegada |

### Cambios de `.env` (marcados)

- **`ABUSEIPDB_CACHE_TTL=21600` está fijado en el `.env` de `.140`** (lo verifiqué leyendo solo los nombres de clave y este valor numérico). Pisa el default nuevo de 86400. Si no se edita, el TTL asimétrico queda en 6 h para todos los scores. El resto de la Fase 3 A funciona igual: tier, cupo no decisivo 0 y log.

  Sin el cambio se pierde el ahorro de re-consultas a las 6 a 24 h, que fue el 14% de las consultas en H56 C. **Pasarlo a 86400 requiere tu OK aparte.**
- `ABUSEIPDB_CACHE_TTL_BELOW_THRESHOLD`, `CASE_TTL_SECONDS` y `CASE_DEDUP_WINDOW_SECONDS` no están en el `.env`, así que rigen los defaults: 6 h, 7 días y 24 h. No hay que tocarlos.

### Comandos en orden

En el Mac:

```bash
git switch feature/fase3a-cuota && git status -sb
git push origin feature/fase3a-cuota:develop       # fast-forward d0c8f93..43a62bd
git branch -f develop feature/fase3a-cuota          # develop local = lo pusheado
```

En `.140` (`ssh motor140`):

```bash
cd ~/tesis/repo && git status -sb                  # limpio, develop...origin/develop
git pull --ff-only && git log --oneline -1         # 43a62bd
date '+%F %T %z'                                   # anotar: hora del pull

# SOLO con el OK aparte del TTL:
sed -i 's/^ABUSEIPDB_CACHE_TTL=21600$/ABUSEIPDB_CACHE_TTL=86400/' motor/.env
grep -c '^ABUSEIPDB_CACHE_TTL=86400$' motor/.env   # 1

# Restarts (Antonio ejecuta sudo), anotando la hora de cada uno:
sudo systemctl restart response-worker             # CORTE DE RÉGIMEN; pide contraseña
sudo -n systemctl restart motor-soc                # ~15 s sin Fast Path
sudo systemctl restart response-audit-indexer      # activa XTRIM (ver nota)
```

**Nota sobre el indexador.** Reiniciarlo activa `XTRIM MINID` con colchón de 48 h. Hoy no recorta nada: el `maxlen` de 100.000 del worker deja unas 18 h en el stream, menos que el colchón. Igual es una escritura nueva en Redis, y el 8-oct dijiste "XTRIM no esta noche". Si preferís, se deja el indexador sin reiniciar y el ítem 1.3 queda inactivo hasta otra ventana. Lo leí del lado conservador: va con tu OK explícito.

### Verificación post-deploy

Todo es de solo lectura, a los +10 min y a los +60 min. `RS` es la hora del restart del worker en el formato del log, por ejemplo `2026-10-09 21:00:30`. Para Redis: `export REDISCLI_AUTH="$(grep '^REDIS_PASSWORD=' motor/.env | cut -d= -f2-)"`, que no imprime nada.

1. **Código vigente:**
   - `ps -o lstart= -p $(systemctl show -p MainPID --value response-worker)` debe ser posterior a la hora del pull. Lo mismo para `motor-soc` y el indexador.
   - `curl -s -o /dev/null -w '%{http_code}\n' localhost:8000/health` debe dar `200`. Nunca `POST /decide`.
2. **AbuseIPDB por tier:**
   - `awk -v t="$RS" 'substr($0,1,19) >= t' motor/logs/worker.log | grep -ao 'AbuseIPDB API tier=[0-9?]*' | sort | uniq -c`. Se espera **`tier=2` = 0**.
   - `... | grep -c ' 429\|cuota agotada'` debe dar 0.
   - `... | grep -a 'AbuseIPDB cuota real' | tail -1` muestra lo que resta.
3. **Casos con dedup:**
   - `... | grep -ao 'T2 caso automático abierto: [0-9a-f-]*' | sort | uniq -c | sort -rn | head`. Un mismo `case_id` repetido significa dedup; el log dice "abierto" también al reutilizar.
   - `redis-cli ZCARD soc:cases:recent` crece de a pocos.
   - `redis-cli TTL soc:cases:$(redis-cli ZREVRANGE soc:cases:recent 0 0)` debe estar cerca de 604800.
4. **Stream de auditoría:**
   - `redis-cli XLEN soc:response:audit` debe ser ≤ 100000.
   - `redis-cli XINFO GROUPS soc:response:audit` debe dar pending 0 y lag 0.
5. **Memoria:**
   - `redis-cli INFO memory | grep used_memory_human`.
   - `redis-cli INFO stats | grep evicted_keys` debe seguir en **72205**.
6. **R2 sigue igual:**
   - `awk ... | grep -ac '\[ENFORCE\]'` debe ser > 0 en la primera hora si hay tráfico T3 corroborado.
   - El dashboard debe cargar la lista de casos.
7. Registrar la hora real de cada restart en `PENDIENTES_MODO_SOMBRA.md` §6.

### Rollback

`d0c8f93` tiene el mismo formato de cadena que `43a62bd`, porque la Fase 3 A no toca el hash. Por eso es un destino válido.

```bash
cd ~/tesis/repo && git switch --detach d0c8f93
sed -i 's/^ABUSEIPDB_CACHE_TTL=86400$/ABUSEIPDB_CACHE_TTL=21600/' motor/.env   # solo si se cambió
sudo systemctl restart response-worker; sudo -n systemctl restart motor-soc; sudo systemctl restart response-audit-indexer
```

Qué queda en Redis después del rollback:
- Las claves `soc:cases:open:ip:*` (TTL 24 h) y el ZSET `soc:cases:recent` las ignora el código viejo.
- Los casos con TTL expiran solos.
- El código viejo vuelve a hacer `SMEMBERS` del índice en `list_cases`, que es el riesgo de H54. Mientras dure el rollback, no abrir la lista de casos del dashboard.

El rollback se registra como corte de régimen.

## 4. Conciliación real de aprobaciones (ventana móvil de 24 h, solo lectura)

La fuente es `soc-responses-*` más las aprobaciones pendientes de Redis, medidas con el script de H58 en `.140`. En OpenSearch fueron consultas paginadas con `search_after`, 0,2 s de pausa y aborto si el heap supera el 85% o la latencia los 10 s; no hubo ningún aborto. En Redis no se usó SCAN.

| Medición (-03) | 02:19:13 | 02:20:59 | 02:28:26 | 02:50:25 |
|---|---|---|---|---|
| IPs bloqueadas (distintas) | 193 | 193 | 186 | 177 |
| Acciones de bloqueo (docs) | 405 | 402 | 392 | 382 |
| IPs derivadas a aprobación | 541 | 543 | 540 | 541 |
| Decisiones T3 derivadas (docs) | 21.304 | 21.318 | 21.349 | 21.484 |
| **Creadas por destino** | 1.594 | 1.600 | 1.602 | 1.625 |
| aprobadas / rechazadas | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| expiradas (TTL 4 h) | 1.389 | 1.394 | 1.408 | 1.439 |
| pendientes | 205 | 206 | 194 | 186 |
| **Creadas por documentos** | 1.594 | 1.600 | 1.602 | 1.625 |
| **Recurrencias por documentos** | 19.710 | 19.718 | 19.747 | 19.859 |
| **Recurrencias por contador** | 19.135 | 19.148 | 19.207 | 19.387 |
| Diferencia | 575 | 570 | 540 | 472 |
| Aprobaciones abiertas antes de la ventana | 101 | 101 | 104 | 109 |
| Cota de borde (Σ ocurrencias − 1 de esas) | 770 | 770 | 770 | 770 |
| Estado | diferencia explicada | diferencia explicada | diferencia explicada | diferencia explicada |
| Derivadas stale / eventos sin `created_at` | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

Separación entre mediciones: 1 min 46 s, 7 min 27 s y 21 min 59 s.

**Igualdad 1, aprobaciones creadas:** cierra exacta en todas las mediciones. Las creadas por destino (aprobadas + rechazadas + expiradas + pendientes) coinciden con las creadas por documentos (`trace_id` de los docs derivados que abrieron aprobación).

**Igualdad 2, recurrencias: no cierra exacta y la diferencia está explicada.**
- La forma original (`derivadas = creadas + recurrencias`) era tautológica: las recurrencias se calculaban como `derivadas − creadas`, así que no podía fallar nunca.
- Ahora se miden por dos caminos independientes:
  - **por documentos:** decisiones derivadas que entraron al flujo de aprobación menos las creadas;
  - **por contador:** Σ (`occurrences` − 1) de las aprobaciones creadas en la ventana, según el destino de cada una.
- Diagnóstico de la diferencia de 472 a 575:
  - Una aprobación abierta **antes** del inicio de la ventana sigue absorbiendo decisiones de su IP dentro de la ventana mientras no venza (TTL 4 h).
  - Esas decisiones son recurrencias por documentos.
  - El contador vive en una aprobación que no se creó en la ventana, así que no suma.
  - La cota es Σ (`occurrences` − 1) de esas 101 a 109 aprobaciones: 770. Es una cota superior, no una igualdad, porque parte de sus recurrencias cayó antes de la ventana.
- En todas las mediciones la diferencia quedó entre 0 y la cota: **diferencia explicada**.
- No se forzó el cierre. Si la diferencia supera la cota, o falta un documento de creación, el estado pasa a "no cierra" con su causa, y hay un test para cada caso.
- Ejemplos de borde, anonimizados: `162.216.x.x`, `91.196.x.x` y `42.82.x.x` con 1 ocurrencia; `209.192.x.x` con 8.

**Dato aparte:** en 24 h ningún humano resolvió una aprobación (0 aprobadas, 0 rechazadas). Todas vencieron o siguen pendientes. Por eso el tiempo humano de respuesta queda "sin datos", y no es un error de medición.

## 5. Campos nuevos en registros encadenados y el hash

Así se calcula el hash, igual en `origin/develop` y en las dos ramas (`motor/response_audit_indexer.py`):

```python
def canonical_json(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
def compute_hash(content, prev_hash): return hashlib.sha256((canonical_json(content) + prev_hash).encode("utf-8")).hexdigest()
def chain_document(content, seq, prev_hash):
    hashed = {**content, "chain_seq": seq}
    return {**hashed, "prev_hash": prev_hash, "hash": compute_hash(hashed, prev_hash)}
```

El evento completo va en `payload` y entra al hash. El cálculo no depende del esquema: cualquier campo presente entra, y uno ausente simplemente no está.

| Campo | Dónde | Rama y ventana | ¿Entra al hash? |
|---|---|---|---|
| `approval_created_at` | `payload` de `manual_approval` (`soc-responses-*`) | cumplimiento, 11-oct | Sí, solo en eslabones nuevos |
| `approval_created_at` | `payload.detail` de `approval_rejected` (`soc-responses-*`) | cumplimiento, 11-oct | Sí, solo en eslabones nuevos |
| `policy_version`, `regime_id` | No se escriben en ninguna cadena; se calculan al armar el informe | cumplimiento | No |
| Notas de enriquecimiento de la Fase 3 A | `payload` de `response`: cambian valores, no campos | fase3a, 9-oct | Sí, como siempre |
| `soc-decisions-*` | Sin cambios de esquema | ninguna | no aplica |

**Decisión sobre el verificador: no se cambia.**
- Lo prueba `tests/unit/test_h58_cadena_esquema_mixto.py` (4 tests):
  - una cadena con eventos viejos y nuevos intercalados verifica íntegra;
  - alterar `approval_created_at` en un doc nuevo se detecta;
  - alterar un doc viejo se detecta;
  - el eslabón de un evento viejo da exactamente el hash del indexador desplegado (`61aa26e0…eb09cc`, calculado con `d0c8f93`).
- **No se recalcula nada histórico:** el indexador sigue desde la cabeza (`chain_seq` y `hash` del último doc) y `verify_chain` solo lee.
- **Riesgo para el deploy del 11-oct: bajo.** Una aprobación sin `created_at` escribiría `null`, que se hashea igual que cualquier valor; hoy hay 0 eventos sin `created_at`.

## 6. Ajustes de la vista (`feature/cumplimiento`)

- **Art. 8 d)** siempre "parcial". El texto separa dos partes:
  - "Cubre R-SOAR: análisis continuo de redes y sistemas…", con el estado de los nodos;
  - "Queda en la organización: ejercicios, simulacros y la comunicación de amenazas al CSIRT Nacional".

  Los tests de etiqueta están actualizados (parametrizados con nodos ok, degraded y unknown).
- **Panel de integridad:** muestra el texto de alcance, que se arma del informe de `verify_chain`, más los huecos declarados. Con el informe de anoche dice:

  > verificación completa (completa) del 2026-10-09 04:04 UTC: soc-responses-* desde 2026-10-02, chain_seq 1 a 1699916, íntegra; soc-decisions-* desde 2026-10-03, chain_seq 1 a 2456573, íntegra; el índice legado soc-decisions (17,9 M documentos, cadena vieja) no se verificó en esta pasada
- **Conciliación en el frontend:** muestra "La conciliación cierra", "Diferencia explicada: {causa}" o "La conciliación NO cierra: {causa}", junto con la regla y las decisiones derivadas que no abrieron aprobación.

## 7. Ambigüedades y la lectura conservadora tomada

1. **"Repetí a los minutos".** Dije que la segunda medición fue 15 min después y fueron 1 min 46 s; ya lo había corregido. Tomé una tercera (+7 min 27 s) y una cuarta (21 min 59 s) para tener separación real.
2. **"Nada de cumplimiento en fase3a" frente a commits mixtos.** `a2ad153` y `f7c9184` quedaron enteros en `feature/cumplimiento`. `approval_created_at` entra el 11-oct, no el 9-oct, y fase3a sale sin la entrada H57 de la bitácora.
3. **Documentación de H58 y filas de PENDIENTES.** Se commitearon solo en `feature/cumplimiento`, para no agregar a fase3a nada fuera de lo aprobado. Al pushear fase3a, la fila del 9-oct en PENDIENTES de `develop` va a seguir con el texto anterior hasta el 11-oct.
4. **Restart del indexador el 9-oct.** Activa el recorte con colchón de 48 h, que hoy no recorta nada. Como el 8-oct dijiste "XTRIM no esta noche", lo marco para OK explícito; la alternativa es no reiniciarlo.
5. **`ABUSEIPDB_CACHE_TTL`:** OK aparte, con o sin cambio. Las dos opciones están descritas en la sección 3.
6. **"Diferencia explicada" en Art. 8 e).** La fila queda "cumple" con el texto "Diferencia explicada: {causa}", porque la diferencia está acotada por una causa medida. Si preferís que una diferencia no nula se muestre como "con observación", es un cambio de una línea.
7. **Art. 8 d) "parcial" aunque los nodos estén bien:** la ley exige más que el análisis continuo.
8. **El "conocimiento" del incidente** (plazos de 3 h y 72 h) es un acto de la organización. El primer T3 corroborado es solo una aproximación, y la vista lo dice (sin cambios desde H57).

## 8. Pendientes que siguen abiertos

- Línea base de Suricata: tenés que correr `h57_suricata_baseline.sh`.
- `grep maxmemory` en `redis.conf` (requiere sudo).
- Decisión sobre el colchón del stream.
- Con OK aparte:
  - desactivar `smoke-*`;
  - pasar las réplicas a 0 donde hay shards sin asignar;
  - reparar `soc:users:index`;
  - correr el script 1.2 de TTL de casos.
- Domingo 11-oct: verificar el corpus y el hash del IF (ver PENDIENTES §6).

Quedo esperando tu OK: sin push ni deploy.
