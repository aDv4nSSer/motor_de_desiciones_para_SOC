import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { CaretDown, CaretRight } from '@phosphor-icons/react'
import { apiFetch } from '../api/client'
import type { Decision, ResponseRecord, Stats } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton, TierBadge } from '../components/common'
import { ChainLink, ExplainPanel } from '../components/ExplainPanel'
import { attackText, useExplain } from '../lib/explain'
import { formatScore, formatTime, shortId } from '../lib/format'
import { accionR2Label } from '../lib/r2'
import {
  LOOKUP_MAX_IDS, lookupResponses, mergeLookups, responseState,
  type ResponseState, type RowLookup,
} from '../lib/responses'
import { abuseipdbStatus, corroboranLabel, otxStatus } from '../lib/ti'
import { usePolling } from '../lib/usePolling'

const PAGE = 50

interface AlertsData {
  decisions: Decision[]
  stats: Stats | null
}

const STATUS_TEXT: Record<Exclude<ResponseState['kind'], 'ok'>, { text: string; hint: string; danger: boolean }> = {
  checking: { text: 'Consultando…', hint: 'Buscando el registro de respuesta de esta decisión.', danger: false },
  processing: {
    text: 'En proceso',
    hint: 'La tarea sigue en la cola del worker de respuesta o en el lote que está procesando.',
    danger: false,
  },
  missing: {
    text: 'Sin registro de respuesta',
    hint: 'El worker de respuesta ya pasó por esta decisión y no dejó registro R1/R2. No es normal en T2/T3: revisar el encolado.',
    danger: true,
  },
  error: {
    text: 'No se pudo verificar',
    hint: 'La consulta falló o una fuente (OpenSearch o Redis) no respondió: no se puede afirmar si hay respuesta.',
    danger: true,
  },
}

function tierCount(stats: Stats | null, prefix: string): string {
  if (!stats?.available || !stats.por_tier) return 'sin dato'
  const entry = Object.entries(stats.por_tier).find(([k]) => k.startsWith(prefix))
  return entry ? entry[1].toLocaleString('es-CL') : '0'
}

export function AlertsView() {
  const [older, setOlder] = useState<Decision[]>([])
  const [lookups, setLookups] = useState<Map<string, RowLookup>>(() => new Map())
  const olderRef = useRef(older)
  const lookupsRef = useRef(lookups)
  useEffect(() => {
    olderRef.current = older
    lookupsRef.current = lookups
  }, [older, lookups])

  // Cada ciclo resuelve la respuesta de la página 1 y vuelve a consultar las
  // filas anteriores que todavía no la tienen (en proceso o con error).
  const fetchAlerts = useCallback(async (): Promise<AlertsData> => {
    const [decisions, stats] = await Promise.all([
      apiFetch<Decision[]>(`/api/v1/dashboard/decisions?tier_min=2&limit=${PAGE}`),
      apiFetch<Stats>('/api/v1/dashboard/stats?window_minutes=60').catch(() => null),
    ])
    const unresolved = (ds: Decision[]) => ds.map((d) => d.trace_id).filter((id) => !lookupsRef.current.get(id)?.record)
    const ids = [...unresolved(decisions), ...unresolved(olderRef.current).slice(0, LOOKUP_MAX_IDS)]
    const fresh = await lookupResponses(ids)
    setLookups((prev) => mergeLookups(prev, fresh))
    return { decisions, stats }
  }, [])

  const poll = usePolling(fetchAlerts)
  const [loadingMore, setLoadingMore] = useState(false)
  const [moreError, setMoreError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const rows = useMemo(() => {
    const seen = new Set<string>()
    return [...(poll.data?.decisions ?? []), ...older].filter((d) => {
      if (seen.has(d.trace_id)) return false
      seen.add(d.trace_id)
      return true
    })
  }, [poll.data, older])

  const loadMore = useCallback(async () => {
    const last = rows[rows.length - 1]
    if (!last) return
    setLoadingMore(true)
    setMoreError(null)
    try {
      const page = await apiFetch<Decision[]>(
        `/api/v1/dashboard/decisions?tier_min=2&limit=${PAGE}&before=${encodeURIComponent(last.timestamp)}`,
      )
      const fresh = await lookupResponses(page.map((d) => d.trace_id))
      setLookups((prev) => mergeLookups(prev, fresh))
      setOlder((prev) => [...prev, ...page])
    } catch (e) {
      setMoreError(e instanceof Error ? e.message : 'No se pudo cargar más')
    } finally {
      setLoadingMore(false)
    }
  }, [rows])

  const stats = poll.data?.stats ?? null

  return (
    <section aria-labelledby="alerts-title">
      <header className="view-header">
        <h2 id="alerts-title">Alertas T2 y T3</h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>

      <dl className="counters" aria-label="Decisiones del Fast Path en los últimos 60 minutos">
        <div className="counter counter-critical"><dt>Decisiones T3, 60 min</dt><dd>{tierCount(stats, 'T3')}</dd></div>
        <div className="counter counter-high"><dt>Decisiones T2, 60 min</dt><dd>{tierCount(stats, 'T2')}</dd></div>
        <div className="counter"><dt>Decisiones totales, 60 min</dt><dd>{stats?.available ? (stats.total_decisiones ?? 0).toLocaleString('es-CL') : 'sin dato'}</dd></div>
      </dl>
      <p className="muted small mb3">
        Unidad: decisiones del Fast Path (un flujo es una decisión), no IPs distintas. Incluyen la infraestructura propia.
        IPs distintas e infraestructura propia por separado: análisis de solo lectura en reports/metricas.
      </p>

      {poll.error && <ErrorNotice message={poll.error} />}

      {poll.loading && !poll.data ? (
        <TableSkeleton cols={8} />
      ) : rows.length === 0 ? (
        <EmptyState title="No hay alertas T2 o T3 recientes">
          Si esperabas alertas, revisa que el Fast Path esté recibiendo tráfico (estado del motor).
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col"><span className="sr-only">Detalle</span></th>
                <th scope="col">Hora</th>
                <th scope="col">Tier</th>
                <th scope="col" className="num">Riesgo</th>
                <th scope="col">Origen</th>
                <th scope="col" className="num">Puerto</th>
                <th scope="col">Acción recomendada</th>
                <th scope="col">Inteligencia de amenazas</th>
                <th scope="col">trace_id</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const st = responseState(d, lookups.get(d.trace_id))
                const r = st.kind === 'ok' ? st.record : undefined
                const open = expanded === d.trace_id
                const e = r?.enrichment
                return (
                  <Fragment key={d.trace_id}>
                    <tr className={d.tier >= 3 ? 'row-critical' : undefined}>
                      <td>
                        <button
                          type="button" className="btn btn-icon"
                          aria-expanded={open} aria-label={open ? 'Ocultar detalle' : 'Ver detalle'}
                          onClick={() => setExpanded(open ? null : d.trace_id)}
                        >
                          {open ? <CaretDown size={16} aria-hidden="true" /> : <CaretRight size={16} aria-hidden="true" />}
                        </button>
                      </td>
                      <td className="mono">{formatTime(d.timestamp)}</td>
                      <td><TierBadge tier={d.tier} /></td>
                      <td className="num mono">{formatScore(d.risk_score)}</td>
                      <td className="mono">{r?.src_ip ?? e?.src_ip ?? <span className="muted">sin dato</span>}</td>
                      <td className="num mono">{d.L4_DST_PORT ?? 'sin dato'}</td>
                      <td>{r ? accionR2Label(r) : <ResponseStatus st={st} />}</td>
                      <td>{e ? <TiSummary e={e} /> : <span className="muted">No disponible</span>}</td>
                      <td className="mono" title={d.trace_id}>{shortId(d.trace_id)}</td>
                    </tr>
                    {open && (
                      <tr className="row-detail">
                        <td colSpan={9}><AlertDetail d={d} r={r} /></td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {rows.length > 0 && (
        <div className="list-footer">
          {moreError && <ErrorNotice message={moreError} />}
          <button type="button" className="btn btn-secondary" onClick={() => void loadMore()} disabled={loadingMore}>
            {loadingMore ? 'Cargando…' : 'Cargar alertas anteriores'}
          </button>
          <p className="muted small">
            Origen, acción recomendada e inteligencia de amenazas vienen del registro del worker de respuesta, buscado por el
            trace_id de cada alerta. «En proceso»: el worker todavía no la procesa. «Sin registro de respuesta»: ya pasó y
            no dejó registro. «No se pudo verificar»: la consulta falló.
          </p>
        </div>
      )}
    </section>
  )
}

function ResponseStatus({ st }: { st: ResponseState }) {
  if (st.kind === 'ok') return null
  const s = STATUS_TEXT[st.kind]
  return <span className={s.danger ? 'text-danger' : 'muted'} title={s.hint}>{s.text}</span>
}

function TiSummary({ e }: { e: NonNullable<ResponseRecord['enrichment']> }) {
  return (
    <span>
      {abuseipdbStatus(e)}, {otxStatus(e)}
      <span className="muted"> ({corroboranLabel(e.corroboration_count)})</span>
    </span>
  )
}

function AlertDetail({ d, r }: { d: Decision; r: ResponseRecord | undefined }) {
  const { user } = useAuth()
  const role = user?.role ?? 'N1'
  const load = useExplain(d.trace_id, role)
  const trace = load?.kind === 'ok' ? load.trace : null
  const e = r?.enrichment
  return (
    <div className="detail-grid">
      <dl>
        <dt>trace_id</dt><dd className="mono wrap-anywhere">{d.trace_id}</dd>
        <dt>Decisión del Fast Path</dt><dd>{d.decision}</dd>
        <dt>Score ML / anomalía</dt><dd className="mono">{formatScore(d.ml_score)} / {formatScore(d.anomaly_score)}</dd>
        <dt>Latencia</dt><dd className="mono">{typeof d.latency_ms === 'number' ? `${d.latency_ms.toFixed(1)} ms` : 'sin dato'}</dd>
        <dt>LightGBM</dt><dd className="mono">{d.model_version || 'sin dato'}<span className="muted">, hash sin dato</span></dd>
        <dt>Isolation Forest</dt><dd className="muted">versión y hash sin dato</dd>
        <dt>policy_version</dt><dd className="muted">sin dato</dd>
        <dt>regime_id</dt><dd className="muted">sin dato</dd>
        <dt>ATT&amp;CK</dt><dd>{trace ? attackText(trace.fast_path?.attack ?? trace.respuesta?.attack_alerta_correlacionada) : <span className="muted">{load ? 'cargando' : 'requiere N2'}</span>}</dd>
      </dl>
      <dl>
        <dt>DNS inverso</dt><dd className="mono wrap-anywhere">{e?.reverse_dns ?? 'sin dato'}</dd>
        <dt>País (AbuseIPDB)</dt><dd>{e?.abuseipdb_country ?? 'sin dato'}</dd>
        <dt>Reportes AbuseIPDB</dt><dd className="mono">{e?.abuseipdb_total_reports ?? 'sin dato'}</dd>
        <dt>AbuseIPDB</dt><dd>{e ? abuseipdbStatus(e) : 'sin dato'}</dd>
        <dt>OTX</dt><dd>{e ? otxStatus(e) : 'sin dato'}</dd>
        <dt>Fuentes que corroboran</dt><dd>{e?.corroborating_sources?.length ? e.corroborating_sources.join(', ') : 'ninguna'}</dd>
        <dt>CrowdSec (observacional)</dt><dd>{e?.crowdsec_observado ? (e.crowdsec_scenario ?? 'observado') : 'no observado'}</dd>
        {r?.block?.reason && (<><dt>Respuesta R2</dt><dd>{r.block.reason}</dd></>)}
      </dl>
      <ExplainPanel traceId={d.trace_id} role={role} load={load} />
      {trace && (
        <dl className="detail-chain">
          <ChainLink label="Eslabón de la decisión" v={trace.integridad.decision} />
          <ChainLink label="Eslabón de la respuesta" v={trace.integridad.respuesta} />
        </dl>
      )}
    </div>
  )
}
