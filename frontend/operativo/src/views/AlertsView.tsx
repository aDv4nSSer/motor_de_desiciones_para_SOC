import { Fragment, useCallback, useMemo, useState } from 'react'
import { CaretDown, CaretRight } from '@phosphor-icons/react'
import { apiFetch } from '../api/client'
import type { Decision, ResponseRecord, Stats } from '../api/types'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton, TierBadge } from '../components/common'
import { accionLabel, formatScore, formatTime, shortId } from '../lib/format'
import { indexResponses } from '../lib/responses'
import { usePolling } from '../lib/usePolling'

const PAGE = 50
const RESPONSES_WINDOW = 200 // tope del endpoint /blocks/recent

interface AlertsData {
  decisions: Decision[]
  responses: Map<string, ResponseRecord>
  stats: Stats | null
}

async function fetchAlerts(): Promise<AlertsData> {
  const [decisions, responses, stats] = await Promise.all([
    apiFetch<Decision[]>(`/api/v1/dashboard/decisions?tier_min=2&limit=${PAGE}`),
    apiFetch<ResponseRecord[]>(`/api/v1/dashboard/blocks/recent?limit=${RESPONSES_WINDOW}`),
    apiFetch<Stats>('/api/v1/dashboard/stats?window_minutes=60').catch(() => null),
  ])
  return { decisions, responses: indexResponses(responses), stats }
}

function tierCount(stats: Stats | null, prefix: string): string {
  if (!stats?.available || !stats.por_tier) return 'sin dato'
  const entry = Object.entries(stats.por_tier).find(([k]) => k.startsWith(prefix))
  return entry ? entry[1].toLocaleString('es-CL') : '0'
}

export function AlertsView() {
  const poll = usePolling(fetchAlerts)
  const [older, setOlder] = useState<Decision[]>([])
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
      setOlder((prev) => [...prev, ...page])
    } catch (e) {
      setMoreError(e instanceof Error ? e.message : 'No se pudo cargar más')
    } finally {
      setLoadingMore(false)
    }
  }, [rows])

  const responses = poll.data?.responses ?? new Map<string, ResponseRecord>()
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

      <dl className="counters" aria-label="Decisiones en los últimos 60 minutos">
        <div className="counter counter-critical"><dt>T3 crítico, 60 min</dt><dd>{tierCount(stats, 'T3')}</dd></div>
        <div className="counter counter-high"><dt>T2 medio, 60 min</dt><dd>{tierCount(stats, 'T2')}</dd></div>
        <div className="counter"><dt>Total decisiones, 60 min</dt><dd>{stats?.available ? (stats.total_decisiones ?? 0).toLocaleString('es-CL') : 'sin dato'}</dd></div>
      </dl>

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
                const r = responses.get(d.trace_id)
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
                      <td>{r ? accionLabel(r.accion_recomendada) : <span className="muted">Sin respuesta en ventana</span>}</td>
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
            La acción recomendada y la inteligencia de amenazas vienen del worker de respuesta (últimas {RESPONSES_WINDOW} respuestas).
            Las alertas fuera de esa ventana o aún no procesadas aparecen sin esos datos.
          </p>
        </div>
      )}
    </section>
  )
}

function TiSummary({ e }: { e: NonNullable<ResponseRecord['enrichment']> }) {
  const parts: string[] = []
  if (e.abuseipdb_available === false) parts.push('AbuseIPDB no disponible')
  else if (typeof e.abuseipdb_score === 'number') parts.push(`AbuseIPDB ${e.abuseipdb_score}`)
  if (e.otx_available === false) parts.push('OTX no disponible')
  else if (typeof e.otx_pulse_count === 'number') parts.push(`OTX ${e.otx_pulse_count} pulsos`)
  return (
    <span>
      {parts.join(', ') || 'Sin señales'}
      <span className="muted"> ({e.corroboration_count ?? 0} fuentes corroboran)</span>
    </span>
  )
}

function AlertDetail({ d, r }: { d: Decision; r: ResponseRecord | undefined }) {
  const e = r?.enrichment
  return (
    <div className="detail-grid">
      <dl>
        <dt>trace_id</dt><dd className="mono wrap-anywhere">{d.trace_id}</dd>
        <dt>Decisión del Fast Path</dt><dd>{d.decision}</dd>
        <dt>Score ML / anomalía</dt><dd className="mono">{formatScore(d.ml_score)} / {formatScore(d.anomaly_score)}</dd>
        <dt>Latencia</dt><dd className="mono">{typeof d.latency_ms === 'number' ? `${d.latency_ms.toFixed(1)} ms` : 'sin dato'}</dd>
        <dt>Modelo</dt><dd className="mono">{d.model_version ?? 'sin dato'}</dd>
      </dl>
      <dl>
        <dt>DNS inverso</dt><dd className="mono wrap-anywhere">{e?.reverse_dns ?? 'sin dato'}</dd>
        <dt>País (AbuseIPDB)</dt><dd>{e?.abuseipdb_country ?? 'sin dato'}</dd>
        <dt>Reportes AbuseIPDB</dt><dd className="mono">{e?.abuseipdb_total_reports ?? 'sin dato'}</dd>
        <dt>Fuentes que corroboran</dt><dd>{e?.corroborating_sources?.length ? e.corroborating_sources.join(', ') : 'ninguna'}</dd>
        <dt>CrowdSec (observacional)</dt><dd>{e?.crowdsec_observado ? (e.crowdsec_scenario ?? 'observado') : 'no observado'}</dd>
        {r?.block?.reason && (<><dt>Respuesta R2</dt><dd>{r.block.reason}</dd></>)}
      </dl>
      <div className="detail-note">
        <p className="detail-label">Reglas y razonamiento</p>
        <p className="muted">No disponible todavía: el motor de reglas (rules.yaml) no está implementado, así que esta decisión no trae rules_fired ni reasoning.</p>
      </div>
    </div>
  )
}
