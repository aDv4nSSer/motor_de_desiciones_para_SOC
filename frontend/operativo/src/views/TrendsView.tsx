import { useCallback, useState } from 'react'
import { apiFetch } from '../api/client'
import type { Trends } from '../api/types'
import { ColumnRow, HBarList, StackedColumns, TableView } from '../components/charts/Charts'
import type { Bucket, Series } from '../components/charts/Charts'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton, TierBadge } from '../components/common'
import { formatTime } from '../lib/format'
import { TIER_LABEL } from '../lib/labels'
import { usePolling } from '../lib/usePolling'

const RANGES = [
  { days: 1, label: '24 horas' },
  { days: 7, label: '7 días' },
  { days: 30, label: '30 días' },
] as const

// Acciones: verde = ejecutada, ámbar = esperando a un humano, grises = sin
// ejecución (expiró o se rechazó). Paleta de estados, no la de marca.
const ACTION_SERIES: Series[] = [
  { key: 'ejecutadas', label: 'Ejecutadas', color: 'var(--t0)' },
  { key: 'derivadas_aprobacion', label: 'Derivadas a aprobación', color: 'var(--t1)' },
  { key: 'expiradas', label: 'Expiradas sin resolver', color: 'var(--series-gray-1)' },
  { key: 'rechazadas', label: 'Rechazadas', color: 'var(--series-gray-2)' },
]

const SOURCE_LABEL: Record<string, string> = { abuseipdb: 'AbuseIPDB', otx: 'AlienVault OTX', crowdsec: 'CrowdSec' }

const hourFmt = new Intl.DateTimeFormat('es-CL', { hour: '2-digit', minute: '2-digit', hour12: false })
const dayFmt = new Intl.DateTimeFormat('es-CL', { day: '2-digit', month: '2-digit' })
const longFmt = new Intl.DateTimeFormat('es-CL', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
const dayLongFmt = new Intl.DateTimeFormat('es-CL', { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' })

function labels(iso: string, hourly: boolean): { label: string; title: string } {
  const d = new Date(iso)
  return hourly ? { label: hourFmt.format(d), title: longFmt.format(d) } : { label: dayFmt.format(d), title: dayLongFmt.format(d) }
}

function TrendsBody({ days }: { days: number }) {
  const fetcher = useCallback(() => apiFetch<Trends>(`/api/v1/dashboard/trends?days=${days}`), [days])
  const poll = usePolling(fetcher)
  const t = poll.data
  const hourly = t?.interval === '1h'

  const header = (
    <div className="toolbar"><Freshness
      updatedAt={poll.updatedAt} paused={poll.paused}
      onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
    /></div>
  )

  if (poll.loading && !t) return <>{header}<TableSkeleton rows={8} cols={6} /></>
  if (!t) return <>{header}{poll.error && <ErrorNotice message={poll.error} />}</>

  const tierBuckets = t.tiers.buckets
  const anyExcluded = tierBuckets.some((b) => b.excluded)
  const tiers = [3, 2, 1, 0] as const
  const totals = tiers.map((n) => tierBuckets.reduce((acc, b) => acc + (b.counts?.[`T${n}`] ?? 0), 0))
  const actionBuckets: Bucket<Record<string, number>>[] = t.actions.buckets.map((b) => ({
    ...labels(b.start, hourly),
    values: { ejecutadas: b.ejecutadas, derivadas_aprobacion: b.derivadas_aprobacion, expiradas: b.expiradas, rechazadas: b.rechazadas },
  }))
  const actionTotals = ACTION_SERIES.map((s) => actionBuckets.reduce((acc, b) => acc + (b.values[s.key] ?? 0), 0))
  const corr = t.corroboration
  const sources = (corr.sources ?? []).map((s) => ({ label: SOURCE_LABEL[s.source] ?? s.source, value: s.count }))

  return (
    <>
      {header}
      {poll.error && <ErrorNotice message={poll.error} />}

      <div className="panel">
        <div className="panel-head">
          <h3>Decisiones por tier</h3>
          <span className="muted small">Cada tier con su propia escala: el volumen de T0 no tapa a T3.</span>
        </div>
        <div className="panel-body">
          {!t.tiers.available ? <ErrorNotice message="OpenSearch no respondió: sin serie de tiers." /> : (
            <div className="multiples">
              {tiers.map((n, idx) => (
                <div className="multiple" key={n}>
                  <div className="name">
                    <TierBadge tier={n} />
                    <span className="mono small">{totals[idx].toLocaleString('es-CL')}</span>
                  </div>
                  <ColumnRow
                    seriesLabel={TIER_LABEL[n]} color={`var(--t${n})`} showAxis={n === 0}
                    excludedNote="Sin datos: el Fast Path no recibió tráfico (H25)."
                    buckets={tierBuckets.map((b) => ({
                      ...labels(b.start, hourly), excluded: b.excluded, values: b.counts ? b.counts[`T${n}`] : null,
                    }))}
                  />
                </div>
              ))}
            </div>
          )}
          {anyExcluded && (
            <p className="muted small mt3">
              Las franjas rayadas son el período sin ingesta de H25 ({formatTime(t.excluded_range.from)} a {formatTime(t.excluded_range.to)}):
              se muestran como sin dato, no como cero.
            </p>
          )}
          <TableView
            caption="Decisiones por tier y por intervalo"
            columns={['Intervalo', 'T3', 'T2', 'T1', 'T0']}
            rows={tierBuckets.map((b) => [labels(b.start, hourly).title,
              ...(b.counts ? [b.counts.T3, b.counts.T2, b.counts.T1, b.counts.T0] : ['sin dato', 'sin dato', 'sin dato', 'sin dato'])])}
          />
        </div>
      </div>

      <div className="chart-grid mt3">
        <div className="panel">
          <div className="panel-head">
            <h3>Acciones ejecutadas y pendientes</h3>
            {t.pending_now !== null && <span className="badge st-warn">{t.pending_now.toLocaleString('es-CL')} pendientes ahora</span>}
          </div>
          <div className="panel-body">
            {!t.actions.available ? <ErrorNotice message="OpenSearch no respondió: sin serie de acciones." />
              : actionTotals.every((v) => v === 0) ? (
                <EmptyState title="Sin acciones registradas en el período">
                  La auditoría persistida de respuestas (soc-responses) existe desde el 3 de octubre de 2026 (H39).
                </EmptyState>
              ) : (
                <StackedColumns buckets={actionBuckets} series={ACTION_SERIES} />
              )}
            <p className="muted small mt3">
              Ejecutadas: bloqueos aplicados por R2 o por aprobación humana. Derivadas: eventos que R2 dejó esperando a un operador.
            </p>
            <TableView
              caption="Acciones por intervalo"
              columns={['Intervalo', ...ACTION_SERIES.map((s) => s.label)]}
              rows={actionBuckets.map((b) => [b.title, ...ACTION_SERIES.map((s) => b.values[s.key] ?? 0)])}
            />
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><h3>Fuentes de corroboración</h3></div>
          <div className="panel-body">
            {!corr.available ? <ErrorNotice message="Redis no respondió: sin datos de corroboración." />
              : sources.length === 0 ? (
                <EmptyState title="Ninguna fuente corroboró en el período leído" />
              ) : (
                <HBarList items={sources} color="var(--series-brand)" />
              )}
            {corr.available && (
              <p className="muted small mt3">
                {corr.evaluated?.toLocaleString('es-CL')} respuestas evaluadas, {corr.sin_corroboracion?.toLocaleString('es-CL')} sin ninguna fuente.
                CrowdSec, observacional (no cuenta para el bloqueo): {corr.crowdsec_observado?.toLocaleString('es-CL')}.
                {corr.coverage_from && <> Cobertura real desde {formatTime(corr.coverage_from)}</>}
                {corr.truncated && ' (el stream conserva menos historia que el período pedido)'}.
              </p>
            )}
            {sources.length > 0 && (
              <TableView caption="Fuentes de corroboración" columns={['Fuente', 'Respuestas']} rows={sources.map((s) => [s.label, s.value])} />
            )}
          </div>
        </div>
      </div>
    </>
  )
}

export function TrendsView() {
  const [days, setDays] = useState<number>(7)
  return (
    <section aria-labelledby="trends-title">
      <header className="view-header">
        <h2 id="trends-title">Tendencias</h2>
        <div className="seg-tabs" role="group" aria-label="Período">
          {RANGES.map((r) => (
            <button key={r.days} type="button" aria-pressed={days === r.days} onClick={() => setDays(r.days)}>{r.label}</button>
          ))}
        </div>
      </header>
      <p className="view-intro">
        Volumen de decisiones por tier, respuesta efectiva y qué inteligencia de amenazas respalda las decisiones.
        Las cifras salen de las mismas cadenas auditadas que usa la vista de historial.
      </p>
      <TrendsBody key={days} days={days} />
    </section>
  )
}
