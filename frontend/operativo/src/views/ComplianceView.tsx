import { useCallback, useState } from 'react'
import { CheckCircle, Info, MinusCircle, SealCheck, SealWarning, WarningCircle, XCircle } from '@phosphor-icons/react'
import type { Icon } from '@phosphor-icons/react'
import { apiFetch } from '../api/client'
import type { ChecklistStatus, ComplianceReport } from '../api/types'
import { ErrorNotice, Freshness, TableSkeleton } from '../components/common'
import { formatTime } from '../lib/format'
import { usePolling } from '../lib/usePolling'

const WINDOWS = [
  { minutes: 1440, label: '24 horas' },
  { minutes: 10_080, label: '7 días' },
  { minutes: 43_200, label: '30 días' },
] as const

const CHECK: Record<ChecklistStatus, { label: string; cls: string; icon: Icon }> = {
  cumple: { label: 'Con evidencia', cls: 'st-ok', icon: CheckCircle },
  parcial: { label: 'Parcial', cls: 'st-warn', icon: WarningCircle },
  no_cubierto: { label: 'No cubierto', cls: 'st-critical', icon: XCircle },
  fuera_de_alcance: { label: 'Fuera del sistema', cls: 'st-neutral', icon: MinusCircle },
}

const SOURCE_LABEL: Record<string, string> = {
  automático: 'Medido por R-SOAR',
  manual: 'Gestión organizacional',
  pendiente: 'Pendiente de implementar',
}

function pct(v: number | null | undefined): string {
  return typeof v === 'number' ? `${v.toLocaleString('es-CL', { maximumFractionDigits: 1 })} %` : 'sin dato'
}

function ms(v: number | null | undefined): string {
  return typeof v === 'number' ? `${v.toLocaleString('es-CL', { maximumFractionDigits: 1 })} ms` : 'sin dato'
}

function ComplianceBody({ minutes }: { minutes: number }) {
  const fetcher = useCallback(() => apiFetch<ComplianceReport>(`/api/v1/dashboard/compliance?window_minutes=${minutes}`), [minutes])
  const poll = usePolling(fetcher)
  const r = poll.data

  const toolbar = (
    <div className="toolbar"><Freshness
      updatedAt={poll.updatedAt} paused={poll.paused}
      onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
    /></div>
  )
  if (poll.loading && !r) return <>{toolbar}<TableSkeleton rows={6} cols={4} /></>
  if (!r) return <>{toolbar}{poll.error && <ErrorNotice message={poll.error} />}</>

  const chains = r.cadenas.chains
  const chainsOk = chains.responses.ok === true && chains.decisions.ok === true
  const chainsBad = chains.responses.ok === false || chains.decisions.ok === false
  const counts = r.checklist.reduce<Record<string, number>>((acc, i) => ({ ...acc, [i.status]: (acc[i.status] ?? 0) + 1 }), {})
  const prec = r.precision_bloqueos
  const acciones = r.respuestas.acciones ?? {}

  return (
    <>
      {toolbar}
      {poll.error && <ErrorNotice message={poll.error} />}

      <dl className="kpis" aria-label="Métricas de valor">
        <div className="kpi">
          <dt>Decisiones en la ventana</dt>
          <dd className="mono">{r.decisiones.available ? r.decisiones.total.toLocaleString('es-CL') : 'sin dato'}</dd>
          <span className="kpi-note">T3: {(r.decisiones.por_tier.T3_CRITICO ?? 0).toLocaleString('es-CL')}, T2: {(r.decisiones.por_tier.T2_MEDIO ?? 0).toLocaleString('es-CL')}</span>
        </div>
        <div className="kpi">
          <dt>Resueltas sin intervención humana</dt>
          <dd>{pct(r.fatiga_alertas_pct)}</dd>
          <span className="kpi-note">Decisiones ALLOW y LOG: carga que no llega al operador.</span>
        </div>
        <div className="kpi">
          <dt>Tiempo de decisión (p95)</dt>
          <dd>{ms(r.latencia_p95_ms)}</dd>
          <span className="kpi-note">Fast Path, promedio {ms(r.latencia_avg_ms)}. Tiempo de respuesta humana: no medido todavía.</span>
        </div>
        <div className="kpi">
          <dt>Bloqueos corroborados por AbuseIPDB</dt>
          <dd>{prec.available ? pct(prec.corroborated?.precision_pct) : 'sin dato'}</dd>
          <span className="kpi-note">
            {prec.available
              ? `${prec.corroborated?.high_score_count ?? 0} de ${prec.corroborated?.count ?? 0} con score ≥ ${prec.corroborated?.threshold ?? 40}; ${prec.uncorroborated?.count ?? 0} sin fuente disponible (aparte).`
              : 'Redis no respondió.'}
          </span>
        </div>
      </dl>

      <div className="panel overall" role="status">
        {chainsOk ? <SealCheck size={28} weight="fill" className="text-ok" aria-hidden="true" />
          : chainsBad ? <SealWarning size={28} weight="fill" className="text-danger" aria-hidden="true" />
            : <Info size={28} aria-hidden="true" />}
        <div>
          <p className="big">
            {chainsOk ? 'Registro de evidencia íntegro' : chainsBad ? 'Problemas de integridad en el registro' : 'Integridad no verificable ahora'}
          </p>
          <p className="muted small">
            Últimos {r.cadenas.tail_size.toLocaleString('es-CL')} eslabones de cada cadena recalculados {formatTime(r.cadenas.verified_at)}.
            Detalle en Historial y auditoría.
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <h3>Checklist Ley 21.663</h3>
          <div className="legend-row">
            {(Object.keys(CHECK) as ChecklistStatus[]).map((k) => counts[k] ? (
              <span key={k} className={`badge ${CHECK[k].cls}`}>{counts[k]} {CHECK[k].label.toLowerCase()}</span>
            ) : null)}
          </div>
        </div>
        <ul className="checklist">
          {r.checklist.map((item) => {
            const c = CHECK[item.status]
            const IconCmp = c.icon
            return (
              <li key={item.id}>
                <div>
                  <span className={`badge ${c.cls}`}><IconCmp size={14} weight="fill" aria-hidden="true" /> {c.label}</span>
                  <p className="art mt1">{item.article}, {SOURCE_LABEL[item.source] ?? item.source}</p>
                </div>
                <div>
                  <p className="title">{item.title}</p>
                  <p className="evidence">{item.evidence}</p>
                </div>
              </li>
            )
          })}
        </ul>
        <div className="panel-body">
          <p className="notice notice-info"><Info size={18} aria-hidden="true" /> {r.nota_legal}</p>
        </div>
      </div>

      <div className="chart-grid mt3">
        <div className="panel panel-pad">
          <h3 className="mb2">Respuesta y aprobaciones en la ventana</h3>
          {r.respuestas.available ? (
            <dl className="kv">
              <dt>Bloqueos ejecutados (automáticos)</dt><dd className="mono">{(acciones.ejecutadas_auto ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Bloqueos ejecutados (aprobación humana)</dt><dd className="mono">{(acciones.ejecutadas_manual ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Derivados a aprobación</dt><dd className="mono">{(acciones.derivadas_aprobacion ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Expirados sin resolver</dt><dd className="mono">{(acciones.expiradas ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Rechazados</dt><dd className="mono">{(acciones.rechazadas ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Casos abiertos</dt><dd className="mono">{(acciones.casos_abiertos ?? 0).toLocaleString('es-CL')}</dd>
              <dt>Pendientes ahora</dt><dd className="mono">{r.aprobaciones_pendientes?.toLocaleString('es-CL') ?? 'sin dato'}</dd>
              <dt>Modo de respuesta</dt><dd className="mono">{r.response_mode}</dd>
            </dl>
          ) : <ErrorNotice message="OpenSearch no respondió: sin datos de respuesta." />}
          {r.respuestas.cobertura_desde && (
            <p className="muted small mt3">Registro persistido desde {formatTime(r.respuestas.cobertura_desde)} (soc-responses, H39).</p>
          )}
        </div>
        <div className="panel panel-pad">
          <h3 className="mb2">Control de acceso</h3>
          <dl className="kv">
            <dt>Operadores N1</dt><dd className="mono">{r.usuarios_por_rol.N1}</dd>
            <dt>Operadores N2</dt><dd className="mono">{r.usuarios_por_rol.N2}</dd>
            <dt>CISO / Gerencia</dt><dd className="mono">{r.usuarios_por_rol.CISO}</dd>
            <dt>Sesiones activas</dt><dd className="mono">{r.sesiones_activas}</dd>
            <dt>Eventos de acceso</dt>
            <dd className="mono">{r.respuestas.accesos ? Object.values(r.respuestas.accesos).reduce((a, b) => a + b, 0).toLocaleString('es-CL') : 'sin dato'}</dd>
          </dl>
          <p className="muted small mt3">Reporte ANCI en PDF: {r.exportacion_pdf.detail}</p>
        </div>
      </div>
    </>
  )
}

export function ComplianceView() {
  const [minutes, setMinutes] = useState<number>(1440)
  return (
    <section aria-labelledby="compliance-title">
      <header className="view-header">
        <h2 id="compliance-title">Cumplimiento Ley 21.663</h2>
        <div className="seg-tabs" role="group" aria-label="Ventana">
          {WINDOWS.map((w) => (
            <button key={w.minutes} type="button" aria-pressed={minutes === w.minutes} onClick={() => setMinutes(w.minutes)}>{w.label}</button>
          ))}
        </div>
      </header>
      <p className="view-intro">
        Resumen para gerencia y auditoría: cuánto resuelve el sistema solo, qué tan rápido decide, si la evidencia
        está íntegra y qué obligaciones de la ley cubre hoy R-SOAR y cuáles quedan fuera.
      </p>
      <ComplianceBody key={minutes} minutes={minutes} />
    </section>
  )
}
