import { Fragment, useCallback, useState } from 'react'
import { CheckCircle, Info, MinusCircle, SealCheck, SealWarning, WarningCircle, XCircle } from '@phosphor-icons/react'
import type { Icon } from '@phosphor-icons/react'
import { apiFetch } from '../api/client'
import type { ApprovalsReconciliation, ChecklistItem, ChecklistStatus, ComplianceReport, CorroborationBand, CorroborationGroup, CorroborationShadow, DailyHistory, IntegrityPanel, ResponseTimings, TimingStat } from '../api/types'
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
  con_observacion: { label: 'Con observación', cls: 'st-warn', icon: WarningCircle },
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

const BAND_LABEL: Record<CorroborationBand, string> = {
  high: 'Alta (sin ambigüedad)',
  medium: 'Media',
  low: 'Baja',
  ambiguous: 'Ambigua (grupos en desacuerdo)',
}

const GROUP_LABEL: Record<CorroborationGroup, string> = {
  ml: 'ML (riesgo del modelo)',
  ti: 'Inteligencia de amenazas (AbuseIPDB, OTX)',
  signature: 'Firma Suricata (classtype, ATT&CK)',
  context: 'Contexto (recidivismo de la IP)',
}

const shadowDateFmt = new Intl.DateTimeFormat('es-CL', {
  day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'America/Santiago',
})

/** "10 oct, 20:40" en hora de Chile: el período se acordó en hora local. */
function shadowDate(iso: string): string {
  return shadowDateFmt.format(new Date(iso)).replace(/\./g, '').replace(/^(\d+) /, '$1\u00a0')
}

function n(v: number | undefined): string {
  return (v ?? 0).toLocaleString('es-CL')
}

/** Línea fija de la tarjeta de corroboración: el score no decide bloqueos.
 *  Va aparte del número principal y no depende de que haya datos.
 *  `generatedAt` (hora del reporte, del servidor) decide si el período cerró. */
function ShadowNotice({ c, generatedAt }: { c: CorroborationShadow; generatedAt: string }) {
  const end = c.validation.end
  const closed = Date.parse(generatedAt) >= Date.parse(end)
  return (
    <p className="kpi-shadow">
      <Info size={14} weight="bold" aria-hidden="true" />
      {closed
        ? `No determina bloqueos reales: validación cerrada el ${shadowDate(end)}, el gate actual sigue vigente hasta que se decida reemplazarlo.`
        : `No determina bloqueos reales: período de validación hasta el ${shadowDate(end)}.`}
    </p>
  )
}


function secs(v: number | null | undefined): string {
  if (typeof v !== 'number') return 'sin dato'
  if (v < 120) return `${v.toLocaleString('es-CL', { maximumFractionDigits: 1 })} s`
  if (v < 7200) return `${(v / 60).toLocaleString('es-CL', { maximumFractionDigits: 1 })} min`
  return `${(v / 3600).toLocaleString('es-CL', { maximumFractionDigits: 1 })} h`
}

/** Ventana, unidad, fuente, hora y enlace de cada fila medida (H57). */
function MetaLine({ item }: { item: ChecklistItem }) {
  const m = item.meta
  if (!m) return null
  return (
    <p className="muted small mt1 meta-line">
      {m.ventana}. Unidad: {m.unidad}. Fuente: {m.fuente}. Actualizado {formatTime(m.actualizado)}.{' '}
      <a href={m.registros}>Ver registros</a>
    </p>
  )
}

function CoverageHeader({ r }: { r: ComplianceReport }) {
  const s = r.resumen
  if (!s) return null
  const order: ChecklistStatus[] = ['cumple', 'con_observacion', 'parcial', 'no_cubierto']
  return (
    <section className="panel panel-pad mb3" aria-labelledby="coverage-title">
      <h3 id="coverage-title" className="mb2">Cobertura de lo que corresponde al sistema</h3>
      <p>
        {s.obligaciones_del_sistema} obligaciones atendibles por R-SOAR:{' '}
        {order.filter((k) => s.por_estado[k]).map((k) => `${s.por_estado[k]} ${CHECK[k].label.toLowerCase()}`).join(', ')}.
        {' '}{s.fuera_del_sistema} quedan fuera del sistema (gestión organizacional) y no se cuentan.
      </p>
      <p className="muted small mt1">
        Generado {formatTime(s.generado)}. Política {r.policy_version ?? 'sin dato'}; régimen {r.regime ? `${r.regime.id} (${r.regime.descripcion})` : 'sin dato'}
        {r.regimes_in_window && r.regimes_in_window.length > 1 ? `; la ventana cruza ${r.regimes_in_window.length} regímenes (${r.regimes_in_window.map((g) => g.id).join(', ')}), no comparables entre sí` : ''}.
      </p>
      {r.nota_alcance && <p className="notice notice-info mt2"><Info size={18} aria-hidden="true" /> {r.nota_alcance}</p>}
    </section>
  )
}

function IntegrityCard({ integ, fallback }: { integ?: IntegrityPanel; fallback: ComplianceReport['cadenas'] }) {
  const live = integ?.cola_en_vivo ?? fallback
  const liveOk = live.chains.responses.ok === true && live.chains.decisions.ok === true
  const liveBad = live.chains.responses.ok === false || live.chains.decisions.ok === false
  const full = integ?.completa
  const alcance = integ?.alcance ?? 'solo_cola'
  const title = liveBad ? 'Problemas de integridad en el registro'
    : alcance === 'completa' ? 'Registro de evidencia íntegro (verificación completa)'
      : liveOk ? 'Cola del registro íntegra (verificación parcial)' : 'Integridad no verificable ahora'
  return (
    <section className="panel overall" role="status" aria-labelledby="integrity-title">
      {liveBad ? <SealWarning size={28} weight="fill" className="text-danger" aria-hidden="true" />
        : liveOk ? <SealCheck size={28} weight="fill" className={alcance === 'completa' ? 'text-ok' : ''} aria-hidden="true" />
          : <Info size={28} aria-hidden="true" />}
      <div>
        <p className="big" id="integrity-title">{title}</p>
        <p className="muted small">
          Alcance: {alcance === 'completa' ? 'completa' : alcance === 'parcial' ? 'parcial' : 'solo la cola en vivo'}.
          {' '}Cola: últimos {live.tail_size.toLocaleString('es-CL')} eslabones de cada cadena, recalculados {formatTime(live.verified_at)}.
          {integ?.alcance_texto ? ` ${integ.alcance_texto.charAt(0).toUpperCase()}${integ.alcance_texto.slice(1)}.`
            : full?.available ? ` Verificación completa del ${formatTime(full.generated_at ?? '')}: ${full.ok ? 'íntegra' : 'con problemas o abortada'}.`
              : ` Verificación completa: ${full?.detail ?? 'sin informe'}.`}
        </p>
        {integ?.huecos_declarados?.gaps?.length ? (
          <>
            <p className="muted small mt1">
              Huecos declarados ({integ.huecos_declarados.gaps.length}): registros que se perdieron antes de encadenarse o rangos sin
              decisiones. La cadena no los puede detectar; se declaran en motor/audit_gaps.yaml.
            </p>
            <ul className="small gaps">
              {integ.huecos_declarados.gaps.map((g) => (
                <li key={g.id}><strong>{g.id}</strong> ({g.cadena}): {formatTime(g.desde)} a {formatTime(g.hasta)}, {g.registros}.</li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
    </section>
  )
}

function ReconciliationPanel({ rec, pendingFallback, acciones }: { rec?: ApprovalsReconciliation; pendingFallback: number | null; acciones: Record<string, number> }) {
  if (!rec?.available) {
    return <ErrorNotice message="OpenSearch no respondió: sin datos de respuesta." />
  }
  const a = rec.aprobaciones
  const c = rec.conciliacion
  const fmt = (v: number | undefined | null) => (typeof v === 'number' ? v.toLocaleString('es-CL') : 'sin dato')
  return (
    <>
      <dl className="kv">
        <dt>IPs distintas bloqueadas</dt><dd className="mono">{fmt(rec.ips_bloqueadas)}</dd>
        <dt>Acciones de bloqueo (incluye re-bloqueos al vencer el TTL)</dt><dd className="mono">{fmt(rec.acciones_de_bloqueo)}</dd>
        <dt>IPs distintas derivadas a aprobación</dt><dd className="mono">{fmt(rec.ips_derivadas)}</dd>
        <dt>Decisiones T3 derivadas</dt><dd className="mono">{fmt(rec.decisiones_t3_derivadas)}</dd>
        <dt>Aprobaciones creadas</dt><dd className="mono">{fmt(a?.creadas_en_la_ventana)}</dd>
        <dt>Recurrencias sumadas a aprobaciones abiertas</dt><dd className="mono">{fmt(a?.recurrencias)}</dd>
        <dt>Aprobadas</dt><dd className="mono">{fmt(a?.aprobadas)}</dd>
        <dt>Rechazadas</dt><dd className="mono">{fmt(a?.rechazadas)}</dd>
        <dt>Expiradas sin resolver</dt><dd className="mono">{fmt(a?.expiradas)}</dd>
        <dt>Pendientes (creadas en la ventana)</dt><dd className="mono">{fmt(a?.pendientes)}</dd>
        <dt>Casos abiertos (decisiones T2)</dt><dd className="mono">{fmt(acciones.casos_abiertos)}</dd>
      </dl>
      <p className={`notice ${c?.estado === 'no_cierra' || !c?.available ? 'notice-warn' : 'notice-info'} mt2`}>
        <Info size={18} aria-hidden="true" />{' '}
        {!c?.available ? 'Conciliación no disponible.'
          : c.estado === 'cierra' ? `La conciliación cierra: ${fmt(c.creadas_por_destino)} aprobaciones creadas por destino y por documentos; ${fmt(c.recurrencias_por_documentos)} recurrencias por documentos y por contador.`
            : c.estado === 'diferencia_explicada' ? `Diferencia explicada: ${c.causa}. Aprobaciones creadas: ${fmt(c.creadas_por_destino)} por destino y por documentos.`
              : `La conciliación NO cierra: ${c.causa}.`}
        {' '}Regla: {c?.regla ?? 'creadas = aprobadas + rechazadas + expiradas + pendientes'}.
        {a?.eventos_sin_created_at ? ` ${fmt(a.eventos_sin_created_at)} eventos anteriores a H57 sin hora de apertura no se pueden ubicar en la ventana.` : ''}
        {rec.decisiones_derivadas_sin_aprobacion ? ` ${fmt(rec.decisiones_derivadas_sin_aprobacion)} decisiones derivadas no abrieron aprobación (p. ej. eventos atrasados) y no cuentan como recurrencias.` : ''}
      </p>
      <p className="muted small mt2">
        Foto actual, sin ventana: {fmt(rec.pendientes_ahora ?? pendingFallback)} aprobaciones pendientes ahora.
        Unidades: una aprobación por IP mientras está abierta; las decisiones T3 siguientes de la misma IP se suman como recurrencias.
      </p>
    </>
  )
}

function TimingsPanel({ t }: { t?: ResponseTimings }) {
  if (!t?.available) return <p className="muted small">Tiempos no disponibles.</p>
  const row = (label: string, v?: TimingStat, note?: string) => (
    <Fragment key={label}>
      <dt>{label}</dt>
      <dd className="mono">{v && v.n ? `p50 ${secs(v.p50)}, p95 ${secs(v.p95)} (n ${v.n.toLocaleString('es-CL')})` : (v?.detalle ?? note ?? 'sin datos')}</dd>
    </Fragment>
  )
  return (
    <dl className="kv">
      {row('Detección a decisión registrada (T2 y T3)', t.deteccion_a_decision_s)}
      {row('Decisión a bloqueo automático', t.decision_a_bloqueo_s)}
      {row('Detección a bloqueo automático', t.deteccion_a_bloqueo_s)}
      {row('Apertura de la aprobación a resolución humana', t.humano_s)}
    </dl>
  )
}

function HistoryTable({ h }: { h?: DailyHistory }) {
  if (!h?.available || !h.dias?.length) return <p className="muted small">Historial no disponible.</p>
  return (
    <div className="table-wrap">
      <table className="data">
        <caption className="muted small">{h.unidad}; recalculado desde soc-responses, sin almacenamiento propio. Cada día lista los regímenes que toca.</caption>
        <thead><tr><th>Día</th><th>IPs bloqueadas</th><th>IPs derivadas</th><th>Bloqueadas / derivadas</th><th>Aprobaciones expiradas</th><th>Regímenes</th></tr></thead>
        <tbody>
          {h.dias.map((d) => (
            <tr key={d.dia}>
              <td className="mono">{d.dia}</td>
              <td className="mono">{d.ips_bloqueadas.toLocaleString('es-CL')}</td>
              <td className="mono">{d.ips_derivadas.toLocaleString('es-CL')}</td>
              <td className="mono">{d.razon_bloqueo_sobre_derivacion === null ? 'sin dato' : d.razon_bloqueo_sobre_derivacion.toLocaleString('es-CL', { maximumFractionDigits: 2 })}</td>
              <td className="mono">{d.aprobaciones_expiradas.toLocaleString('es-CL')}</td>
              <td className="mono">{d.regimenes.join(', ') || 'sin registro'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
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

  const counts = r.checklist.reduce<Record<string, number>>((acc, i) => ({ ...acc, [i.status]: (acc[i.status] ?? 0) + 1 }), {})
  const corr = r.corroboracion_sombra
  const acciones = r.respuestas.acciones ?? {}

  return (
    <>
      {toolbar}
      {poll.error && <ErrorNotice message={poll.error} />}
      <CoverageHeader r={r} />

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
          <span className="kpi-note">{r.latencia_descripcion ?? 'Fast Path.'} Promedio {ms(r.latencia_avg_ms)}. Respuesta humana: {r.tiempos?.humano_s?.n ? secs(r.tiempos.humano_s.p50) : 'sin datos'}.</span>
        </div>
        <div className="kpi">
          <dt className="kpi-head">Corroboración multi-fuente de T3 <span className="badge st-warn">modo sombra</span></dt>
          <dd>{corr.available ? pct(corr.eligible_pct) : 'sin dato'}</dd>
          <span className="kpi-note">
            {corr.available
              ? `${n(corr.eligible)} de ${n(corr.scored)} T3 ${corr.clamped ? `desde el inicio de la validación (${shadowDate(corr.from)})` : 'de la ventana'}: banda alta y sin ambigüedad, el criterio de autobloqueo si el score fuera el gate.`
              : 'OpenSearch no respondió.'}
          </span>
          <ShadowNotice c={corr} generatedAt={r.generated_at} />
        </div>
      </dl>

      <IntegrityCard integ={r.integridad} fallback={r.cadenas} />

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
                  <MetaLine item={item} />
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
          <p className="muted small mb2">Modo de respuesta: <span className="mono">{r.response_mode}</span>.</p>
          <ReconciliationPanel rec={r.conciliacion_aprobaciones} pendingFallback={r.aprobaciones_pendientes} acciones={acciones} />
          {r.respuestas.cobertura_desde && (
            <p className="muted small mt3">Registro persistido desde {formatTime(r.respuestas.cobertura_desde)} (soc-responses, H39).</p>
          )}
        </div>
        <div className="panel panel-pad">
          <h3 className="mb2">Control de acceso</h3>
          {r.indice_usuarios && !r.indice_usuarios.reliable && (
            <p className="notice notice-warn mb2"><WarningCircle size={18} aria-hidden="true" /> Usuarios y sesiones: dato no confiable ({r.indice_usuarios.reason}).</p>
          )}
          <dl className="kv">
            <dt>Operadores N1</dt><dd className="mono">{r.usuarios_por_rol?.N1 ?? 'dato no confiable'}</dd>
            <dt>Operadores N2</dt><dd className="mono">{r.usuarios_por_rol?.N2 ?? 'dato no confiable'}</dd>
            <dt>CISO / Gerencia</dt><dd className="mono">{r.usuarios_por_rol?.CISO ?? 'dato no confiable'}</dd>
            <dt>Sesiones activas</dt><dd className="mono">{r.sesiones_activas ?? 'dato no confiable'}</dd>
            <dt>Eventos de acceso</dt>
            <dd className="mono">{r.respuestas.accesos ? Object.values(r.respuestas.accesos).reduce((a, b) => a + b, 0).toLocaleString('es-CL') : 'sin dato'}</dd>
          </dl>
          <p className="muted small mt3">Reporte ANCI en PDF: {r.exportacion_pdf.detail}</p>
        </div>
      </div>

      <div className="chart-grid mt3">
        <section className="panel panel-pad" aria-labelledby="timings-title">
          <h3 id="timings-title" className="mb2">Tiempos de detección y respuesta</h3>
          <TimingsPanel t={r.tiempos} />
          <p className="muted small mt2">Ventana elegida. Medido desde el flujo que detectó Suricata; el tiempo humano se registra desde H57.</p>
        </section>
        <section className="panel panel-pad" aria-labelledby="history-title">
          <h3 id="history-title" className="mb2">Historial diario (30 días)</h3>
          <HistoryTable h={r.historial_diario} />
        </section>
      </div>

      {corr.available && corr.bands && corr.groups && (
        <section className="panel panel-pad mt3" aria-labelledby="corr-shadow-title">
          <h3 id="corr-shadow-title" className="mb2">
            Corroboración multi-fuente de T3 <span className="badge st-warn">modo sombra</span>
          </h3>
          <div className="chart-grid">
            <div>
              <p className="muted small mb2">Bandas del score, sobre {n(corr.scored)} T3 con score desde el {shadowDate(corr.from)}</p>
              <dl className="kv">
                {(Object.keys(BAND_LABEL) as CorroborationBand[]).map((b) => (
                  <Fragment key={b}>
                    <dt>{BAND_LABEL[b]}</dt>
                    <dd className="mono">{n(corr.bands?.[b])} ({pct(corr.scored ? (100 * (corr.bands?.[b] ?? 0)) / corr.scored : null)})</dd>
                  </Fragment>
                ))}
              </dl>
            </div>
            <div>
              <p className="muted small mb2">Disponibilidad de cada grupo, sobre {n(corr.groups.evaluated)} T3 con detalle por grupo</p>
              <dl className="kv">
                {(Object.keys(GROUP_LABEL) as CorroborationGroup[]).map((g) => (
                  <Fragment key={g}>
                    <dt>{GROUP_LABEL[g]}</dt>
                    <dd className="mono">{pct(corr.groups?.available_pct[g])}</dd>
                  </Fragment>
                ))}
              </dl>
            </div>
          </div>
          <p className="muted small mt3">
            {corr.clamped
              ? `Calculado desde el inicio del período de validación (${shadowDate(corr.from)}): antes, el score corrió con reglas previas (H52 y H53 sin P4) y sus bandas no son comparables. `
              : 'Calculado sobre la ventana elegida. '}
            {corr.excluded ? `${n(corr.excluded)} T3 de la ventana quedan fuera del cálculo (anteriores al período o sin score). ` : ''}
            Es informativo: el gate de R2 sigue decidiendo con el conteo de fuentes corroborantes y este score no ejecuta ni bloquea nada.
          </p>
        </section>
      )}
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
