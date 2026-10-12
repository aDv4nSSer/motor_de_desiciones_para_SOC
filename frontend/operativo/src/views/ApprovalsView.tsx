import { useEffect, useMemo, useRef, useState } from 'react'
import { CheckCircle, Prohibit, XCircle } from '@phosphor-icons/react'
import { resolveApproval } from '../api/approvals'
import { apiFetch } from '../api/client'
import type { Approval, ApprovalsPage } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, LevelBadge, TableSkeleton, TierBadge } from '../components/common'
import { formatScore, formatTime, requiredLevel, roleReaches, shortId } from '../lib/format'
import { groupByNet, net24Of } from '../lib/net'
import { lookupResponses, mergeLookups, type RowLookup } from '../lib/responses'
import { abuseipdbStatus, otxStatus, tiHasError } from '../lib/ti'
import { usePolling } from '../lib/usePolling'

type Decision = 'approved' | 'rejected'

const PAGE = 50
const FETCH_LIMIT = 1000 // tope del endpoint; hoy la cola real ronda las 260
/** Reintento mínimo del detalle por fuente de una aprobación sin registro: la
 *  vista refresca cada pocos segundos y no debe golpear el lookup en cada vuelta. */
const DETAIL_RETRY_MS = 60_000

interface RowState {
  confirming: Decision | null
  submitting: boolean
  message: { tone: 'danger' | 'info'; text: string } | null
}

interface Resolved {
  approval: Approval
  by: string
}

export function ApprovalsView() {
  const { user } = useAuth()
  const poll = usePolling(() => apiFetch<ApprovalsPage>(`/api/v1/dashboard/approvals?limit=${FETCH_LIMIT}`))
  const [rowState, setRowState] = useState<Record<string, RowState>>({})
  const [removed, setRemoved] = useState<Set<string>>(new Set())
  const [resolved, setResolved] = useState<Resolved[]>([])
  const [visible, setVisible] = useState(PAGE)
  const [group24, setGroup24] = useState(false)
  const [details, setDetails] = useState<Map<string, RowLookup>>(() => new Map())
  const detailsRef = useRef(details)
  const triedAt = useRef(new Map<string, number>())

  // Detalle por fuente (solo lectura, POST /responses/lookup): un único pedido por
  // lote con los trace_id VISIBLES que aún no tienen registro. Lo ya encontrado no
  // se vuelve a pedir (el enrichment de un trace_id no cambia) y lo no encontrado se
  // reintenta como máximo una vez por DETAIL_RETRY_MS. Si falla, la vista sigue igual.
  const visibleKey = useMemo(
    () => (poll.data?.items ?? []).filter((a) => a.status === 'pending' && !removed.has(a.trace_id))
      .slice(0, visible).map((a) => a.trace_id).join(','),
    [poll.data, removed, visible],
  )
  useEffect(() => {
    detailsRef.current = details
  }, [details])
  useEffect(() => {
    const now = Date.now()
    const todo = (visibleKey ? visibleKey.split(',') : [])
      .filter((id) => !detailsRef.current.get(id)?.record && now - (triedAt.current.get(id) ?? 0) >= DETAIL_RETRY_MS)
    if (todo.length === 0) return
    todo.forEach((id) => triedAt.current.set(id, now))
    let cancelled = false
    lookupResponses(todo)
      .then((fresh) => { if (!cancelled) setDetails((prev) => mergeLookups(prev, fresh)) })
      // Errores de sesión: los detecta el polling de la lista; acá solo degrada el detalle.
      .catch(() => { if (!cancelled) setDetails((prev) => mergeLookups(prev, new Map(todo.map((id) => [id,
        { complete: false, failed: true, frontierMs: null, checkedAt: now } as RowLookup])))) })
    return () => { cancelled = true }
  }, [visibleKey, poll.updatedAt])

  if (!user) return null
  const role = user.role

  const page = poll.data
  const pending = (page?.items ?? []).filter((a) => a.status === 'pending' && !removed.has(a.trace_id))
  // Total real de la cola (no el largo de la página), descontando lo resuelto en esta sesión.
  const resolvedHere = (page?.items ?? []).filter((a) => removed.has(a.trace_id)).length
  const total = page ? Math.max(page.total - resolvedHere, pending.length) : 0
  const truncated = page ? page.total > page.items.length : false
  type Entry = { header: { net: string; ips: number }; item?: never } | { header?: never; item: Approval }
  const visibleItems = pending.slice(0, visible)
  const shown: Entry[] = group24
    ? groupByNet(visibleItems, (a) => net24Of(a.src_ip) ?? 'IP sin dato / no IPv4').flatMap((g) => [
        { header: { net: g.net, ips: new Set(g.items.map((a) => a.src_ip)).size } } as Entry,
        ...g.items.map((item): Entry => ({ item })),
      ])
    : visibleItems.map((item): Entry => ({ item }))
  const state = (id: string): RowState => rowState[id] ?? { confirming: null, submitting: false, message: null }
  const patch = (id: string, p: Partial<RowState>) =>
    setRowState((prev) => ({ ...prev, [id]: { ...state(id), ...p } }))

  async function submit(a: Approval, decision: Decision) {
    patch(a.trace_id, { submitting: true, message: null })
    const outcome = await resolveApproval(a.trace_id, decision, role, a.approval_level)
    if (outcome.kind === 'done') {
      // Recién con el 200 del servidor sale de la lista de pendientes.
      setRemoved((prev) => new Set(prev).add(a.trace_id))
      setResolved((prev) => [{ approval: outcome.approval, by: user!.username }, ...prev])
      patch(a.trace_id, { submitting: false, confirming: null })
      return
    }
    patch(a.trace_id, {
      submitting: false,
      confirming: null,
      message: { tone: outcome.kind === 'conflict' || outcome.kind === 'gone' ? 'info' : 'danger', text: outcome.message },
    })
    if (outcome.kind === 'conflict' || outcome.kind === 'gone') void poll.refresh()
  }

  return (
    <section aria-labelledby="approvals-title">
      <header className="view-header">
        <h2 id="approvals-title">
          Aprobaciones pendientes{page?.available ? ` (${total})` : ''}
        </h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>
      <p className="muted view-intro">
        Aprobar ejecuta la acción en producción (bloqueo de la IP de origen). Hay una aprobación por IP: los eventos repetidos suman ocurrencias.
        Las que pasan 4 h sin resolver expiran solas. Cada aprobación exige el nivel que trae el registro; tu rol es <strong>{role}</strong>.
      </p>

      {poll.error && <ErrorNotice message={poll.error} />}
      {page && !page.available && (
        <ErrorNotice message="El motor no pudo leer la cola de aprobaciones. La lista puede estar incompleta: no la tomes como vacía." />
      )}
      {truncated && (
        <p className="notice notice-info" role="status">
          Se muestran las {page!.items.length} más recientes de {page!.total} pendientes.
        </p>
      )}

      {poll.loading && !poll.data ? (
        <TableSkeleton cols={7} />
      ) : pending.length === 0 && page?.available !== false ? (
        <EmptyState title="No hay aprobaciones pendientes">
          Las acciones de alto impacto que requieran confirmación humana aparecerán aquí.
        </EmptyState>
      ) : (
        <>
        <div className="case-filters">
          <label className="check">
            <input type="checkbox" checked={group24} onChange={(e) => setGroup24(e.target.checked)} />
            Agrupar por /24
          </label>
          {group24 && (
            <span className="muted small">Solo presentación: cada aprobación se resuelve por separado, no hay acciones en lote.</span>
          )}
        </div>
        <ul className="approval-list">
          {shown.map((entry) => {
            if (entry.header) {
              return (
                <li key={`net:${entry.header.net}`} className="approval-group">
                  <span className="mono strong">{entry.header.net}</span>
                  <span className="muted"> ({entry.header.ips} {entry.header.ips === 1 ? 'IP' : 'IPs'})</span>
                </li>
              )
            }
            const a = entry.item
            const s = state(a.trace_id)
            const allowed = roleReaches(role, a.approval_level)
            const level = requiredLevel(a.approval_level)
            return (
              <li key={a.trace_id} className="approval">
                <div className="approval-main">
                  <div className="approval-head">
                    <TierBadge tier={a.tier} />
                    <span className="mono strong">{a.src_ip ?? 'IP sin dato'}</span>
                    <LevelBadge level={level} />
                    {a.safelisted && <span className="badge sev-high">Infraestructura propia</span>}
                  </div>
                  <p className="approval-reason">{a.reason || 'Sin motivo registrado'}</p>
                  <SourceDetail lookup={details.get(a.trace_id)} />
                  <p className="muted small mono">
                    {(a.occurrences ?? 1) > 1
                      ? <>
                          <strong className="occurrences">{(a.occurrences ?? 1).toLocaleString('es-CL')} ocurrencias</strong>
                          , última {formatTime(a.last_seen_at ?? a.created_at)}, primera {formatTime(a.created_at)}
                        </>
                      : formatTime(a.created_at)}
                    , riesgo {formatScore(a.risk_score)}, trace {shortId(a.trace_id)}
                  </p>
                  {s.message && (
                    <p className={`notice notice-${s.message.tone}`} role={s.message.tone === 'danger' ? 'alert' : 'status'}>
                      {s.message.text}
                    </p>
                  )}
                </div>

                <div className="approval-actions">
                  {!allowed ? (
                    <p className="muted small">Requiere rol {level} o superior.</p>
                  ) : a.safelisted && !s.confirming ? (
                    <>
                      <p className="muted small">IP en la safelist: no se puede bloquear.</p>
                      <button type="button" className="btn btn-secondary" onClick={() => patch(a.trace_id, { confirming: 'rejected', message: null })}>
                        <Prohibit size={18} aria-hidden="true" /> Rechazar
                      </button>
                    </>
                  ) : s.confirming ? (
                    <div className="confirm" role="group" aria-label="Confirmar resolución">
                      <p className="small">
                        {s.confirming === 'approved'
                          ? <>¿Bloquear <span className="mono">{a.src_ip ?? 'esta IP'}</span> ahora?</>
                          : '¿Rechazar sin ejecutar ninguna acción?'}
                      </p>
                      <button
                        type="button"
                        className={`btn ${s.confirming === 'approved' ? 'btn-danger' : 'btn-secondary'}`}
                        disabled={s.submitting}
                        onClick={() => void submit(a, s.confirming!)}
                      >
                        {s.submitting ? 'Enviando…' : s.confirming === 'approved' ? 'Confirmar bloqueo' : 'Confirmar rechazo'}
                      </button>
                      <button type="button" className="btn btn-ghost" disabled={s.submitting} onClick={() => patch(a.trace_id, { confirming: null })}>
                        Cancelar
                      </button>
                    </div>
                  ) : (
                    <>
                      <button type="button" className="btn btn-primary" onClick={() => patch(a.trace_id, { confirming: 'approved', message: null })}>
                        <CheckCircle size={18} aria-hidden="true" /> Aprobar
                      </button>
                      <button type="button" className="btn btn-secondary" onClick={() => patch(a.trace_id, { confirming: 'rejected', message: null })}>
                        <Prohibit size={18} aria-hidden="true" /> Rechazar
                      </button>
                    </>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
        </>
      )}

      {pending.length > visible && (
        <div className="list-footer">
          <button type="button" className="btn btn-secondary" onClick={() => setVisible((v) => v + PAGE)}>
            Mostrar {Math.min(PAGE, pending.length - visible)} más de {pending.length - visible} restantes
          </button>
        </div>
      )}

      {resolved.length > 0 && (
        <section className="resolved" aria-labelledby="resolved-title">
          <h3 id="resolved-title">Resueltas en esta sesión</h3>
          <ul>
            {resolved.map(({ approval: r }) => (
              <li key={r.trace_id}>
                {r.status === 'approved'
                  ? <CheckCircle size={16} aria-hidden="true" />
                  : <XCircle size={16} aria-hidden="true" />}
                <span className="mono">{r.src_ip ?? 'IP sin dato'}</span>
                <span>{r.status === 'approved' ? 'Aprobada' : 'Rechazada'} por {r.resolved_by ?? 'ti'}, {formatTime(r.resolved_at)}</span>
                {r.status === 'approved' && (
                  <span className={r.enforced ? 'text-ok' : 'text-danger'}>
                    {r.enforced ? 'bloqueo ejecutado' : 'bloqueo NO ejecutado, revisar auditoría'}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
    </section>
  )
}

/** Estado por fuente de TI de la aprobación (R1 ya lo registró; esto solo lo muestra). */
function SourceDetail({ lookup }: { lookup: RowLookup | undefined }) {
  if (!lookup) return <p className="muted small">Consultando detalle por fuente…</p>
  const e = lookup.record?.enrichment
  if (!e) return <p className="muted small">Detalle por fuente no disponible</p>
  return (
    <p className="muted small">
      {abuseipdbStatus(e)} · {otxStatus(e)}
      {tiHasError(e) && (
        <strong className="text-danger"> · Una fuente con error NO equivale a «sin evidencia»: la consulta falló y no hay dato.</strong>
      )}
    </p>
  )
}
