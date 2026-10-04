import { useCallback, useState } from 'react'
import type { FormEvent } from 'react'
import { CheckCircle, LinkBreak, MagnifyingGlass, Question, SealCheck, SealWarning, XCircle } from '@phosphor-icons/react'
import { ApiError, apiFetch } from '../api/client'
import type { AccessEvent, ChainStatus, ChainTail, DocVerification, TraceResult } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton, TierBadge } from '../components/common'
import { accionLabel, formatScore, formatTime } from '../lib/format'
import { ACCESS_LABEL } from '../lib/labels'
import { usePolling } from '../lib/usePolling'

const TRACE_RE = /^[A-Za-z0-9-]{8,64}$/

const EVENT_LABEL: Record<string, string> = {
  response: 'Respuesta R1/R2',
  manual_approval: 'Aprobación manual',
  approval_expired: 'Aprobación expirada',
  access: 'Evento de acceso',
  other: 'Otro evento',
  unparseable: 'Evento ilegible (persistido crudo)',
}


function short(hash: string | null | undefined, n = 16): string {
  return hash ? `${hash.slice(0, n)}…` : 'sin dato'
}

function ChainCard({ title, tail }: { title: string; tail: ChainTail }) {
  const state = !tail.available ? 'unknown' : tail.ok ? 'ok' : tail.ok === false ? 'bad' : 'unknown'
  return (
    <article className="panel chain-card" aria-labelledby={`chain-${tail.pattern}`}>
      <div className="chain-verdict">
        <span className={`seal seal-${state}`}>
          {state === 'ok' ? <SealCheck size={28} weight="fill" aria-hidden="true" />
            : state === 'bad' ? <SealWarning size={28} weight="fill" aria-hidden="true" />
              : <Question size={28} aria-hidden="true" />}
        </span>
        <div>
          <h3 id={`chain-${tail.pattern}`} className="muted small">{title}</h3>
          <p className="verdict">
            {state === 'ok' ? 'Cadena verificada ✓' : state === 'bad' ? 'Cadena con problemas' : 'No se pudo verificar'}
          </p>
        </div>
      </div>
      {tail.available && tail.verified > 0 && (
        <p className="small">
          {tail.verified.toLocaleString('es-CL')} eslabones recalculados, chain_seq {tail.from_seq?.toLocaleString('es-CL')} a {tail.to_seq?.toLocaleString('es-CL')}
          {typeof tail.duration_ms === 'number' && <span className="muted"> ({Math.round(tail.duration_ms)} ms)</span>}
        </p>
      )}
      {tail.available && tail.verified === 0 && <p className="small muted">La cadena no tiene documentos todavía.</p>}
      {!tail.available && <p className="small muted">OpenSearch no respondió. Esto no indica que la cadena esté alterada.</p>}
      <dl className="kv">
        <dt>Índices</dt><dd className="mono">{tail.pattern}</dd>
        <dt>Cabeza</dt><dd className="hash" title={tail.head_hash ?? undefined}>{short(tail.head_hash, 24)}</dd>
        <dt>Último evento</dt><dd className="mono">{tail.head_time ? formatTime(tail.head_time) : 'sin dato'}</dd>
        {tail.cutover && (
          <>
            <dt>Empalme</dt>
            <dd className="small">
              chain_seq 1 apunta a la cabeza de <span className="mono">{tail.cutover.legacy_index}</span>{' '}
              (<span className="hash">{short(tail.cutover.prev_hash)}</span>), corte {formatTime(tail.cutover.cutover_at)}
            </dd>
          </>
        )}
      </dl>
      {tail.problems.length > 0 && (
        <ul className="notice notice-danger" role="alert">
          {tail.problems.map((p) => <li key={p} className="mono">{p}</li>)}
        </ul>
      )}
    </article>
  )
}

function Check({ ok, label }: { ok: boolean | null; label: string }) {
  if (ok === null) return <span className="badge st-neutral"><Question size={14} aria-hidden="true" /> {label}: sin vecino</span>
  return ok
    ? <span className="badge st-ok"><CheckCircle size={14} weight="fill" aria-hidden="true" /> {label}</span>
    : <span className="badge st-critical">{label === 'Contenido íntegro' ? <XCircle size={14} weight="fill" aria-hidden="true" /> : <LinkBreak size={14} aria-hidden="true" />} {label}: NO coincide</span>
}

function Verification({ v }: { v: DocVerification }) {
  return (
    <div className="verify-line">
      <Check ok={v.content_ok} label="Contenido íntegro" />
      {v.chain_seq !== null && <Check ok={v.prev_link_ok} label="Enlace con el anterior" />}
      {v.chain_seq !== null && <Check ok={v.next_link_ok} label="Enlace con el siguiente" />}
      <span className="hash">{v.chain_seq !== null ? `chain_seq ${v.chain_seq}, ` : ''}hash {short(v.hash)}</span>
      {v.note && <span className="muted small">{v.note}</span>}
    </div>
  )
}

function eventSummary(doc: Record<string, unknown>): string {
  const type = String(doc.event_type ?? '')
  if (type === 'response') {
    const parts = [accionLabel(doc.accion_recomendada as string | undefined)]
    if (doc.block_reason) parts.push(String(doc.block_reason))
    if (doc.block_enforced === true) parts.push('bloqueo ejecutado')
    return parts.join('. ')
  }
  if (type === 'manual_approval') return `Aprobada por ${doc.username ?? 'sin dato'} (${doc.approver_role ?? '?'}), bloqueo ${doc.block_enforced ? 'ejecutado' : 'NO ejecutado'}`
  if (type === 'approval_expired') return 'Pasó el plazo sin resolución humana'
  if (type === 'access') return `${ACCESS_LABEL[String(doc.access_event)] ?? doc.access_event} por ${doc.username ?? 'sin dato'}`
  return ''
}

function TraceSearch({ isCiso }: { isCiso: boolean }) {
  const [input, setInput] = useState('')
  const [result, setResult] = useState<TraceResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const invalid = input.trim() !== '' && !TRACE_RE.test(input.trim())

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const tid = input.trim()
    if (!TRACE_RE.test(tid)) return
    setLoading(true)
    setError(null)
    try {
      setResult(await apiFetch<TraceResult>(`/api/v1/dashboard/audit/trace/${encodeURIComponent(tid)}`))
    } catch (err) {
      setResult(null)
      setError(err instanceof ApiError ? (err.detail || `HTTP ${err.status}`) : 'No se pudo consultar el historial.')
    } finally {
      setLoading(false)
    }
  }

  const empty = result && result.decisions.length === 0 && result.events.length === 0

  return (
    <>
      <form className="search-bar" onSubmit={onSubmit} role="search">
        <div className="field">
          <label htmlFor="trace">Buscar por trace_id</label>
          <input
            id="trace" className="mono" value={input} onChange={(e) => setInput(e.target.value)}
            placeholder="9291e87d-a84d-4e61-b429-8f9207fd401b" aria-invalid={invalid}
            aria-describedby="trace-hint" spellCheck={false} autoComplete="off"
          />
        </div>
        <button type="submit" className="btn btn-primary btn-lg" disabled={loading || invalid || input.trim() === ''}>
          <MagnifyingGlass size={18} aria-hidden="true" /> {loading ? 'Buscando…' : 'Buscar'}
        </button>
      </form>
      <p id="trace-hint" className={`hint small search-hint ${invalid ? 'text-danger' : 'muted'}`}>
        {invalid ? 'Formato inválido: letras, números y guiones (8 a 64).' : 'Reconstruye la decisión y todo lo que el sistema hizo con ella.'}
      </p>

      {error && <ErrorNotice message={error} />}
      {result && !result.available && (
        <ErrorNotice message="OpenSearch no respondió por completo: el resultado puede estar incompleto." />
      )}
      {empty && (
        <EmptyState title="Sin registros para ese trace_id">
          Revisa el identificador. Las decisiones T0 sin respuesta R1/R2 solo aparecen en la cadena de decisiones.
        </EmptyState>
      )}

      {result && !empty && (
        <div className="panel">
          <div className="panel-head">
            <h3>Registro de <span className="mono">{result.trace_id}</span></h3>
            {result.scope === 'partial' && <span className="badge badge-outline">Vista parcial (N2)</span>}
          </div>
          <ol className="timeline">
            {result.decisions.map(({ chain, doc, verification }) => (
              <li key={`d-${chain}`}>
                <div>
                  <p className="strong">Decisión del Fast Path</p>
                  <p className="mono small">{formatTime(doc.timestamp as string)}</p>
                  <p className="muted small">{chain}</p>
                </div>
                <div>
                  <p>
                    <TierBadge tier={Number(doc.tier ?? 0)} /> {String(doc.decision ?? '')}, riesgo {formatScore(doc.risk_score as number)},
                    puerto <span className="mono">{String(doc.L4_DST_PORT ?? 'sin dato')}</span>, modelo <span className="mono">{String(doc.model_version ?? 'sin dato')}</span>
                  </p>
                  <Verification v={verification} />
                </div>
              </li>
            ))}
            {result.events.map(({ doc, verification }) => (
              <li key={`e-${verification.chain_seq ?? String(doc.stream_id)}`}>
                <div>
                  <p className="strong">{EVENT_LABEL[String(doc.event_type)] ?? String(doc.event_type)}</p>
                  <p className="mono small">{formatTime(doc.event_time as string)}</p>
                  <p className="muted small">soc-responses-*</p>
                </div>
                <div>
                  <p>{eventSummary(doc)}{doc.src_ip ? <>, origen <span className="mono">{String(doc.src_ip)}</span></> : null}</p>
                  <Verification v={verification} />
                </div>
              </li>
            ))}
          </ol>
          {result.hidden_events > 0 && !isCiso && (
            <p className="panel-body muted small">
              {result.hidden_events} eventos de control de acceso de este trace_id son visibles solo para el CISO.
            </p>
          )}
        </div>
      )}
    </>
  )
}

function AccessLog() {
  const [username, setUsername] = useState('')
  const [filter, setFilter] = useState('')
  const fetcher = useCallback(
    () => apiFetch<{ available: boolean; items: AccessEvent[] }>(
      `/api/v1/dashboard/audit/access?limit=100${filter ? `&username=${encodeURIComponent(filter)}` : ''}`),
    [filter],
  )
  const poll = usePolling(fetcher)
  const items = poll.data?.items ?? []

  return (
    <>
      <div className="section-title">
        <h3>Bitácora de accesos</h3>
        <span className="muted small">Persistida con hash-chain en soc-responses-*; solo CISO.</span>
      </div>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); setFilter(username.trim()) }}>
        <label className="sr-only" htmlFor="acc-user">Filtrar por usuario</label>
        <input id="acc-user" className="input" placeholder="Filtrar por usuario" value={username}
               onChange={(e) => setUsername(e.target.value)} pattern="[A-Za-z0-9._\-]*" />
        <button type="submit" className="btn btn-secondary btn-sm">Filtrar</button>
        {filter && <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setUsername(''); setFilter('') }}>Quitar filtro</button>}
      </form>
      {poll.error && <ErrorNotice message={poll.error} />}
      {poll.data && !poll.data.available && <ErrorNotice message="OpenSearch no respondió: la bitácora no está disponible ahora." />}
      {poll.loading && !poll.data ? <TableSkeleton cols={5} /> : items.length === 0 ? (
        <EmptyState title="Sin eventos de acceso">{filter ? 'No hay eventos para ese usuario.' : 'Todavía no hay eventos persistidos.'}</EmptyState>
      ) : (
        <div className="table-wrap mt3">
          <table className="data">
            <thead>
              <tr><th scope="col">Hora</th><th scope="col">Usuario</th><th scope="col">Evento</th><th scope="col">Detalle</th><th scope="col">chain_seq</th></tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.chain_seq ?? `${e.event_time}-${e.access_event}`}>
                  <td className="mono">{formatTime(e.event_time)}</td>
                  <td className="mono">{e.username ?? 'sin dato'}</td>
                  <td>{ACCESS_LABEL[e.access_event ?? ''] ?? e.access_event}</td>
                  <td className="small muted wrap-anywhere">
                    {Object.entries(e.detail).filter(([k]) => k !== 'jti').map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`).join(', ') || 'sin detalle'}
                  </td>
                  <td className="mono num">{e.chain_seq?.toLocaleString('es-CL') ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

export function AuditView() {
  const { user } = useAuth()
  const poll = usePolling(() => apiFetch<ChainStatus>('/api/v1/dashboard/audit/chain'))
  if (!user) return null
  const isCiso = user.role === 'CISO'
  const chains = poll.data?.chains

  return (
    <section aria-labelledby="audit-title">
      <header className="view-header">
        <h2 id="audit-title">Historial y auditoría</h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>
      <p className="view-intro">
        Las decisiones y las respuestas se guardan en cadenas de hashes append-only: cada registro incluye el hash
        del anterior. Aquí se recalculan en vivo los últimos {poll.data?.tail_size.toLocaleString('es-CL') ?? '2.000'} eslabones
        de cada cadena; la verificación completa se corre en el servidor con <span className="mono">verify_response_chain.py</span>.
        {!isCiso && ' Como N2 ves el historial operativo; la bitácora de accesos es exclusiva del CISO.'}
      </p>

      {poll.error && <ErrorNotice message={poll.error} />}
      {poll.loading && !chains ? <TableSkeleton rows={3} cols={3} /> : chains && (
        <div className="chain-row">
          <ChainCard title="Decisiones del Fast Path" tail={chains.decisions} />
          <ChainCard title="Respuestas, aprobaciones y accesos" tail={chains.responses} />
        </div>
      )}

      <TraceSearch isCiso={isCiso} />
      {isCiso && <AccessLog />}
    </section>
  )
}
