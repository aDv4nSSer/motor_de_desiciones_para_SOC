import { Fragment, useCallback, useMemo, useRef, useState } from 'react'
import { CaretDown, CaretRight, DownloadSimple } from '@phosphor-icons/react'
import { CASES_PAGE, downloadClosuresCsv, fetchCasesPage, updateCaseState, type CaseFilters } from '../api/cases'
import type { Case, CasesPage, CaseState, ResponseRecord, Role } from '../api/types'
import { ROLE_LEVEL } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton, TierBadge } from '../components/common'
import { ChainLink, ExplainPanel } from '../components/ExplainPanel'
import { CASE_STATE_LABEL, caseTier } from '../lib/cases'
import { attackText, useExplain } from '../lib/explain'
import { formatScore, formatTime, shortId } from '../lib/format'
import { accionR2Label } from '../lib/r2'
import { lookupResponses, mergeLookups, type RowLookup } from '../lib/responses'
import { abuseipdbStatus, corroboranLabel, otxStatus } from '../lib/ti'
import { groupByNet } from '../lib/net'
import { usePolling } from '../lib/usePolling'

const STATE_CLASS: Record<CaseState, string> = {
  abierto: 'st-warn',
  en_investigacion: 'st-serious',
  cerrado_confirmado: 'st-neutral',
  cerrado_falso_positivo: 'st-neutral',
}

const STATE_FILTERS: { value: CaseFilters['state']; label: string }[] = [
  { value: 'abierto', label: 'Abiertos' },
  { value: 'en_investigacion', label: 'En investigación' },
  { value: 'cerrado_confirmado', label: 'Confirmados' },
  { value: 'cerrado_falso_positivo', label: 'Falsos positivos' },
  { value: 'todos', label: 'Todos' },
]

const WINDOWS: { value: number | null; label: string }[] = [
  { value: 24, label: '24 h' },
  { value: 72, label: '72 h' },
  { value: null, label: '7 días' },
]

/** Transiciones que ofrece la UI; las mismas que valida el backend
 *  (dashboard.CASE_TRANSITIONS y CASE_TARGET_MIN_ROLE). Esto es UX: el
 *  servidor rechaza con 403 o 409 aunque la UI se saltee. */
const ACTIONS: Record<CaseState, { to: CaseState; label: string; minRole: Role; noteRequired: boolean }[]> = {
  abierto: [
    { to: 'en_investigacion', label: 'Pasar a investigación', minRole: 'N1', noteRequired: false },
    { to: 'cerrado_confirmado', label: 'Cerrar como confirmado', minRole: 'N2', noteRequired: true },
    { to: 'cerrado_falso_positivo', label: 'Cerrar como falso positivo', minRole: 'N2', noteRequired: true },
  ],
  en_investigacion: [
    { to: 'cerrado_confirmado', label: 'Cerrar como confirmado', minRole: 'N2', noteRequired: true },
    { to: 'cerrado_falso_positivo', label: 'Cerrar como falso positivo', minRole: 'N2', noteRequired: true },
  ],
  cerrado_confirmado: [],
  cerrado_falso_positivo: [],
}

const NOTE_MIN = 3

function lastSeen(c: Case): string | undefined {
  return c.last_seen ?? c.updated_at ?? c.opened_at
}

function filtersKey(f: CaseFilters): string {
  return `${f.state}|${f.publicOnly}|${f.sinceHours ?? 'all'}`
}

interface CasesData {
  key: string
  page: CasesPage
}

export function CasesView() {
  const { user } = useAuth()
  const role: Role = user?.role ?? 'N1'
  const [filters, setFilters] = useState<CaseFilters>({ state: 'abierto', publicOnly: true, sinceHours: null })
  const filtersRef = useRef(filters)
  const [older, setOlder] = useState<{ key: string; items: Case[]; next: number | null }>({ key: '', items: [], next: null })
  const [lookups, setLookups] = useState<Map<string, RowLookup>>(() => new Map())
  const [updated, setUpdated] = useState<Map<string, Case>>(() => new Map())
  const [expanded, setExpanded] = useState<string | null>(null)
  const [group24, setGroup24] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [moreError, setMoreError] = useState<string | null>(null)
  const [csvError, setCsvError] = useState<string | null>(null)

  const resolveTi = useCallback(async (cases: Case[]) => {
    const ids = cases.map((c) => c.detail?.trace_id).filter((t): t is string => !!t)
    if (ids.length === 0) return
    const fresh = await lookupResponses(ids)
    setLookups((prev) => mergeLookups(prev, fresh))
  }, [])

  const fetchFirst = useCallback(async (): Promise<CasesData> => {
    const f = filtersRef.current
    const page = await fetchCasesPage(f)
    await resolveTi(page.items)
    return { key: filtersKey(f), page }
  }, [resolveTi])

  const poll = usePolling(fetchFirst)
  const key = filtersKey(filters)
  const first = poll.data?.key === key ? poll.data.page : null

  function changeFilters(next: CaseFilters) {
    filtersRef.current = next
    setFilters(next)
    setOlder({ key: filtersKey(next), items: [], next: null })
    setExpanded(null)
    void poll.refresh()
  }

  const rows = useMemo(() => {
    const seen = new Set<string>()
    const extra = older.key === key ? older.items : []
    return [...(first?.items ?? []), ...extra]
      .filter((c) => (seen.has(c.case_id) ? false : (seen.add(c.case_id), true)))
      .map((c) => updated.get(c.case_id) ?? c)
  }, [first, older, key, updated])

  const nextCursor = older.key === key && older.items.length > 0 ? older.next : first?.next_cursor ?? null

  async function loadMore() {
    if (nextCursor === null) return
    setLoadingMore(true)
    setMoreError(null)
    try {
      const page = await fetchCasesPage(filtersRef.current, nextCursor)
      await resolveTi(page.items)
      const k = filtersKey(filtersRef.current)
      setOlder((prev) => ({ key: k, items: prev.key === k ? [...prev.items, ...page.items] : page.items, next: page.next_cursor }))
    } catch (e) {
      setMoreError(e instanceof Error ? e.message : 'No se pudo cargar más')
    } finally {
      setLoadingMore(false)
    }
  }

  async function exportCsv() {
    setCsvError(null)
    try {
      await downloadClosuresCsv()
    } catch (e) {
      setCsvError(e instanceof Error ? e.message : 'No se pudo exportar')
    }
  }

  const onUpdated = (c: Case) => setUpdated((prev) => new Map(prev).set(c.case_id, c))
  const canExport = ROLE_LEVEL[role] >= ROLE_LEVEL.N2
  const groups = useMemo(() => groupBy24(rows), [rows])

  return (
    <section aria-labelledby="cases-title">
      <header className="view-header">
        <h2 id="cases-title">Gestión interna de casos</h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        >
          {canExport && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => void exportCsv()}>
              <DownloadSimple size={16} aria-hidden="true" /> Exportar cierres (CSV)
            </button>
          )}
        </Freshness>
      </header>
      <p className="muted view-intro">
        Un caso nace de una alerta T2 de una IP no propia y agrupa sus repeticiones durante 24 h. N1 pasa un caso a
        investigación; N2 y CISO lo cierran como confirmado o falso positivo, con nota obligatoria. Tu rol es <strong>{role}</strong>.
      </p>
      <p className="muted small mb3">
        Mientras un caso está en investigación, las nuevas ocurrencias de la IP abren casos nuevos.
      </p>

      <div className="case-filters" role="group" aria-label="Filtros de casos">
        <div className="seg-tabs" role="group" aria-label="Estado">
          {STATE_FILTERS.map((s) => (
            <button key={s.value} type="button" aria-pressed={filters.state === s.value}
              onClick={() => changeFilters({ ...filters, state: s.value })}>{s.label}</button>
          ))}
        </div>
        <div className="seg-tabs" role="group" aria-label="Ventana de actividad">
          {WINDOWS.map((w) => (
            <button key={w.label} type="button" aria-pressed={filters.sinceHours === w.value}
              onClick={() => changeFilters({ ...filters, sinceHours: w.value })}>{w.label}</button>
          ))}
        </div>
        <label className="check">
          <input type="checkbox" checked={filters.publicOnly}
            onChange={(e) => changeFilters({ ...filters, publicOnly: e.target.checked })} />
          Solo IPs públicas
        </label>
        <label className="check">
          <input type="checkbox" checked={group24} onChange={(e) => setGroup24(e.target.checked)} />
          Agrupar por /24
        </label>
      </div>

      {poll.error && <ErrorNotice message={poll.error} />}
      {csvError && <ErrorNotice message={`No se pudo exportar: ${csvError}`} />}
      {first && !first.available && (
        <ErrorNotice message="El motor no pudo leer los casos de Redis. La lista puede estar incompleta: no la tomes como vacía." />
      )}

      {poll.loading && !first ? (
        <TableSkeleton cols={9} />
      ) : rows.length === 0 && first?.available !== false ? (
        <EmptyState title="No hay casos con estos filtros">
          {first?.scan_cap_reached
            ? 'Se revisaron los 2.000 casos más recientes del índice sin coincidencias: usa "Cargar más" para seguir.'
            : 'Prueba con otro estado o una ventana más amplia.'}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col"><span className="sr-only">Detalle</span></th>
                <th scope="col">{group24 ? 'Red /24' : 'IP'}</th>
                <th scope="col">Tier</th>
                <th scope="col" className="num">Riesgo</th>
                <th scope="col">Primera vez</th>
                <th scope="col">Última vez</th>
                <th scope="col" className="num">Ocurrencias</th>
                <th scope="col">Estado</th>
                <th scope="col">Fuentes de TI</th>
                <th scope="col">trace_id</th>
              </tr>
            </thead>
            <tbody>
              {group24
                ? groups.map((g) => (
                  <GroupRows key={g.net} net={g.net} cases={g.cases} lookups={lookups} role={role}
                    expanded={expanded} setExpanded={setExpanded} onUpdated={onUpdated} />
                ))
                : rows.map((c) => (
                  <CaseRow key={c.case_id} c={c} lookups={lookups} role={role}
                    open={expanded === c.case_id} toggle={() => setExpanded(expanded === c.case_id ? null : c.case_id)}
                    onUpdated={onUpdated} />
                ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="list-footer">
        {moreError && <ErrorNotice message={moreError} />}
        {nextCursor !== null && (
          <button type="button" className="btn btn-secondary" onClick={() => void loadMore()} disabled={loadingMore}>
            {loadingMore ? 'Cargando…' : `Cargar ${CASES_PAGE} más`}
          </button>
        )}
        <p className="muted small">
          {first?.index_size != null && <>Índice {first.source === 'worked' ? 'de casos trabajados' : 'de casos recientes'}: {first.index_size.toLocaleString('es-CL')} casos. </>}
          Orden: última actividad. Cada consulta lee a lo sumo 2.000 casos del índice, nunca el índice completo.
          Fuentes de TI desde el registro de respuesta del trace_id con que se abrió el caso.
        </p>
        <p className="muted small">
          Auditoría: cada cambio de estado queda en la cadena hash (actor, caso, estados y huella de la nota); el texto de la
          nota queda solo en el caso. Limitaciones declaradas: mientras un caso está en investigación, las repeticiones de
          esa IP abren un caso nuevo; y si el worker suma una ocurrencia en el mismo instante de un cambio de estado,
          puede revertirlo (se resuelve del lado del worker, después del período 2).
        </p>
      </div>
    </section>
  )
}

function groupBy24(rows: Case[]): { net: string; cases: Case[] }[] {
  return groupByNet(rows, (c) => c.net24 ?? c.host).map((g) => ({ net: g.net, cases: g.items }))
}

function sourcesOf(r: ResponseRecord | undefined): string {
  if (!r) return 'sin dato'
  const s = r.enrichment?.corroborating_sources
  return s && s.length ? s.join(', ') : 'ninguna'
}

interface RowProps {
  c: Case
  lookups: Map<string, RowLookup>
  role: Role
  open: boolean
  toggle: () => void
  onUpdated: (c: Case) => void
}

function CaseRow({ c, lookups, role, open, toggle, onUpdated }: RowProps) {
  const tid = c.detail?.trace_id
  const rec = tid ? lookups.get(tid)?.record : undefined
  const tier = caseTier(c)
  return (
    <>
      <tr>
        <td>
          <button type="button" className="btn btn-icon" aria-expanded={open}
            aria-label={open ? 'Ocultar caso' : 'Ver caso'} onClick={toggle}>
            {open ? <CaretDown size={16} aria-hidden="true" /> : <CaretRight size={16} aria-hidden="true" />}
          </button>
        </td>
        <td className="mono">{c.host}</td>
        <td>{tier !== null ? <TierBadge tier={tier} /> : <span className="muted">sin dato</span>}</td>
        <td className="num mono">{formatScore(c.detail?.risk_score)}</td>
        <td className="mono nowrap">{formatTime(c.opened_at)}</td>
        <td className="mono nowrap">{formatTime(lastSeen(c))}</td>
        <td className="num mono">{(c.occurrences ?? 1).toLocaleString('es-CL')}</td>
        <td><span className={`badge ${STATE_CLASS[c.state] ?? 'st-neutral'}`}>{CASE_STATE_LABEL[c.state] ?? c.state}</span></td>
        <td>{sourcesOf(rec)}</td>
        <td className="mono" title={tid}>{tid ? shortId(tid) : 'sin dato'}</td>
      </tr>
      {open && (
        <tr className="row-detail">
          <td colSpan={10}><CaseDetail key={c.case_id} c={c} rec={rec} role={role} onUpdated={onUpdated} /></td>
        </tr>
      )}
    </>
  )
}

interface GroupProps {
  net: string
  cases: Case[]
  lookups: Map<string, RowLookup>
  role: Role
  expanded: string | null
  setExpanded: (id: string | null) => void
  onUpdated: (c: Case) => void
}

function GroupRows({ net, cases, lookups, role, expanded, setExpanded, onUpdated }: GroupProps) {
  const gid = `net:${net}`
  const open = expanded === gid || cases.some((c) => c.case_id === expanded)
  const occ = cases.reduce((n, c) => n + (c.occurrences ?? 1), 0)
  const risk = Math.max(...cases.map((c) => c.detail?.risk_score ?? 0))
  const firstAt = cases.map((c) => c.opened_at).sort()[0]
  const lastAt = cases.map((c) => lastSeen(c) ?? '').sort().at(-1)
  const states = [...new Set(cases.map((c) => CASE_STATE_LABEL[c.state] ?? c.state))].join(', ')
  const sources = [...new Set(cases.flatMap((c) => {
    const r = c.detail?.trace_id ? lookups.get(c.detail.trace_id)?.record : undefined
    return r?.enrichment?.corroborating_sources ?? []
  }))]
  const ips = new Set(cases.map((c) => c.host)).size
  return (
    <Fragment>
      <tr className="row-group">
        <td>
          <button type="button" className="btn btn-icon" aria-expanded={open}
            aria-label={open ? `Ocultar ${net}` : `Ver ${net}`} onClick={() => setExpanded(open ? null : gid)}>
            {open ? <CaretDown size={16} aria-hidden="true" /> : <CaretRight size={16} aria-hidden="true" />}
          </button>
        </td>
        <td className="mono">{net} <span className="muted small">({ips} {ips === 1 ? 'IP' : 'IPs'})</span></td>
        <td>{cases.some((c) => caseTier(c) === 2) ? <TierBadge tier={2} /> : <span className="muted">sin dato</span>}</td>
        <td className="num mono">{formatScore(risk)}</td>
        <td className="mono nowrap">{formatTime(firstAt)}</td>
        <td className="mono nowrap">{formatTime(lastAt)}</td>
        <td className="num mono">{occ.toLocaleString('es-CL')}</td>
        <td>{states}</td>
        <td>{sources.length ? sources.join(', ') : 'ninguna o sin dato'}</td>
        <td className="muted">{cases.length} {cases.length === 1 ? 'caso' : 'casos'}</td>
      </tr>
      {open && cases.map((c) => (
        <CaseRow key={c.case_id} c={c} lookups={lookups} role={role}
          open={expanded === c.case_id} toggle={() => setExpanded(expanded === c.case_id ? gid : c.case_id)}
          onUpdated={onUpdated} />
      ))}
    </Fragment>
  )
}

function CaseDetail({ c, rec, role, onUpdated }: { c: Case; rec: ResponseRecord | undefined; role: Role; onUpdated: (c: Case) => void }) {
  const tid = c.detail?.trace_id
  const load = useExplain(tid, role)
  const trace = load?.kind === 'ok' ? load.trace : null
  const e = rec?.enrichment
  const classtype = c.detail?.classtype
  const lastTrace = c.trace_ids?.at(-1)
  return (
    <div className="case-detail">
      <section aria-label="Línea de tiempo">
        <p className="detail-label">Línea de tiempo</p>
        <ol className="case-timeline">
          {(c.history ?? []).map((h, i) => (
            <li key={i}>
              <span className="mono small">{formatTime(h.at)}</span>
              <span><strong>{CASE_STATE_LABEL[h.state] ?? h.state}</strong>, {h.actor ?? 'sistema'}</span>
              {h.note && <span className="muted">{h.note}</span>}
            </li>
          ))}
        </ol>
        <CaseActions c={c} role={role} onUpdated={onUpdated} />
      </section>

      <div className="detail-grid">
        <dl>
          <dt>Inteligencia de amenazas</dt><dd>{e ? corroboranLabel(e.corroboration_count) : 'sin registro de respuesta'}</dd>
          <dt>AbuseIPDB</dt><dd>{e ? abuseipdbStatus(e) : 'sin dato'}</dd>
          <dt>OTX</dt><dd>{e ? otxStatus(e) : 'sin dato'}</dd>
          <dt>CrowdSec (observacional)</dt><dd>{e?.crowdsec_observado ? (e.crowdsec_scenario ?? 'observado') : 'no observado'}</dd>
          <dt>Puerto destino</dt><dd className="mono">{c.detail?.dst_port ?? 'sin dato'}</dd>
          <dt>ATT&amp;CK</dt>
          <dd>{trace ? attackText(trace.fast_path?.attack ?? trace.respuesta?.attack_alerta_correlacionada)
            : classtype ? `classtype ${classtype} (el mapeo se ve en la traza, N2)` : 'sin classtype en la decisión: sin mapeo ATT&CK'}</dd>
        </dl>
        <dl>
          <dt>Evidencia (por referencia)</dt><dd className="muted">sin archivos adjuntos</dd>
          <dt>trace_id de apertura</dt><dd className="mono wrap-anywhere">{tid ?? 'sin dato'}</dd>
          {lastTrace && lastTrace !== tid && (<><dt>Último trace_id</dt><dd className="mono wrap-anywhere">{lastTrace}</dd></>)}
          <dt>Documento de respuesta</dt>
          <dd>{rec ? <>soc-responses-*, {accionR2Label(rec)}</> : 'sin registro encontrado'}</dd>
          {trace ? (
            <>
              <ChainLink label="Eslabón de la decisión" v={trace.integridad.decision} />
              <ChainLink label="Eslabón de la respuesta" v={trace.integridad.respuesta} />
            </>
          ) : (<><dt>Eslabones de la cadena</dt><dd className="muted">{load ? 'cargando' : 'requieren rol N2'}</dd></>)}
          <dt>case_id</dt><dd className="mono wrap-anywhere">{c.case_id}</dd>
          <dt>Red /24</dt><dd className="mono">{c.net24 ?? 'sin dato'}</dd>
        </dl>
        <ExplainPanel traceId={tid} role={role} load={load} />
      </div>
    </div>
  )
}

function CaseActions({ c, role, onUpdated }: { c: Case; role: Role; onUpdated: (c: Case) => void }) {
  const [target, setTarget] = useState<CaseState | null>(null)
  const [note, setNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const options = ACTIONS[c.state] ?? []
  if (options.length === 0) return <p className="muted small">Caso cerrado: sin acciones.</p>
  const allowed = options.filter((o) => ROLE_LEVEL[role] >= ROLE_LEVEL[o.minRole])
  const denied = options.filter((o) => ROLE_LEVEL[role] < ROLE_LEVEL[o.minRole])
  const chosen = options.find((o) => o.to === target)
  const noteOk = !chosen?.noteRequired || note.trim().length >= NOTE_MIN

  async function submit() {
    if (!chosen) return
    setSubmitting(true)
    setMessage(null)
    const out = await updateCaseState(c.case_id, chosen.to, note.trim())
    setSubmitting(false)
    if (out.kind === 'done') {
      setTarget(null)
      setNote('')
      onUpdated(out.case)
    } else {
      setMessage(out.message)
    }
  }

  return (
    <div className="case-actions">
      {!chosen ? (
        <div className="row-actions" role="group" aria-label="Acciones del caso">
          {allowed.map((o) => (
            <button key={o.to} type="button" className={o.to === 'en_investigacion' ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm'}
              onClick={() => { setTarget(o.to); setMessage(null) }}>{o.label}</button>
          ))}
          {denied.length > 0 && <span className="muted small">Cerrar un caso requiere rol N2 o CISO.</span>}
        </div>
      ) : (
        <form className="confirm" onSubmit={(ev) => { ev.preventDefault(); void submit() }}>
          <div className="field">
            <label htmlFor={`note-${c.case_id}`}>
              Nota{chosen.noteRequired ? ' (obligatoria)' : ' (opcional)'}
            </label>
            <textarea id={`note-${c.case_id}`} className="input" rows={3} maxLength={1000} value={note}
              aria-invalid={!noteOk} onChange={(ev) => setNote(ev.target.value)} />
            {chosen.noteRequired && <span className="hint">Mínimo {NOTE_MIN} caracteres: por qué se cierra así.</span>}
          </div>
          <button type="submit" className="btn btn-primary btn-sm" disabled={submitting || !noteOk}>
            {submitting ? 'Enviando…' : `Confirmar: ${chosen.label.toLowerCase()}`}
          </button>
          <button type="button" className="btn btn-ghost btn-sm" disabled={submitting}
            onClick={() => { setTarget(null); setNote('') }}>Cancelar</button>
        </form>
      )}
      {message && <p className="notice notice-danger" role="alert">{message}</p>}
    </div>
  )
}
