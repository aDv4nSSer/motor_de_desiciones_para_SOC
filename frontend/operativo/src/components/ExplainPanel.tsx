import type { ChainVerification, ExplainSignal, Role } from '../api/types'
import { canExplain, EXPLAIN_NOTE, type ExplainLoad } from '../lib/explain'
import { formatScore, plainText } from '../lib/format'

function fmtValue(v: unknown): string {
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : formatScore(v)
  if (v === null || v === undefined || v === '') return 'sin dato'
  return String(v)
}

function Consistency({ ok }: { ok: boolean }) {
  return ok
    ? <span className="badge st-ok">Reproduce lo guardado</span>
    : <span className="badge st-critical">No reproduce lo guardado</span>
}

/** Eslabón de la cadena hash: posición, hash propio y enlaces verificados. */
export function ChainLink({ label, v }: { label: string; v: ChainVerification | null | undefined }) {
  if (!v) return <><dt>{label}</dt><dd className="muted">sin registro</dd></>
  const links = [v.prev_link_ok, v.next_link_ok]
  const linkText = links.some((x) => x === false) ? 'enlace roto' : links.every((x) => x === true) ? 'enlaces verificados' : 'enlaces parciales (extremo de la cadena o sin vecino)'
  return (
    <>
      <dt>{label}</dt>
      <dd>
        <span className={v.content_ok ? 'text-ok' : 'text-danger'}>{v.content_ok ? 'contenido íntegro' : 'hash no coincide'}</span>
        {', '}{linkText}
        <span className="mono muted small wrap-anywhere"> seq {v.chain_seq ?? 'sin dato'}, hash {v.hash ? v.hash.slice(0, 16) : 'sin dato'}</span>
      </dd>
    </>
  )
}

function SignalRows({ signals, gate }: { signals: ExplainSignal[]; gate: boolean }) {
  return (
    <table className="data compact">
      <thead>
        <tr>
          <th scope="col">Señal</th>
          <th scope="col" className="num">Valor</th>
          {gate ? <th scope="col">Umbral</th> : <th scope="col" className="num">Peso</th>}
          {gate ? <th scope="col">Corrobora</th> : <th scope="col" className="num">Aporte</th>}
        </tr>
      </thead>
      <tbody>
        {signals.map((s) => (
          <tr key={s.senal}>
            <td title={s.fuente ?? s.nota}>{s.senal}{gate && s.disponible === false ? <span className="muted"> (sin dato)</span> : null}</td>
            <td className="num mono">{fmtValue(s.valor)}</td>
            {gate ? <td className="mono">{s.umbral ?? s.nota ?? ''}</td> : <td className="num mono">{fmtValue(s.peso)}</td>}
            {gate ? <td>{s.corrobora ? 'sí' : 'no'}</td> : <td className="num mono">{fmtValue(s.aporte)}</td>}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Traza explicativa v1 (H59) de un trace_id. Reemplaza el texto de
 *  rules.yaml: explica la combinación de scores y las reglas, no la
 *  contribución de cada feature (SHAP pendiente). */
export function ExplainPanel({ traceId, role, load }: { traceId: string | undefined; role: Role; load: ExplainLoad | null }) {
  return (
    <div className="detail-note">
      <p className="detail-label">Reglas y razonamiento</p>
      <p className="muted small">{EXPLAIN_NOTE}</p>
      {!traceId ? <p className="muted">Sin trace_id: no hay traza que reconstruir.</p>
        : !canExplain(role) ? <p className="muted">La traza explicativa requiere rol N2 (mismo permiso que el historial).</p>
          : load && <ExplainBody load={load} />}
    </div>
  )
}

function ExplainBody({ load }: { load: ExplainLoad }) {
  if (load.kind === 'loading') return <p className="muted">Reconstruyendo la traza…</p>
  if (load.kind === 'missing') return <p className="muted">Este trace_id no tiene registros en las cadenas.</p>
  if (load.kind === 'error') return <p className="text-danger">No se pudo leer la traza: {load.message}</p>
  const { fast_path: fp, respuesta: rp } = load.trace
  return (
    <div className="explain">
      {fp ? (
        <section aria-label="Fast Path">
          <p className="small"><strong>Tier:</strong> <span className="mono">{fp.regla.id}</span> {plainText(fp.regla.texto)} <Consistency ok={fp.consistente} /></p>
          <SignalRows signals={fp.senales} gate={false} />
        </section>
      ) : <p className="muted small">Sin documento del Fast Path para este trace_id.</p>}
      {rp ? (
        <section aria-label="Respuesta R1 y R2">
          <p className="small"><strong>R2:</strong> <span className="mono">{rp.r2.regla.id}</span> {plainText(rp.r2.regla.texto)} <Consistency ok={rp.consistente} /></p>
          <SignalRows signals={rp.r1.senales} gate />
          {rp.r1.notas.length > 0 && <p className="muted small">Notas de R1: {rp.r1.notas.map(plainText).join('; ')}</p>}
        </section>
      ) : <p className="muted small">Sin registro de respuesta R1/R2 para este trace_id.</p>}
      <p className="muted small">{load.trace.version}. {load.trace.limitaciones.map(plainText).join(' ')}</p>
    </div>
  )
}
