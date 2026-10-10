import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { mergeLookups, PROCESSING_GRACE_MS, responseState, type RowLookup } from '../lib/responses'
import { json, LOGIN_OK, mockFetch } from './helpers'

const DECISION = {
  trace_id: 'abcdef12-3456', timestamp: '2026-09-30T18:00:00+00:00', tier: 3, tier_name: 'T3_CRITICO',
  risk_score: 0.97, ml_score: 0.95, anomaly_score: 0.4, decision: 'BLOCK', L4_DST_PORT: 22,
}
const RECORD = {
  trace_id: 'abcdef12-3456', src_ip: '198.51.100.7', accion_recomendada: 'alertar_pendiente_aprobacion',
  enrichment: { abuseipdb_score: 91, otx_pulse_count: 3, corroboration_count: 1, corroborating_sources: ['abuseipdb'] },
}
const lookupOk = (responses: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  json(200, { responses, complete: true, sources: { opensearch: true, redis: true }, worker_frontier: null, ...extra })

async function login() {
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  return user
}

describe('estado de la respuesta de una alerta', () => {
  const base: RowLookup = { complete: true, failed: false, frontierMs: Date.parse('2026-10-05T14:00:00Z'), checkedAt: 0 }
  const at = (iso: string) => ({ ...DECISION, timestamp: iso })

  it('separa en proceso, sin registro y error', () => {
    expect(responseState(at('2026-10-05T14:00:05Z'), base).kind).toBe('processing') // después de la frontera
    const dentroDelMargen = new Date(base.frontierMs! - PROCESSING_GRACE_MS + 1000).toISOString()
    expect(responseState(at(dentroDelMargen), base).kind).toBe('processing')
    expect(responseState(at('2026-10-05T13:50:00Z'), base).kind).toBe('missing') // el worker ya pasó
    expect(responseState(at('2026-10-05T13:50:00Z'), { ...base, complete: false }).kind).toBe('error')
    expect(responseState(at('2026-10-05T13:50:00Z'), { ...base, failed: true }).kind).toBe('error')
    expect(responseState(at('2026-10-05T13:50:00Z'), undefined).kind).toBe('checking')
  })

  it('un registro encontrado no se pierde si una consulta posterior falla', () => {
    const encontrado = new Map([['t1', { ...base, record: RECORD }]])
    const falla = new Map([['t1', { ...base, failed: true }], ['t2', { ...base, failed: true }]])
    const m = mergeLookups(encontrado, falla)
    expect(m.get('t1')?.record).toEqual(RECORD)
    expect(m.get('t2')?.failed).toBe(true)
  })
})

describe('vista de alertas', () => {
  it('pide solo T2+, resuelve la respuesta por trace_id y no inventa razonamiento', async () => {
    const { calls } = mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': () => json(200, [DECISION]),
      '/api/v1/dashboard/responses/lookup': () => lookupOk({ [RECORD.trace_id]: RECORD }),
      '/api/v1/dashboard/stats': () => json(200, { available: true, window_minutes: 60, total_decisiones: 4210, por_tier: { T3_CRITICO: 37, T2_MEDIO: 412 } }),
    })
    const user = await login()

    expect(await screen.findByText('198.51.100.7')).toBeInTheDocument()
    expect(calls.some((c) => c.url.includes('tier_min=2'))).toBe(true)
    const lookup = calls.find((c) => c.url.startsWith('/api/v1/dashboard/responses/lookup'))!
    expect(lookup.init?.method).toBe('POST')
    expect(JSON.parse(String(lookup.init?.body))).toEqual({ trace_ids: [DECISION.trace_id] })
    expect(calls.some((c) => c.url.includes('/blocks/recent'))).toBe(false)
    expect(screen.getByText('T3 crítico')).toBeInTheDocument()
    expect(screen.getByText('Pendiente de aprobación (nivel sin dato)')).toBeInTheDocument()
    expect(screen.getByText(/AbuseIPDB 91, OTX 3 pulsos/)).toBeInTheDocument()
    expect(screen.getByText(/1 fuente corrobora/)).toBeInTheDocument()
    expect(screen.getByText('37')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Ver detalle' }))
    expect(screen.queryByText(/rules.yaml/)).not.toBeInTheDocument()
    expect(screen.getByText('Reglas explicativas v1; SHAP pendiente.')).toBeInTheDocument()
    expect(screen.getByText(/requiere rol N2/)).toBeInTheDocument()
    expect(calls.some((c) => c.url.includes('/explain/'))).toBe(false) // N1: no pide la traza
  })

  it('muestra en proceso y sin registro como estados distintos', async () => {
    const frontier = '2026-10-05T14:00:00+00:00'
    mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': () => json(200, [
        { ...DECISION, trace_id: 'nueva-0001', timestamp: '2026-10-05T14:00:10+00:00' },
        { ...DECISION, trace_id: 'vieja-0002', timestamp: '2026-10-05T13:40:00+00:00' },
      ]),
      '/api/v1/dashboard/responses/lookup': () => lookupOk({}, { worker_frontier: frontier }),
      '/api/v1/dashboard/stats': () => json(200, { available: false, window_minutes: 60 }),
    })
    await login()
    const nueva = (await screen.findByText('nueva-00')).closest('tr')!
    const vieja = screen.getByText('vieja-00').closest('tr')!
    expect(within(nueva).getByText('En proceso')).toBeInTheDocument()
    expect(within(vieja).getByText('Sin registro de respuesta')).toBeInTheDocument()
    expect(screen.queryByText(/Sin respuesta en ventana/)).not.toBeInTheDocument()
  })

  it('si la consulta falla no afirma que falte la respuesta', async () => {
    mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': () => json(200, [DECISION]),
      '/api/v1/dashboard/responses/lookup': () => json(500, { detail: 'boom' }),
      '/api/v1/dashboard/stats': () => json(200, { available: false, window_minutes: 60 }),
    })
    await login()
    expect(await screen.findByText('No se pudo verificar')).toBeInTheDocument()
    expect(screen.queryByText('Sin registro de respuesta')).not.toBeInTheDocument()
  })

  it('"cargar anteriores" pagina con el cursor before y resuelve esa página por trace_id', async () => {
    const OLDER = { ...DECISION, trace_id: 'older-0001', timestamp: '2026-09-30T17:00:00+00:00' }
    const { calls } = mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': (url) => json(200, url.includes('before=') ? [OLDER] : [DECISION]),
      '/api/v1/dashboard/responses/lookup': (_url, init) => {
        const ids: string[] = JSON.parse(String(init?.body)).trace_ids
        return lookupOk(Object.fromEntries(ids.map((id) => [id, { ...RECORD, trace_id: id, src_ip: `ip-${id}` }])))
      },
      '/api/v1/dashboard/stats': () => json(200, { available: false, window_minutes: 60 }),
    })
    const user = await login()
    await screen.findByText('abcdef12')
    await user.click(screen.getByRole('button', { name: 'Cargar alertas anteriores' }))
    const paged = calls.find((c) => c.url.includes('before='))!
    expect(paged.url).toContain(`before=${encodeURIComponent(DECISION.timestamp)}`)
    expect(paged.url).toContain('tier_min=2')
    expect(await screen.findByText('ip-older-0001')).toBeInTheDocument()
  })
})
