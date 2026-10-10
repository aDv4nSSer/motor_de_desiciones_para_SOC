import { afterEach, describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import type { Role } from '../api/types'
import { AuthProvider } from '../auth/AuthContext'
import { accionR2Label } from '../lib/r2'
import { abuseipdbStatus, corroboranLabel, otxStatus } from '../lib/ti'
import { json, mockFetch } from './helpers'

type Handler = Parameters<typeof mockFetch>[0][string]

const TRACE = '13dd7cd0-2c35-4e59-a717-450729535a48'
const CASE = {
  case_id: '1aa30a78-2167-4038-b726-9cb6bb7871ce', kind: 'network_t2_unconfirmed', host: '91.92.42.173',
  net24: '91.92.42.0/24', state: 'abierto', opened_at: '2026-10-09T19:05:03+00:00',
  last_seen: '2026-10-10T15:19:46+00:00', occurrences: 849, trace_ids: [TRACE, 'daf8c941-d740-4b5f-8e61-88232a61dd0e'],
  detail: { trace_id: TRACE, risk_score: 0.6909, dst_port: 22, classtype: '', corroboration_count: 2 },
  history: [{ state: 'abierto', at: '2026-10-09T19:05:03+00:00', note: 'Caso creado automáticamente (R1, tier T2)' }],
}
const OTHER = { ...CASE, case_id: '2bb30a78-2167-4038-b726-9cb6bb7871ce', host: '91.92.42.80', occurrences: 3,
  detail: { ...CASE.detail, trace_id: '23dd7cd0-2c35-4e59-a717-450729535a48' } }
const RECORD = {
  trace_id: TRACE, src_ip: '91.92.42.173', accion_recomendada: 'alertar_crear_caso', case_id: CASE.case_id,
  enrichment: {
    abuseipdb_score: 100, abuseipdb_available: true, otx_pulse_count: 26, otx_available: true,
    corroboration_count: 2, corroborating_sources: ['abuseipdb', 'otx'],
  },
}
const PAGE = { items: [CASE, OTHER], next_cursor: null, scanned: 2, source: 'recent', index_size: 12502,
  scan_cap_reached: false, available: true }
const EXPLAIN = {
  version: 'explain-v1', trace_id: TRACE,
  fast_path: {
    senales: [{ senal: 'ml_score', valor: 0.9, peso: 0.7, aporte: 0.63 }], risk_score: 0.6909,
    risk_score_recalculado: 0.6909, tier: 2, tier_recalculado: 2, consistente: true,
    regla: { id: 'FP-TIER-T2', texto: 'T1_max 0.55 < risk_score 0.6909 <= T2_max 0.8: T2.' },
    attack: { classtype: null, nota: 'sin classtype en la decisión (H50): sin mapeo ATT&CK' },
  },
  respuesta: {
    r1: { senales: [{ senal: 'abuseipdb', valor: 100, umbral: '>= 50', corrobora: true }], corroboration_count: 2, notas: [] },
    r2: { regla: { id: 'T2-CASO', texto: 'T2 de IP no propia: alerta y caso automático (sin bloqueo).' }, ejecutado: false, minimo_fuentes: 2 },
    consistente: true,
  },
  integridad: { decision: { content_ok: true, prev_link_ok: true, next_link_ok: true, chain_seq: 41, hash: 'a'.repeat(64) },
    respuesta: { content_ok: true, prev_link_ok: true, next_link_ok: null, chain_seq: 7, hash: 'b'.repeat(64) } },
  limitaciones: ['SHAP no implementado.'],
}

async function enterCases(role: Role, routes: Record<string, Handler> = {}) {
  const mock = mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 'tok', token_type: 'bearer', role }),
    '/api/v1/dashboard/responses/lookup': () => json(200, {
      responses: { [TRACE]: RECORD }, complete: true, sources: { opensearch: true, redis: true }, worker_frontier: null,
    }),
    '/api/v1/dashboard/explain/': () => json(200, EXPLAIN),
    ...routes,
    '/api/v1/dashboard/cases/page': () => json(200, PAGE),
  })
  window.location.hash = '#casos'
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  await screen.findByText('91.92.42.173')
  return { user, ...mock }
}

const rowOf = (ip: string) => screen.getByText(ip).closest('tr')!

afterEach(() => { window.location.hash = '' })

describe('gestión interna de casos', () => {
  it('lista solo IPs públicas abiertas por defecto, sin mencionar Iris', async () => {
    const { calls } = await enterCases('N1')
    const page = calls.find((c) => c.url.startsWith('/api/v1/dashboard/cases/page'))!
    expect(page.url).toContain('public_only=true')
    expect(page.url).toContain('state=abierto')
    expect(screen.queryByText(/Iris/)).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Gestión interna de casos' })).toBeInTheDocument()
    const row = rowOf('91.92.42.173')
    expect(within(row).getByText('T2 medio')).toBeInTheDocument()
    expect(within(row).getByText('849')).toBeInTheDocument()
    expect(within(row).getByText('abuseipdb, otx')).toBeInTheDocument()
    expect(within(row).getByText('13dd7cd0')).toBeInTheDocument()
    expect(within(rowOf('91.92.42.80')).getByText('sin dato')).toBeInTheDocument() // sin registro de respuesta
  })

  it('agrupa por /24', async () => {
    const { user } = await enterCases('N1')
    await user.click(screen.getByLabelText('Agrupar por /24'))
    const group = screen.getByText('91.92.42.0/24').closest('tr')!
    expect(within(group).getByText('(2 IPs)')).toBeInTheDocument()
    expect(within(group).getByText('852')).toBeInTheDocument()
    expect(screen.queryByText('91.92.42.173')).not.toBeInTheDocument()
  })

  it('cambiar el filtro pide la página con ese estado y ventana', async () => {
    const { user, calls } = await enterCases('N1')
    await user.click(screen.getByRole('button', { name: 'En investigación' }))
    await user.click(screen.getByRole('button', { name: '24 h' }))
    const last = calls.filter((c) => c.url.startsWith('/api/v1/dashboard/cases/page')).at(-1)!
    expect(last.url).toContain('state=en_investigacion')
    expect(last.url).toContain('since_hours=24')
  })

  it('N1 solo puede pasar a investigación, no ve la traza ni exporta', async () => {
    const investigated = { ...CASE, state: 'en_investigacion', history: [...CASE.history,
      { state: 'en_investigacion', at: '2026-10-10T16:00:00+00:00', note: '', actor: 'ana' }] }
    const { user, calls } = await enterCases('N1', {
      [`/api/v1/dashboard/cases/${CASE.case_id}/state`]: () => json(200, investigated),
    })
    expect(screen.queryByRole('button', { name: /Exportar cierres/ })).not.toBeInTheDocument()
    await user.click(within(rowOf('91.92.42.173')).getByRole('button', { name: 'Ver caso' }))
    expect(screen.queryByRole('button', { name: 'Cerrar como confirmado' })).not.toBeInTheDocument()
    expect(screen.getByText('Cerrar un caso requiere rol N2 o CISO.')).toBeInTheDocument()
    expect(screen.getByText(/La traza explicativa requiere rol N2/)).toBeInTheDocument()
    expect(calls.some((c) => c.url.includes('/explain/'))).toBe(false)
    expect(screen.getByText('AbuseIPDB 100')).toBeInTheDocument()
    expect(screen.getByText('OTX 26 pulsos')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Pasar a investigación' }))
    await user.click(screen.getByRole('button', { name: /Confirmar: pasar a investigación/ }))
    const post = calls.find((c) => c.url.endsWith('/state'))!
    expect(post.init?.method).toBe('POST')
    expect(JSON.parse(String(post.init?.body))).toEqual({ state: 'en_investigacion', note: '' })
    expect(await within(rowOf('91.92.42.173')).findByText('En investigación')).toBeInTheDocument()
    expect(screen.getAllByText(/, ana/).length).toBeGreaterThan(0) // actor en la línea de tiempo
  })

  it('N2 cierra con nota obligatoria y ve la traza v1 con sus eslabones', async () => {
    const closed = { ...CASE, state: 'cerrado_confirmado', history: [...CASE.history,
      { state: 'cerrado_confirmado', at: '2026-10-10T16:05:00+00:00', note: 'AbuseIPDB 100 y OTX 26', actor: 'ana' }] }
    const { user, calls } = await enterCases('N2', {
      [`/api/v1/dashboard/cases/${CASE.case_id}/state`]: () => json(200, closed),
    })
    expect(screen.getByRole('button', { name: /Exportar cierres/ })).toBeInTheDocument()
    await user.click(within(rowOf('91.92.42.173')).getByRole('button', { name: 'Ver caso' }))
    expect(await screen.findByText(/T1_max 0.55 < risk_score 0.6909/)).toBeInTheDocument()
    expect(screen.getByText('Reglas explicativas v1; SHAP pendiente.')).toBeInTheDocument()
    expect(screen.getByText('Eslabón de la respuesta')).toBeInTheDocument()
    expect(screen.getByText(/seq 7, hash bbbbbbbb/)).toBeInTheDocument()
    expect(screen.getByText(/sin mapeo ATT&CK/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Cerrar como confirmado' }))
    const confirm = screen.getByRole('button', { name: /Confirmar: cerrar como confirmado/ })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Nota (obligatoria)'), 'ok')
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Nota (obligatoria)'), ' AbuseIPDB 100')
    await user.click(confirm)
    const post = calls.find((c) => c.url.endsWith('/state'))!
    expect(JSON.parse(String(post.init?.body))).toEqual({ state: 'cerrado_confirmado', note: 'ok AbuseIPDB 100' })
    expect(await screen.findByText('Caso cerrado: sin acciones.')).toBeInTheDocument()
  })

  it('muestra el rechazo del servidor sin cambiar el estado', async () => {
    const { user } = await enterCases('N2', {
      [`/api/v1/dashboard/cases/${CASE.case_id}/state`]: () => json(409, { detail: 'No se puede pasar de cerrado_confirmado a cerrado_falso_positivo' }),
    })
    await user.click(within(rowOf('91.92.42.173')).getByRole('button', { name: 'Ver caso' }))
    await user.click(screen.getByRole('button', { name: 'Cerrar como falso positivo' }))
    await user.type(screen.getByLabelText('Nota (obligatoria)'), 'Bingbot verificado')
    await user.click(screen.getByRole('button', { name: /Confirmar/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/cambió de estado/)
    expect(within(rowOf('91.92.42.173')).getByText('Abierto')).toBeInTheDocument()
  })
})

describe('etiquetas de presentación de Alertas (H60)', () => {
  it('deriva la acción de R2 del registro, no solo de accion_recomendada', () => {
    expect(accionR2Label({ accion_recomendada: 'ninguna', block: { action: 'block_skipped', reason: 'ya bloqueada — TTL extendido' } }))
      .toBe('Ya bloqueada (TTL extendido)')
    expect(accionR2Label({ accion_recomendada: 'bloqueo_ip', block: { action: 'block', enforced: true } })).toBe('Bloqueo automático')
    expect(accionR2Label({ accion_recomendada: 'alertar_pendiente_aprobacion', block: { action: 'block_pending_approval', approval_level: 'N1' } }))
      .toBe('Pendiente de aprobación N1')
    expect(accionR2Label({ accion_recomendada: 'ninguna_infra_propia' })).toBe('Infra propia, sin caso')
    expect(accionR2Label({ accion_recomendada: 'ninguna', block: { action: 'block_skipped', reason: 'safelisted (infra del lab)' } }))
      .toBe('Infra propia, sin caso')
    expect(accionR2Label({ accion_recomendada: 'bloqueo_ip', block: { action: 'block_skipped', reason: 'stale_backlog: evento de 900 s' } }))
      .toBe('Bloqueo recomendado, no ejecutado (evento antiguo)')
    expect(accionR2Label({ accion_recomendada: 'alertar_crear_caso', case_id: 'x' })).toBe('Alertar y crear caso')
  })

  it('separa la política de cuota del error real de TI', () => {
    const politica = { abuseipdb_available: false, notes: ['abuseipdb: omitido (tier < r2_min_tier: no puede cambiar R2, solo caché)'] }
    expect(abuseipdbStatus(politica)).toBe('AbuseIPDB no consultada (política de cuota, solo caché)')
    expect(abuseipdbStatus({ abuseipdb_available: false, notes: ['abuseipdb: omitido por throttling (presupuesto de la ventana agotado)'] }))
      .toBe('AbuseIPDB no consultada (política de cuota, solo caché)')
    expect(abuseipdbStatus({ abuseipdb_available: false, notes: ['abuseipdb error: ReadTimeout'] })).toBe('AbuseIPDB no disponible (error)')
    expect(abuseipdbStatus({ abuseipdb_available: false, notes: ['abuseipdb no disponible (evento stale, solo caché)'] }))
      .toBe('AbuseIPDB no consultada (evento antiguo, solo caché)')
    expect(abuseipdbStatus({ abuseipdb_available: false, notes: ['abuseipdb: IP no pública, TI externa no aplica'] }))
      .toBe('AbuseIPDB no aplica (IP no pública)')
    expect(otxStatus({ otx_available: false, notes: ['otx HTTP 503'] })).toBe('OTX no disponible (error)')
    expect(otxStatus({ otx_pulse_count: 1 })).toBe('OTX 1 pulso')
    expect(corroboranLabel(1)).toBe('1 fuente corrobora')
    expect(corroboranLabel(2)).toBe('2 fuentes corroboran')
    expect(corroboranLabel(undefined)).toBe('0 fuentes corroboran')
  })
})
