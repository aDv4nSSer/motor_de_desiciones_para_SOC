import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { indexResponses } from '../lib/responses'
import { json, LOGIN_OK, mockFetch } from './helpers'

const DECISION = {
  trace_id: 'abcdef12-3456', timestamp: '2026-09-30T18:00:00+00:00', tier: 3, tier_name: 'T3_CRITICO',
  risk_score: 0.97, ml_score: 0.95, anomaly_score: 0.4, decision: 'BLOCK', L4_DST_PORT: 22,
}

describe('indexResponses', () => {
  it('descarta eventos de acceso y aprobaciones manuales del stream de auditoría', () => {
    const m = indexResponses([
      { access_event: 'login_success' },
      { trace_id: 't1', manual_approval: true },
      { trace_id: 't2', accion_recomendada: 'bloqueo_ip' },
      { trace_id: 't3', enrichment: { abuseipdb_score: 80 } },
      { trace_id: 't4' },
    ])
    expect([...m.keys()]).toEqual(['t2', 't3'])
  })
})

describe('vista de alertas', () => {
  it('pide solo T2+, une con la respuesta por trace_id y no inventa razonamiento', async () => {
    const { calls } = mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': () => json(200, [DECISION]),
      '/api/v1/dashboard/blocks/recent': () => json(200, [{
        trace_id: 'abcdef12-3456', src_ip: '198.51.100.7', accion_recomendada: 'alertar_pendiente_aprobacion',
        enrichment: { abuseipdb_score: 91, otx_pulse_count: 3, corroboration_count: 1, corroborating_sources: ['abuseipdb'] },
      }]),
      '/api/v1/dashboard/stats': () => json(200, { available: true, window_minutes: 60, total_decisiones: 4210, por_tier: { T3_CRITICO: 37, T2_MEDIO: 412 } }),
    })
    const user = userEvent.setup()
    render(<AuthProvider><App /></AuthProvider>)
    await user.type(screen.getByLabelText('Usuario'), 'ana')
    await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
    await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(await screen.findByText('198.51.100.7')).toBeInTheDocument()
    expect(calls.some((c) => c.url.includes('tier_min=2'))).toBe(true)
    expect(screen.getByText('T3 crítico')).toBeInTheDocument()
    expect(screen.getByText('Pendiente de aprobación')).toBeInTheDocument()
    expect(screen.getByText(/AbuseIPDB 91, OTX 3 pulsos/)).toBeInTheDocument()
    expect(screen.getByText('37')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Ver detalle' }))
    expect(screen.getByText(/motor de reglas \(rules.yaml\) no está implementado/)).toBeInTheDocument()
  })

  it('"cargar anteriores" pagina con el cursor before = timestamp del último ítem', async () => {
    const { calls } = mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': (url) => json(200, url.includes('before=') ? [] : [DECISION]),
      '/api/v1/dashboard/blocks/recent': () => json(200, []),
      '/api/v1/dashboard/stats': () => json(200, { available: false, window_minutes: 60 }),
    })
    const user = userEvent.setup()
    render(<AuthProvider><App /></AuthProvider>)
    await user.type(screen.getByLabelText('Usuario'), 'ana')
    await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
    await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
    await screen.findByText('abcdef12')
    await user.click(screen.getByRole('button', { name: 'Cargar alertas anteriores' }))
    const paged = calls.find((c) => c.url.includes('before='))!
    expect(paged.url).toContain(`before=${encodeURIComponent(DECISION.timestamp)}`)
    expect(paged.url).toContain('tier_min=2')
  })
})
