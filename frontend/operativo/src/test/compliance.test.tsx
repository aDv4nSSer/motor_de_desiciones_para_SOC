import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { json, mockFetch } from './helpers'

const VALIDATION = { start: '2026-10-07T23:40:00+00:00', end: '2026-10-10T23:40:00+00:00' }

const CORR = {
  available: true, shadow: true, validation: VALIDATION, from: VALIDATION.start, clamped: true,
  t3_total: 27_406, scored: 3_839, excluded: 23_567, eligible: 3_775, eligible_pct: 98.3,
  bands: { high: 3_775, medium: 19, low: 0, ambiguous: 45 },
  groups: { evaluated: 3_839, available_pct: { ml: 100, ti: 99.8, signature: 0.7, context: 98.9 } },
}

function report(corroboracion_sombra: unknown, generated_at = '2026-10-08T12:00:00Z') {
  return {
    window_minutes: 1440, generated_at,
    fatiga_alertas_pct: 91.2, latencia_avg_ms: 12, latencia_p95_ms: 40,
    precision_bloqueos: { available: true, total_blocks: 0, corroborated: { count: 0, high_score_count: 0, precision_pct: null, threshold: 40 }, uncorroborated: { count: 0 } },
    corroboracion_sombra,
    decisiones: { available: true, total: 50_000, por_tier: { T3_CRITICO: 12_400, T2_MEDIO: 300 } },
    respuestas: { available: true, acciones: {}, accesos: {} },
    aprobaciones_pendientes: 0, usuarios_por_rol: { N1: 1, N2: 1, CISO: 1 }, sesiones_activas: 1,
    response_mode: 'enforce',
    cadenas: { verified_at: '2026-10-08T12:00:00Z', tail_size: 2000, chains: { responses: { ok: true }, decisions: { ok: true } } },
    checklist: [], mttr_humano: { available: false, detail: '' }, nota_legal: 'nota',
    exportacion_pdf: { available: false, detail: 'pendiente' },
  }
}

/** Entra como CISO: su vista por defecto es Cumplimiento (ventana 24 h). */
async function enterCompliance(corr: unknown, generatedAt?: string) {
  const mock = mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 'tok', token_type: 'bearer', role: 'CISO' }),
    '/api/v1/dashboard/compliance': () => json(200, report(corr, generatedAt)),
  })
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  return mock
}

async function kpi(name: RegExp) {
  const metrics = await screen.findByLabelText('Métricas de valor')
  return within(metrics).getByText(name).closest('.kpi') as HTMLElement
}

describe('tarjeta de corroboración multi-fuente (Cumplimiento)', () => {
  it('reemplaza la de AbuseIPDB y muestra el % elegible sobre T3 con score, marcado como sombra', async () => {
    const { calls } = await enterCompliance(CORR)

    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(screen.queryByText(/Bloqueos corroborados por AbuseIPDB/)).not.toBeInTheDocument()
    expect(within(card).getByText('modo sombra')).toBeInTheDocument()
    expect(within(card).getByText('98,3 %')).toBeInTheDocument()
    expect(within(card).getByText(/3\.775 de 3\.839 T3 desde el inicio de la validación \(7 oct, 20:40\)/)).toBeInTheDocument()
    // La línea de sombra va aparte del número principal.
    const notice = within(card).getByText(/No determina bloqueos reales/)
    expect(notice).toHaveClass('kpi-shadow')
    expect(notice).toHaveTextContent('período de validación hasta el 10 oct, 20:40')
    // Misma ventana que el resto de la vista.
    expect(calls.find((c) => c.url.startsWith('/api/v1/dashboard/compliance'))?.url).toContain('window_minutes=1440')

    const panel = screen.getByRole('region', { name: /Corroboración multi-fuente de T3/ })
    expect(within(panel).getByText('Ambigua (grupos en desacuerdo)').nextSibling).toHaveTextContent('45 (1,2 %)')
    expect(within(panel).getByText('Firma Suricata (classtype, ATT&CK)').nextSibling).toHaveTextContent('0,7 %')
    expect(within(panel).getByText(/sobre 3\.839 T3 con detalle por grupo/)).toBeInTheDocument()
    // Las T3 sin score se informan aparte, nunca en el denominador del %.
    expect(within(panel).getByText(/Calculado desde el inicio del período de validación \(7 oct, 20:40\)/))
      .toHaveTextContent('23.567 T3 de la ventana quedan fuera del cálculo')
  })

  it('sin OpenSearch muestra sin dato pero conserva el aviso de modo sombra', async () => {
    await enterCompliance({ available: false, shadow: true, validation: VALIDATION, from: VALIDATION.start, clamped: true })
    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(within(card).getByText('sin dato')).toBeInTheDocument()
    expect(within(card).getByText(/No determina bloqueos reales/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: /Corroboración multi-fuente de T3/ })).not.toBeInTheDocument()
  })

  it('cerrado el período, sigue diciendo que no determina bloqueos', async () => {
    await enterCompliance(CORR, '2026-10-11T12:00:00Z')
    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(within(card).getByText(/No determina bloqueos reales/)).toHaveTextContent('validación cerrada el 10 oct, 20:40')
  })
})
