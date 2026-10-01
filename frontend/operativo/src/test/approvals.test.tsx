import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import type { Approval } from '../api/types'
import { json, mockFetch } from './helpers'

function approval(over: Partial<Approval> = {}): Approval {
  return {
    trace_id: 'trace-aaaa-1111', src_ip: '203.0.113.50', tier: 3, risk_score: 0.912,
    reason: 'corroboración insuficiente (1/2 fuentes)', approval_level: 'N1', status: 'pending',
    created_at: '2026-09-30T18:00:00+00:00', resolved_by: null, resolved_at: null, ...over,
  }
}

async function openApprovals(role: 'N1' | 'N2' | 'CISO', resolve: (url: string, init?: RequestInit) => Response | Promise<Response>, list: Approval[] = [approval()]) {
  const mock = mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 't', token_type: 'bearer', role }),
    '/api/v1/dashboard/approvals/': resolve,
    '/api/v1/dashboard/approvals': () => json(200, list),
  })
  window.location.hash = '#aprobaciones'
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'op')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  await screen.findByText('203.0.113.50')
  return { user, ...mock }
}

describe('aprobar / rechazar', () => {
  it('sin optimistic update: el ítem sigue en la lista hasta el 200 del servidor', async () => {
    let release!: (r: Response) => void
    const pending = new Promise<Response>((r) => { release = r })
    const { user, calls } = await openApprovals('N1', () => pending)

    await user.click(screen.getByRole('button', { name: /Aprobar/ }))
    await user.click(screen.getByRole('button', { name: 'Confirmar bloqueo' }))

    // Request en vuelo: el ítem sigue en la lista de pendientes y el botón indica envío.
    expect(screen.getByRole('heading', { name: /Aprobaciones pendientes \(1\)/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Enviando…' })).toBeDisabled()
    const post = calls.find((c) => c.url.endsWith('/resolve'))!
    expect(post.url).toBe('/api/v1/dashboard/approvals/trace-aaaa-1111/resolve')
    expect(JSON.parse(post.init!.body as string)).toEqual({ decision: 'approved', note: '' })

    release(json(200, approval({ status: 'approved', resolved_by: 'op', resolved_at: '2026-09-30T18:01:00+00:00', enforced: true })))
    const done = await screen.findByRole('heading', { name: 'Resueltas en esta sesión' })
    const section = done.closest('section')!
    expect(within(section).getByText(/Aprobada por op/)).toBeInTheDocument()
    expect(within(section).getByText('bloqueo ejecutado')).toBeInTheDocument()
    expect(screen.getByText('No hay aprobaciones pendientes')).toBeInTheDocument()
  })

  it('403: mensaje de rol insuficiente y el ítem no se quita', async () => {
    const { user } = await openApprovals('N1', () => json(403, { detail: 'Esta aprobación requiere rol N1 o superior' }))
    await user.click(screen.getByRole('button', { name: /Rechazar/ }))
    await user.click(screen.getByRole('button', { name: 'Confirmar rechazo' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Tu rol (N1) no alcanza para este nivel')
    expect(screen.getByRole('heading', { name: /Aprobaciones pendientes \(1\)/ })).toBeInTheDocument()
  })

  it('409: "ya fue resuelta por otro operador" y se refresca la lista', async () => {
    const { user, calls } = await openApprovals('N1', () => json(409, { detail: 'Ya resuelta (approved)' }))
    const listCallsBefore = calls.filter((c) => c.url === '/api/v1/dashboard/approvals').length
    await user.click(screen.getByRole('button', { name: /Aprobar/ }))
    await user.click(screen.getByRole('button', { name: 'Confirmar bloqueo' }))
    expect(await screen.findByRole('status', { name: '' })).toHaveTextContent('Ya fue resuelta por otro operador')
    await waitFor(() =>
      expect(calls.filter((c) => c.url === '/api/v1/dashboard/approvals').length).toBeGreaterThan(listCallsBefore))
  })

  it('cancelar la confirmación no envía nada', async () => {
    const { user, calls } = await openApprovals('N1', () => json(200, approval({ status: 'approved' })))
    await user.click(screen.getByRole('button', { name: /Aprobar/ }))
    await user.click(screen.getByRole('button', { name: 'Cancelar' }))
    expect(calls.some((c) => c.url.endsWith('/resolve'))).toBe(false)
    expect(screen.getByRole('button', { name: /Aprobar/ })).toBeInTheDocument()
  })

  it('nivel por encima del rol: sin botones, con explicación', async () => {
    await openApprovals('N1', () => json(200, {}), [approval({ approval_level: 'N2' })])
    expect(screen.queryByRole('button', { name: /Aprobar/ })).not.toBeInTheDocument()
    expect(screen.getByText('Requiere rol N2 o superior.')).toBeInTheDocument()
  })

  it('nivel vacío o desconocido exige CISO (mismo fail-closed que el backend)', async () => {
    await openApprovals('N2', () => json(200, {}), [approval({ approval_level: '' })])
    expect(screen.queryByRole('button', { name: /Aprobar/ })).not.toBeInTheDocument()
    expect(screen.getByText('Requiere rol CISO o superior.')).toBeInTheDocument()
  })
})
