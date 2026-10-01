import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { json, LOGIN_OK, mockFetch } from './helpers'

function renderApp() {
  return render(<AuthProvider><App /></AuthProvider>)
}

async function login(user = userEvent.setup()) {
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
}

const EMPTY_ALERTS = {
  '/api/v1/dashboard/decisions': () => json(200, []),
  '/api/v1/dashboard/blocks/recent': () => json(200, []),
  '/api/v1/dashboard/stats': () => json(200, { available: true, window_minutes: 60, total_decisiones: 0, por_tier: {} }),
}

describe('login', () => {
  it('credenciales inválidas (401) muestran error y no entran', async () => {
    mockFetch({ '/api/v1/auth/login': () => json(401, { detail: 'Credenciales inválidas' }) })
    renderApp()
    await login()
    expect(await screen.findByRole('alert')).toHaveTextContent('Usuario o contraseña incorrectos')
    expect(screen.getByLabelText('Contraseña')).toHaveValue('')
  })

  it('motor sin poder verificar (503) da un mensaje distinto al de credenciales', async () => {
    mockFetch({ '/api/v1/auth/login': () => json(503, { detail: 'No se pudo verificar' }) })
    renderApp()
    await login()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('no pudo verificar las credenciales')
    expect(alert).not.toHaveTextContent('incorrectos')
  })

  it('el token va en memoria como Bearer, nunca a localStorage', async () => {
    const { calls } = mockFetch({ '/api/v1/auth/login': LOGIN_OK, ...EMPTY_ALERTS })
    renderApp()
    await login()
    await screen.findByText('No hay alertas T2 o T3 recientes')
    const authed = calls.find((c) => c.url.startsWith('/api/v1/dashboard/decisions'))!
    expect(new Headers(authed.init?.headers).get('Authorization')).toBe('Bearer tok-test')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })
})

describe('sesión durante el uso', () => {
  it('401 en una llamada protegida vuelve al login con el motivo', async () => {
    mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/decisions': () => json(401, { detail: 'Sesión revocada, inicie sesión nuevamente' }),
      '/api/v1/dashboard/blocks/recent': () => json(200, []),
      '/api/v1/dashboard/stats': () => json(200, { available: false, window_minutes: 60 }),
    })
    renderApp()
    await login()
    expect(await screen.findByText(/Tu sesión expiró o fue revocada/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Iniciar sesión' })).toBeInTheDocument()
  })

  it('503 muestra "reintentando" y NO saca al operador de la sesión', async () => {
    mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      // Con Redis caído, get_current_user responde 503 en TODA llamada protegida.
      '/api/v1/dashboard/': () => json(503, { detail: 'No se pudo verificar el usuario, reintente' }),
    })
    renderApp()
    await login()
    expect(await screen.findByText(/No se puede verificar tu sesión, reintentando/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Cerrar sesión/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Iniciar sesión' })).not.toBeInTheDocument()
  })

  it('el banner de 503 desaparece cuando una llamada vuelve a responder', async () => {
    let healthy = false
    mockFetch({
      '/api/v1/auth/login': LOGIN_OK,
      '/api/v1/dashboard/stats': () => (healthy ? json(200, { available: false, window_minutes: 60 }) : json(503, {})),
      '/api/v1/dashboard/': () => (healthy ? json(200, []) : json(503, {})),
    })
    const user = userEvent.setup()
    renderApp()
    await login(user)
    await screen.findByText(/reintentando/)
    healthy = true
    await user.click(screen.getByRole('button', { name: /Actualizar/ }))
    await waitFor(() => expect(screen.queryByText(/reintentando/)).not.toBeInTheDocument())
  })
})
