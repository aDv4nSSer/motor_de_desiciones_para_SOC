import { vi } from 'vitest'

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>

/** fetch mockeado que enruta por path; registra cada llamada. */
export function mockFetch(routes: Record<string, Handler>) {
  const calls: { url: string; init?: RequestInit }[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    calls.push({ url, init })
    const key = Object.keys(routes).find((k) => url.startsWith(k))
    if (!key) return json(404, { detail: `sin mock para ${url}` })
    return routes[key](url, init)
  })
  vi.stubGlobal('fetch', fn)
  return { fn, calls }
}

export const LOGIN_OK: Handler = () => json(200, { access_token: 'tok-test', token_type: 'bearer', role: 'N1' })
