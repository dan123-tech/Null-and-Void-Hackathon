const TOKEN_KEY = 'cyber_sentinel_token'

export function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export async function login(email: string, password: string): Promise<void> {
  const body = new URLSearchParams()
  body.set('username', email)
  body.set('password', password)

  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!r.ok) throw new Error('Invalid credentials')
  const data = (await r.json()) as { access_token: string }
  setToken(data.access_token)
}

export async function fetchMe(): Promise<{ email: string; is_admin: boolean }> {
  const token = getToken()
  if (!token) throw new Error('Not authenticated')
  const r = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
  if (!r.ok) throw new Error('Not authenticated')
  return (await r.json()) as { email: string; is_admin: boolean }
}

