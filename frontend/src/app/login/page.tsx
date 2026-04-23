'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'

import { login } from '../../lib/auth'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('daniel.cocu4@gmail.com')
  const [password, setPassword] = useState('123456789')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr(null)
    setBusy(true)
    try {
      await login(email, password)
      router.replace('/dashboard')
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="loginWrap">
      <div className="loginCard">
        <div className="brandTitle">CYBER-SENTINEL</div>
        <div className="muted" style={{ marginTop: 6 }}>
          Secure access to the Digital Twin dashboard.
        </div>

        <form onSubmit={onSubmit} className="loginForm">
          <label className="field">
            <div className="k">EMAIL</div>
            <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">
            <div className="k">PASSWORD</div>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {err ? <div className="error">{err}</div> : null}
          <button className="dangerBtn" type="submit" disabled={busy}>
            {busy ? 'Authenticating…' : 'Enter Command Center'}
          </button>
        </form>
      </div>
    </div>
  )
}

