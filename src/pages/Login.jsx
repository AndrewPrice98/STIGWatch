import { useState } from 'react'
import { api } from '../api.js'
import { DISCLAIMER } from '../lib.js'
import Logo from '../components/Logo.jsx'
import { usePageTitle } from '../components/ui.jsx'

export default function Login({ onLogin, notice, onCancel }) {
  usePageTitle('Sign in')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.login(username.trim(), password)
      setPassword('')
      await onLogin()
    } catch (err) {
      setError(err.status === 429 ? 'Too many failed attempts. Wait a few minutes and try again.' : err.message)
      setBusy(false)
    }
  }

  return (
    <main className="login-wrap">
      <form className="login" onSubmit={submit} aria-labelledby="login-title">
        <div className="login-brand">
          <Logo size={28} />
          <span className="brand-name">STIGWatch</span>
        </div>
        <h1 id="login-title">Sign in</h1>
        <p className="muted">Admins can upload scans and record assessor comments. Everyone else can browse read-only.</p>
        {notice && <div className="state" role="status">{notice}</div>}
        <label className="field">
          <span>Username</span>
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)}
            maxLength={128} required autoFocus />
        </label>
        <label className="field">
          <span>Password</span>
          <input type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} maxLength={1024} required />
        </label>
        {error && <div className="state error" role="alert">{error}</div>}
        <button className="btn primary block" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        {onCancel && (
          <button type="button" className="btn ghost block" onClick={onCancel}>Back to the read-only demo</button>
        )}
        <p className="disclaimer">{DISCLAIMER}</p>
      </form>
    </main>
  )
}
