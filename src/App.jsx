import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { api } from './api.js'
import { DISCLAIMER, GITHUB_URL } from './lib.js'
import Fleet from './pages/Fleet.jsx'
import Hosts from './pages/Hosts.jsx'
import HostDetail from './pages/HostDetail.jsx'
import RuleDetail from './pages/RuleDetail.jsx'
import Login from './pages/Login.jsx'
import Findings from './pages/Findings.jsx'
import Drift from './pages/Drift.jsx'
import Remediation from './pages/Remediation.jsx'
import Reports from './pages/Reports.jsx'
import Benchmarks from './pages/Benchmarks.jsx'
import { Empty, ErrorState, Icon, Loading, SessionContext, usePageTitle, useSession } from './components/ui.jsx'

const NAV = [
  ['/', 'Fleet'],
  ['/hosts', 'Hosts'],
  ['/findings', 'Findings'],
  ['/drift', 'Drift'],
  ['/remediation', 'Remediation'],
  ['/reports', 'Reports'],
  ['/benchmarks', 'Benchmarks'],
]

function Brand() {
  return (
    <NavLink to="/" className="brand" aria-label="STIGWatch, fleet overview">
      <span className="brand-mark" aria-hidden="true"><Icon name="radar" size={20} /></span>
      <span className="brand-text">
        <span className="brand-name">STIGWatch</span>
        <span className="brand-sub">DISA STIG compliance</span>
      </span>
    </NavLink>
  )
}

function AccountArea({ onLogout, onSignIn }) {
  const { user, guest, demo, authConfigured } = useSession()
  if (guest) {
    return (
      <div className="account">
        <span className="badge demo" title="Hosted demo with an invented fleet. Browsing is read-only.">
          <Icon name="lock" size={14} /> Demo · read-only
        </span>
        {authConfigured && (
          <button type="button" className="btn ghost small" onClick={onSignIn}>Sign in</button>
        )}
      </div>
    )
  }
  return (
    <div className="account">
      {demo && <span className="badge demo" title="Hosted demo with an invented fleet.">Demo</span>}
      <span className="account-user"><span className="sr-only">Signed in as </span>{user}</span>
      <button type="button" className="btn ghost small" onClick={onLogout}>Sign out</button>
    </div>
  )
}

/** Move focus to the page heading after navigation so screen readers announce the new page. */
function useFocusOnNavigate(mainRef) {
  const { pathname } = useLocation()
  const previous = useRef(pathname)
  useEffect(() => {
    if (previous.current === pathname) return undefined
    previous.current = pathname
    window.scrollTo(0, 0)
    let frame = 0
    const started = performance.now()
    const tryFocus = () => {
      const heading = mainRef.current?.querySelector('h1')
      if (heading) heading.focus({ preventScroll: true })
      else if (performance.now() - started < 3000) frame = requestAnimationFrame(tryFocus)
    }
    frame = requestAnimationFrame(tryFocus)
    return () => cancelAnimationFrame(frame)
  }, [pathname, mainRef])
}

function NotFound() {
  usePageTitle('Not found')
  return <Empty><h1 tabIndex={-1} className="h-inline">Page not found.</h1></Empty>
}

function Shell({ onLogout, onSignIn }) {
  const { version } = useSession()
  const mainRef = useRef(null)
  useFocusOnNavigate(mainRef)
  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <Brand />
          <nav className="nav" aria-label="Main">
            <ul>
              {NAV.map(([to, label]) => (
                <li key={to}><NavLink to={to} end={to === '/'}>{label}</NavLink></li>
              ))}
            </ul>
          </nav>
          <div className="topbar-right">
            <a className="gh-link" href={GITHUB_URL} target="_blank" rel="noreferrer">
              <Icon name="github" size={18} /><span className="gh-text">GitHub</span>
              <span className="sr-only"> (opens in a new tab)</span>
            </a>
            <AccountArea onLogout={onLogout} onSignIn={onSignIn} />
          </div>
        </div>
      </header>
      <main id="main" className="main" ref={mainRef}>
        <Routes>
          <Route path="/" element={<Fleet />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/hosts/:hostId" element={<HostDetail />} />
          <Route path="/hosts/:hostId/rules/:stigId" element={<RuleDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/drift" element={<Drift />} />
          <Route path="/remediation" element={<Remediation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/benchmarks" element={<Benchmarks />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
      <footer className="footer">
        <div className="footer-inner">
          <p className="disclaimer">{DISCLAIMER}</p>
          <p className="footer-meta">
            STIGWatch v{version} · Ubuntu 22.04 LTS and Windows Server 2022 STIGs · read-only collectors ·{' '}
            <a href={GITHUB_URL} target="_blank" rel="noreferrer">Source on GitHub<span className="sr-only"> (opens in a new tab)</span></a>
          </p>
        </div>
      </footer>
    </div>
  )
}

function App() {
  // checking -> (anon | user); 'unconfigured' when the server has no admin and no guest access
  const [state, setState] = useState({ phase: 'checking' })

  const check = useCallback(async () => {
    try {
      const health = await api.health()
      const base = { version: health.version, demo: health.demo, authConfigured: health.auth_configured }
      if (!health.guest && !health.auth_configured) return setState({ phase: 'unconfigured' })
      let me
      try {
        me = await api.me()
      } catch (err) {
        if (err.status === 401) return setState({ phase: 'anon', ...base })
        throw err
      }
      setState({ phase: 'user', user: me.username, guest: me.guest, ...base })
    } catch (error) {
      setState({ phase: 'error', error })
    }
  }, [])

  useEffect(() => { check() }, [check])

  // Any API call that comes back 401 (session expired) returns to the sign-in screen.
  useEffect(() => {
    const expire = () => setState((s) => (s.phase === 'user'
      ? { ...s, phase: 'anon', notice: 'Your session has expired. Sign in again.' }
      : s))
    window.addEventListener('stigwatch:unauthorized', expire)
    return () => window.removeEventListener('stigwatch:unauthorized', expire)
  }, [])

  const signIn = useCallback(() => setState((s) => ({ ...s, phase: 'anon', canCancel: true, notice: undefined })), [])

  const session = useMemo(() => (state.phase === 'user' ? {
    user: state.user, guest: state.guest, demo: state.demo, version: state.version,
    authConfigured: state.authConfigured, signIn,
  } : null), [state, signIn])

  async function logout() {
    try { await api.logout() } catch { /* clearing local state is enough */ }
    await check() // demo mode lands back on the guest view; otherwise on the sign-in page
  }

  if (state.phase === 'checking') return <div className="center-wrap"><Loading label="Connecting…" /></div>
  if (state.phase === 'error') {
    return <div className="center-wrap"><ErrorState error={state.error} onRetry={check} /></div>
  }
  if (state.phase === 'unconfigured') {
    return (
      <div className="center-wrap">
        <div className="state error" role="alert">
          No admin account is configured on the server. Run{' '}
          <code>python -m stigwatch create-admin</code> (or set the STIGWATCH_* environment variables
          on your host) and restart the API.
        </div>
      </div>
    )
  }
  if (state.phase === 'anon') {
    return (
      <Login notice={state.notice} onLogin={check}
        onCancel={state.canCancel ? () => setState((s) => ({ ...s, phase: 'user', canCancel: false })) : undefined} />
    )
  }
  return (
    <SessionContext.Provider value={session}>
      <BrowserRouter>
        <Shell onLogout={logout} onSignIn={signIn} />
      </BrowserRouter>
    </SessionContext.Provider>
  )
}

export default App
