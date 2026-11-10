import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from 'react-router-dom'
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
import Logo from './components/Logo.jsx'
import { Empty, ErrorState, Icon, Loading, SessionContext, usePageTitle, useSession } from './components/ui.jsx'

const NAV_GROUPS = [
  { label: 'Monitor', items: [
    ['/', 'Fleet', 'dashboard'],
    ['/hosts', 'Hosts', 'hosts'],
    ['/findings', 'Findings', 'findings'],
    ['/drift', 'Drift', 'drift'],
  ] },
  { label: 'Act', items: [
    ['/remediation', 'Remediation', 'remediation'],
    ['/reports', 'Reports', 'reports'],
  ] },
  { label: 'Reference', items: [
    ['/benchmarks', 'Benchmarks', 'benchmarks'],
  ] },
]

function Brand() {
  return (
    <NavLink to="/" className="brand" aria-label="STIGWatch, fleet overview">
      <Logo size={24} />
      <span className="brand-name">STIGWatch</span>
    </NavLink>
  )
}

/** Where the page sits: the section, and for a host or rule page the levels above it. */
function Breadcrumb() {
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  const crumbs = []
  if (parts.length === 0) crumbs.push({ label: 'Fleet' })
  else if (parts[0] === 'hosts' && parts.length >= 2) {
    crumbs.push({ label: 'Hosts', to: '/hosts' })
    if (parts[2] === 'rules') crumbs.push({ label: 'Host', to: `/hosts/${parts[1]}` }, { label: 'Rule' })
    else crumbs.push({ label: 'Host' })
  } else {
    const found = NAV_GROUPS.flatMap((g) => g.items).find(([to]) => to === `/${parts[0]}`)
    crumbs.push({ label: found ? found[1] : 'Not found' })
  }
  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <ol>
        {crumbs.map((c, i) => (
          <li key={c.label} aria-current={i === crumbs.length - 1 ? 'page' : undefined}>
            {c.to ? <Link to={c.to}>{c.label}</Link> : c.label}
          </li>
        ))}
      </ol>
    </nav>
  )
}

function AccountArea({ onLogout, onSignIn }) {
  const { user, guest, authConfigured } = useSession()
  if (guest) {
    return authConfigured
      ? <button type="button" className="btn ghost" onClick={onSignIn}>Sign in</button>
      : null
  }
  return (
    <div className="account">
      <span className="account-user"><span className="sr-only">Signed in as </span>{user}</span>
      <button type="button" className="btn ghost" onClick={onLogout}>Sign out</button>
    </div>
  )
}

/** The foot of the sidebar: the demo status line and the version. */
function SideStatus() {
  const { guest, demo, version } = useSession()
  return (
    <div className="side-foot">
      {(guest || demo) && (
        <p className="badge demo" title="Hosted demo with an invented fleet. Browsing is read-only.">
          <i className="dot" aria-hidden="true" />{guest ? 'Demo, read-only' : 'Demo'}
        </p>
      )}
      <p className="side-version">STIGWatch v{version}</p>
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
  const mainRef = useRef(null)
  const menuRef = useRef(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const { pathname } = useLocation()
  useFocusOnNavigate(mainRef)
  useEffect(() => { setMenuOpen(false) }, [pathname])
  useEffect(() => {
    if (!menuOpen) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') { setMenuOpen(false); menuRef.current?.focus() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [menuOpen])
  const closeMenu = () => { setMenuOpen(false); menuRef.current?.focus() }
  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <div className={`sidebar${menuOpen ? ' open' : ''}`} id="sidebar">
        <div className="side-top">
          <Brand />
          <button type="button" className="icon-btn side-close" aria-label="Close menu" onClick={closeMenu}>
            <Icon name="close" />
          </button>
        </div>
        <nav className="nav" aria-label="Main">
          {NAV_GROUPS.map((g) => (
            <div key={g.label} className="nav-group">
              <p className="nav-label">{g.label}</p>
              <ul>
                {g.items.map(([to, label, icon]) => (
                  <li key={to}>
                    <NavLink to={to} end={to === '/'}><Icon name={icon} />{label}</NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <SideStatus />
      </div>
      {menuOpen && <div className="scrim" onClick={closeMenu} aria-hidden="true" />}
      <div className="column">
        <header className="topbar">
          <button type="button" ref={menuRef} className="icon-btn menu-btn" aria-label="Menu" aria-expanded={menuOpen}
            aria-controls="sidebar" onClick={() => setMenuOpen((o) => !o)}>
            <Icon name="menu" />
          </button>
          <span className="topbar-brand"><Brand /></span>
          <Breadcrumb />
          <div className="topbar-right">
            <a className="icon-btn" href={GITHUB_URL} target="_blank" rel="noreferrer" title="Source on GitHub">
              <Icon name="github" size={16} />
              <span className="sr-only">Source on GitHub (opens in a new tab)</span>
            </a>
            <AccountArea onLogout={onLogout} onSignIn={onSignIn} />
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
          <p className="disclaimer">{DISCLAIMER}</p>
          <p className="footer-meta">
            Ubuntu 22.04 LTS and Windows Server 2022 STIGs · read-only collectors ·{' '}
            <a href={GITHUB_URL} target="_blank" rel="noreferrer">Source on GitHub<span className="sr-only"> (opens in a new tab)</span></a>
          </p>
        </footer>
      </div>
    </div>
  )
}

function App() {
  // checking -> (anon | user); 'unconfigured' when the server has no admin and no guest access
  const [state, setState] = useState({ phase: 'checking' })

  const check = useCallback(async () => {
    try {
      const health = await api.health()
      const base = { version: health.version, demo: health.demo, authConfigured: health.auth_configured,
        maxUploadMb: health.max_upload_mb }
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
    authConfigured: state.authConfigured, maxUploadMb: state.maxUploadMb, signIn,
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
