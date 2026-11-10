import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { STATUS_INFO } from '../lib.js'

// -- status and severity: always a text label, never colour alone -----------------------------

/** Status chip: glyph + text + tone. */
export function StatusChip({ status, small }) {
  const s = STATUS_INFO[status] || { label: status, tone: 'neutral', glyph: '' }
  return (
    <span className={`chip ${s.tone}${small ? ' small' : ''}`}>
      {s.glyph && <span className="chip-glyph" aria-hidden="true">{s.glyph}</span>}
      {s.label}
    </span>
  )
}

const CAT_CLASS = { 'CAT I': 'cat1', 'CAT II': 'cat2', 'CAT III': 'cat3' }
const CAT_SEVERITY_WORD = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

/** Severity badge: "CAT I" text with its colour and a severity bar glyph. */
export function CatBadge({ cat, withSeverity }) {
  return (
    <span className={`cat ${CAT_CLASS[cat] || ''}`} title={`${cat}: ${CAT_SEVERITY_WORD[cat] || ''} severity`}>
      <span className="cat-bars" aria-hidden="true"><i /><i /><i /></span>
      {cat}{withSeverity && <span className="cat-sev"> · {CAT_SEVERITY_WORD[cat]}</span>}
    </span>
  )
}

/** A count of open findings for one CAT; zero is shown muted with a dash for screen readers too. */
export function OpenCount({ n, cat }) {
  if (!n) {
    return <span className="count zero"><span aria-hidden="true">0</span><span className="sr-only">no open {cat}</span></span>
  }
  return <span className={`count ${CAT_CLASS[cat]}`}>{n}<span className="sr-only"> open {cat}</span></span>
}

export function Loading({ label = 'Loading…' }) {
  return (
    <div className="state" role="status">
      <span className="spinner" aria-hidden="true" /> {label}
    </div>
  )
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="state error" role="alert">
      <strong>Something went wrong.</strong> {error?.message || String(error)}
      {onRetry && <> <button type="button" className="link" onClick={onRetry}>Try again</button></>}
    </div>
  )
}

export function Empty({ children }) {
  return <div className="state">{children}</div>
}

/** Page wrapper with the standard heading block. The h1 takes focus after navigation. */
export function PageHead({ eyebrow, title, children, actions, back }) {
  return (
    <header className="page-head">
      <div className="page-head-main">
        {back && (
          <Link className="back-link" to={back.to}><Icon name="back" size={16} />{back.label}</Link>
        )}
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1 tabIndex={-1}>{title}</h1>
        {children}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Icon({ name, size = 16, label }) {
  const paths = {
    github: <path d="M10 1.5a8.5 8.5 0 0 0-2.7 16.6c.4 0 .6-.2.6-.4v-1.5c-2.4.5-2.9-1-2.9-1-.4-1-1-1.3-1-1.3-.8-.5 0-.5 0-.5.9 0 1.3.9 1.3.9.8 1.3 2 1 2.5.7 0-.6.3-1 .6-1.2-1.9-.2-3.9-1-3.9-4.2 0-.9.3-1.7.9-2.3-.1-.2-.4-1.1.1-2.3 0 0 .7-.2 2.3.9a8 8 0 0 1 4.2 0c1.6-1.1 2.3-.9 2.3-.9.5 1.2.2 2 .1 2.3.5.6.9 1.4.9 2.3 0 3.3-2 4-3.9 4.2.3.3.6.8.6 1.6v2.4c0 .2.2.5.6.4A8.5 8.5 0 0 0 10 1.5Z" fill="currentColor" stroke="none" />,
    back: <path d="M12.5 4.5 7 10l5.5 5.5" />,
    arrow: <><path d="M4 10h11" /><path d="m11 5.5 4.5 4.5-4.5 4.5" /></>,
    lock: <><rect x="4" y="9" width="12" height="8.5" rx="1.5" /><path d="M7 9V6.5a3 3 0 0 1 6 0V9" /></>,
    radar: <><circle cx="10" cy="10" r="7.5" /><circle cx="10" cy="10" r="3.2" /><path d="M10 2.5v2.8M10 14.7v2.8M2.5 10h2.8M14.7 10h2.8" /></>,
    alert: <><path d="M9.1 2.6 1.7 15.2A1.2 1.2 0 0 0 2.7 17h14.6a1.2 1.2 0 0 0 1-1.8L10.9 2.6a1 1 0 0 0-1.8 0Z" /><path d="M10 7.5v4" /><path d="M10 14.2v.1" /></>,
    info: <><circle cx="10" cy="10" r="7.5" /><path d="M10 9v5" /><path d="M10 6.2v.1" /></>,
    check: <path d="m4.5 10.5 3.5 3.5 7.5-8" />,
    download: <><path d="M10 3v10" /><path d="m5.5 8.5 4.5 4.5 4.5-4.5" /><path d="M3.5 16.5h13" /></>,
    terminal: <><rect x="2.5" y="3.5" width="15" height="13" rx="1.5" /><path d="m6 8 2.5 2L6 12" /><path d="M10.5 12.5H14" /></>,
    server: <><rect x="3" y="3" width="14" height="5.5" rx="1.2" /><rect x="3" y="11.5" width="14" height="5.5" rx="1.2" /><path d="M6 5.8h.1M6 14.3h.1" /></>,
    eye: <><path d="M1.8 10S5 4.5 10 4.5 18.2 10 18.2 10 15 15.5 10 15.5 1.8 10 1.8 10Z" /><circle cx="10" cy="10" r="2.5" /></>,
    eyeOff: <><path d="M3 3l14 14" /><path d="M8.2 4.7A8 8 0 0 1 10 4.5c5 0 8.2 5.5 8.2 5.5a14 14 0 0 1-2.3 2.9M5.4 6.4A13.6 13.6 0 0 0 1.8 10S5 15.5 10 15.5a7.6 7.6 0 0 0 3.5-.9" /></>,
    up: <><path d="M10 16V4" /><path d="m5 9 5-5 5 5" /></>,
    down: <><path d="M10 4v12" /><path d="m5 11 5 5 5-5" /></>,
    edit: <path d="m12.5 4 3.5 3.5L7.5 16H4v-3.5L12.5 4Z" />,
    external: <><path d="M11 3.5h5.5V9" /><path d="M16.5 3.5 9 11" /><path d="M14 12v4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h4" /></>,
  }
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor"
      strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden={label ? undefined : 'true'} role={label ? 'img' : undefined} aria-label={label}
      focusable="false">
      {paths[name]}
    </svg>
  )
}

/** Inline result of a save: announced politely. */
export function FormMessage({ message }) {
  return <span role="status" className={`form-msg ${message?.tone || ''}`}>{message?.text}</span>
}

// -- session and data hooks -----------------------------------------------------------------

export const SessionContext = createContext(null)

/** { user, guest, demo, version, authConfigured, signIn } */
export function useSession() {
  return useContext(SessionContext)
}

export function usePageTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} · STIGWatch` : 'STIGWatch'
  }, [title])
}

/** Run an async loader whenever deps change. Ignores stale responses. */
export function useAsync(loader, deps) {
  const [state, setState] = useState({ loading: true, error: null, data: null })
  const [tick, setTick] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps)
  useEffect(() => {
    let live = true
    setState((s) => ({ ...s, loading: true, error: null }))
    load()
      .then((data) => live && setState({ loading: false, error: null, data }))
      .catch((error) => live && setState({ loading: false, error, data: null }))
    return () => { live = false }
  }, [load, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { ...state, reload }
}

/** Width of an element, kept current with ResizeObserver (charts draw at real pixel size). */
export function useWidth(ref, fallback = 640) {
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    setWidth(el.clientWidth || fallback)
    if (typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver((entries) => {
      const w = Math.round(entries[0].contentRect.width)
      if (w > 0) setWidth(w)
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref, fallback])
  return width
}
