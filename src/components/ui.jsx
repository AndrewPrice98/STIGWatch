import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowDown, ArrowLeft, ArrowRight, ArrowUp, Check, Copy, Download, ExternalLink, Eye, EyeOff, FileText,
  GitCompareArrows, Info, LayoutDashboard, Library, Lock, Menu, Pencil, Plus, Search, Server, ShieldAlert,
  Terminal, TriangleAlert, Upload, Wrench, X,
} from 'lucide-react'
import { STATUS_INFO, asyncView } from '../lib.js'

// -- status and severity: always a text label, never colour alone -----------------------------

/** Status: a 6 px dot plus the label. The dot repeats the tone; the text carries the meaning. */
export function StatusChip({ status }) {
  const s = STATUS_INFO[status] || { label: status, tone: 'neutral' }
  return (
    <span className={`status ${s.tone}`}>
      <i className="dot" aria-hidden="true" />
      {s.label}
    </span>
  )
}

const CAT_CLASS = { 'CAT I': 'cat1', 'CAT II': 'cat2', 'CAT III': 'cat3' }
const CAT_SEVERITY_WORD = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

/** Severity tag: the CAT text on a faint tint of the severity hue. */
export function CatBadge({ cat, withSeverity }) {
  return (
    <span className={`cat ${CAT_CLASS[cat] || ''}`} title={`${cat}: ${CAT_SEVERITY_WORD[cat] || ''} severity`}>
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

/** Error panel. A 503 (the demo data is still being prepared) is a friendly retry state that retries itself. */
export function ErrorState({ error, onRetry }) {
  const waiting = error?.status === 503
  const delay = Math.min(Math.max(error?.retryAfter || 3, 2), 30)
  useEffect(() => {
    if (!waiting || !onRetry) return undefined
    const t = setTimeout(onRetry, delay * 1000)
    return () => clearTimeout(t)
  }, [waiting, onRetry, delay])
  if (waiting) {
    return (
      <div className="state" role="status">
        <span className="spinner" aria-hidden="true" />
        <span>
          <strong>The demo data is not ready yet.</strong> It is being prepared and this usually takes a few
          seconds. Trying again automatically.
        </span>
        {onRetry && <button type="button" className="link" onClick={onRetry}>Try now</button>}
      </div>
    )
  }
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

/**
 * Page heading: a 21 px title with at most one short muted line under it. The h1 takes focus
 * after navigation. `children` is for the rare extra row (host metadata).
 */
export function PageHead({ title, sub, children, actions, back }) {
  return (
    <header className="page-head">
      <div className="page-head-main">
        {back && (
          <Link className="back-link" to={back.to}><Icon name="back" size={14} />{back.label}</Link>
        )}
        <h1 tabIndex={-1}>{title}</h1>
        {sub && <p className="page-sub">{sub}</p>}
        {children}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

/** A flat panel: a hairline-bordered surface with an optional heading row. `flush` drops the body padding (tables). */
export function Panel({ id, title, desc, actions, flush, live, className = '', children }) {
  const titleId = id ? `${id}-title` : undefined
  return (
    <section id={id} className={`panel ${className}`} aria-labelledby={title ? titleId : undefined}>
      {(title || actions) && (
        <div className="panel-head">
          <div>
            {title && <h2 id={titleId} aria-live={live ? 'polite' : undefined}>{title}</h2>}
            {desc && <p className="panel-desc">{desc}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      <div className={flush ? 'panel-flush' : 'panel-body'}>{children}</div>
    </section>
  )
}

/** A plain one-row notice: an icon and text on the surface, no coloured edge. */
export function Notice({ icon = 'info', tone = '', title, children, actions }) {
  return (
    <div className={`notice ${tone}`} role="note">
      <Icon name={icon} size={16} />
      <div className="notice-text">
        {title && <p className="notice-title">{title}</p>}
        {children}
      </div>
      {actions && <div className="notice-actions">{actions}</div>}
    </div>
  )
}

/** The long version of a page's explanation, folded away behind a disclosure. */
export function About({ children }) {
  return (
    <details className="about">
      <summary>About this view</summary>
      <div className="about-body">{children}</div>
    </details>
  )
}

const ICONS = {
  back: ArrowLeft,
  arrow: ArrowRight,
  lock: Lock,
  alert: TriangleAlert,
  info: Info,
  check: Check,
  download: Download,
  terminal: Terminal,
  server: Server,
  eye: Eye,
  eyeOff: EyeOff,
  up: ArrowUp,
  down: ArrowDown,
  edit: Pencil,
  copy: Copy,
  upload: Upload,
  plus: Plus,
  file: FileText,
  external: ExternalLink,
  menu: Menu,
  close: X,
  search: Search,
  dashboard: LayoutDashboard,
  hosts: Server,
  findings: ShieldAlert,
  drift: GitCompareArrows,
  remediation: Wrench,
  reports: FileText,
  benchmarks: Library,
}

/** Stroke icons from lucide-react (16 px, 1.5 stroke, current colour). GitHub is a brand mark, drawn here. */
export function Icon({ name, size = 16, label }) {
  const a11y = {
    'aria-hidden': label ? undefined : 'true', role: label ? 'img' : undefined, 'aria-label': label, focusable: 'false',
  }
  if (name === 'github') {
    return (
      <svg className="icon" width={size} height={size} viewBox="0 0 20 20" fill="currentColor" {...a11y}>
        <path d="M10 1.5a8.5 8.5 0 0 0-2.7 16.6c.4 0 .6-.2.6-.4v-1.5c-2.4.5-2.9-1-2.9-1-.4-1-1-1.3-1-1.3-.8-.5 0-.5 0-.5.9 0 1.3.9 1.3.9.8 1.3 2 1 2.5.7 0-.6.3-1 .6-1.2-1.9-.2-3.9-1-3.9-4.2 0-.9.3-1.7.9-2.3-.1-.2-.4-1.1.1-2.3 0 0 .7-.2 2.3.9a8 8 0 0 1 4.2 0c1.6-1.1 2.3-.9 2.3-.9.5 1.2.2 2 .1 2.3.5.6.9 1.4.9 2.3 0 3.3-2 4-3.9 4.2.3.3.6.8.6 1.6v2.4c0 .2.2.5.6.4A8.5 8.5 0 0 0 10 1.5Z" />
      </svg>
    )
  }
  const Glyph = ICONS[name]
  if (!Glyph) return null
  return <Glyph className="icon" size={size} strokeWidth={1.5} {...a11y} />
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

/**
 * Run an async loader whenever deps change. Ignores stale responses, and never hands back the
 * data of the previous deps: the render in which the deps change already reports loading with
 * no data, so host B's URL can never show (or act on) host A's data. `reload()` re-runs the
 * same loader and keeps the current data on screen while it does.
 */
export function useAsync(loader, deps) {
  const [state, setState] = useState({ owner: null, loading: true, error: null, data: null })
  const [tick, setTick] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps)
  useEffect(() => {
    let live = true
    setState((s) => (s.owner === load ? { ...s, loading: true, error: null } : { owner: load, loading: true, error: null, data: null }))
    load()
      .then((data) => live && setState({ owner: load, loading: false, error: null, data }))
      .catch((error) => live && setState({ owner: load, loading: false, error, data: null }))
    return () => { live = false }
  }, [load, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  const current = asyncView(state, load)
  return { loading: current.loading, error: current.error, data: current.data, reload }
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
