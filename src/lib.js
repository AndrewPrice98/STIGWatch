// Pure helpers with no React, so Node's test runner can import them (npm test).

export const DISCLAIMER =
  "STIGWatch is an independent tool. It is not a DISA product and does not replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review."

export const GITHUB_URL = 'https://github.com/AndrewPrice98/STIGWatch'

export const CATS = ['CAT I', 'CAT II', 'CAT III']
export const CAT_SEVERITY = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

/** STIG Viewer status vocabulary. Order is the order findings are worked: Open first. */
export const STATUSES = ['Open', 'Not_Reviewed', 'NotAFinding', 'Not_Applicable']

export const STATUS_INFO = {
  Open: { label: 'Open', tone: 'bad', glyph: '✕' },
  NotAFinding: { label: 'Not a finding', tone: 'good', glyph: '✓' },
  Not_Applicable: { label: 'Not applicable', tone: 'neutral', glyph: '–' },
  Not_Reviewed: { label: 'Not reviewed', tone: 'warn', glyph: '?' },
}

export const OS_LABEL = { linux: 'Ubuntu 22.04 LTS', windows: 'Windows Server 2022' }

export const COMPLIANCE_DEFINITION = 'Not a finding ÷ (Open + Not a finding)'

export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

/** "A", "A and B", "A, B and C", "A, B, C and 2 more". */
export function listWords(items, max = 3) {
  if (items.length <= 1) return items.join('')
  if (items.length > max) return `${items.slice(0, max).join(', ')} and ${items.length - max} more`
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}

// -- compliance -----------------------------------------------------------------------------

// The API supplies the compliance percentage (Not a finding ÷ (Open + Not a finding)); the
// dashboard only formats it.
export function formatPct(value) {
  return value == null ? '—' : `${value.toFixed(1)}%`
}

// -- week-over-week deltas --------------------------------------------------------------------

/**
 * Change in open findings of one CAT between the last two points of a trend
 * ([{week, open: {CAT I: n, ...}}, ...], oldest first). null when there is no previous point.
 */
export function weekDelta(trend, cat) {
  if (!Array.isArray(trend) || trend.length < 2) return null
  const last = trend[trend.length - 1].open?.[cat] ?? 0
  const prev = trend[trend.length - 2].open?.[cat] ?? 0
  return { current: last, previous: prev, change: last - prev, since: trend[trend.length - 2].week }
}

/**
 * Words and direction for a change in open findings: fewer open findings is better.
 * { arrow, text, tone, sr } where sr is the screen-reader sentence.
 */
export function describeDelta(change) {
  if (change == null) return null
  if (change === 0) return { arrow: '→', text: 'no change', tone: 'neutral', sr: 'no change from the previous week' }
  const n = Math.abs(change)
  if (change < 0) return { arrow: '↓', text: `${n} fewer`, tone: 'good', sr: `down ${n} from the previous week` }
  return { arrow: '↑', text: `${n} more`, tone: 'bad', sr: `up ${n} from the previous week` }
}

// -- host risk ordering -----------------------------------------------------------------------

/** Highest risk first: open CAT I, then CAT II, then CAT III, then lower compliance, then name. */
export function compareHostRisk(a, b) {
  for (const cat of CATS) {
    const d = (b.open?.[cat] || 0) - (a.open?.[cat] || 0)
    if (d) return d
  }
  const ca = a.compliance ?? 101
  const cb = b.compliance ?? 101
  if (ca !== cb) return ca - cb
  return String(a.name).localeCompare(String(b.name))
}

export function sortHostsByRisk(hosts) {
  return [...hosts].sort(compareHostRisk)
}

/** Hosts with any open CAT I or CAT II finding, riskiest first, at most `limit`. */
export function hostsAtRisk(hosts, limit = 6) {
  return sortHostsByRisk(hosts.filter((h) => (h.open?.['CAT I'] || 0) + (h.open?.['CAT II'] || 0) > 0))
    .slice(0, limit)
}

export const HOST_SORTS = {
  risk: 'Highest risk first',
  name: 'Name (A–Z)',
  compliance: 'Lowest compliance first',
  scanned: 'Most recently scanned',
}

export function sortHosts(hosts, key = 'risk') {
  const list = [...hosts]
  if (key === 'name') return list.sort((a, b) => String(a.name).localeCompare(String(b.name)))
  if (key === 'compliance') {
    return list.sort((a, b) => (a.compliance ?? 101) - (b.compliance ?? 101) || compareHostRisk(a, b))
  }
  if (key === 'scanned') {
    const at = (h) => h.latest_scan?.collected_at || ''
    return list.sort((a, b) => at(b).localeCompare(at(a)) || compareHostRisk(a, b))
  }
  return list.sort(compareHostRisk)
}

/** Client-side host filter: { os, environment, cat1, q }. Empty values mean "any". */
export function filterHosts(hosts, { os = '', environment = '', cat1 = false, q = '' } = {}) {
  const needle = q.trim().toLowerCase()
  return hosts.filter((h) => {
    if (os && h.os !== os) return false
    if (environment && String(h.environment).toLowerCase() !== environment.toLowerCase()) return false
    if (cat1 && !((h.open?.['CAT I'] || 0) > 0)) return false
    if (needle) {
      const hay = [h.name, h.owner, h.environment, OS_LABEL[h.os] || h.os, ...(h.tags || [])].join(' ').toLowerCase()
      if (!hay.includes(needle)) return false
    }
    return true
  })
}

/** Distinct environments in a fixed, sensible order (prod, staging, dev, then the rest A-Z). */
export function environments(hosts) {
  const order = ['prod', 'production', 'staging', 'test', 'dev', 'development']
  const set = [...new Set(hosts.map((h) => h.environment).filter(Boolean))]
  return set.sort((a, b) => {
    const ia = order.indexOf(a.toLowerCase())
    const ib = order.indexOf(b.toLowerCase())
    if (ia !== ib) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
    return a.localeCompare(b)
  })
}

// -- scan results -----------------------------------------------------------------------------

/** Open first, then Not reviewed, Not a finding, Not applicable; within a status CAT I first; then STIG ID. */
export function compareResults(a, b) {
  const sa = STATUSES.indexOf(a.status)
  const sb = STATUSES.indexOf(b.status)
  if (sa !== sb) return (sa === -1 ? 9 : sa) - (sb === -1 ? 9 : sb)
  const ca = CATS.indexOf(a.cat)
  const cb = CATS.indexOf(b.cat)
  if (ca !== cb) return (ca === -1 ? 9 : ca) - (cb === -1 ? 9 : cb)
  return String(a.stig_id).localeCompare(String(b.stig_id))
}

export function sortResults(results) {
  return [...results].sort(compareResults)
}

/** { status, cat, q } filter for result rows (status from STATUSES, cat from CATS). */
export function filterResults(results, { status = '', cat = '', q = '' } = {}) {
  const needle = q.trim().toLowerCase()
  return results.filter((r) => {
    if (status && r.status !== status) return false
    if (cat && r.cat !== cat) return false
    if (needle) {
      const hay = `${r.stig_id} ${r.group_id || ''} ${r.title || ''} ${r.reason || ''} ${r.comment || ''}`.toLowerCase()
      if (!hay.includes(needle)) return false
    }
    return true
  })
}

/** Per CAT: how many results of each status. { 'CAT I': {Open, NotAFinding, ..., total}, ... } */
export function catBreakdown(results) {
  const out = {}
  for (const cat of CATS) {
    out[cat] = { Open: 0, NotAFinding: 0, Not_Applicable: 0, Not_Reviewed: 0, total: 0 }
  }
  for (const r of results) {
    const row = out[r.cat]
    if (!row || !(r.status in row)) continue
    row[r.status] += 1
    row.total += 1
  }
  return out
}

// -- scan privilege ---------------------------------------------------------------------------

/**
 * The collector's own statement about how it ran. `scan.privileged` is tri-state: true (root /
 * Administrator), false (it was not), or null / missing (unknown). Only an explicit false
 * justifies the "ran without root" notice; unknown makes no claim either way.
 */
export function ranUnprivileged(scan) {
  return scan?.privileged === false
}

/** Not_Reviewed rules of a scan, from the API's own status counts. */
export function notReviewedCount(scan) {
  return scan?.status?.Not_Reviewed ?? 0
}

// -- the regression story (Start here) --------------------------------------------------------

/**
 * Turns CAT I regression alerts into the "Start here" story: the scan week with the most
 * CAT I regressions (the latest such week on a tie). Week numbers come from the fleet trend
 * (week 1 is the first trend point). Returns null when there are no alerts.
 */
export function regressionStory(alerts, trend = []) {
  // Alerts are bucketed by the day their scan was collected (`collected_at`, joined on by the
  // caller from the host's scan list), not by when the alert row was written.
  const regressions = (alerts || []).filter((a) => (a.kind === 'cat1_regression' || a.cat === 'CAT I') && a.collected_at)
  if (!regressions.length) return null
  const byDay = new Map()
  for (const a of regressions) {
    const day = String(a.collected_at).slice(0, 10)
    if (!byDay.has(day)) byDay.set(day, [])
    byDay.get(day).push(a)
  }
  let best = null
  for (const [day, items] of byDay) {
    if (!best || items.length > best.items.length || (items.length === best.items.length && day > best.day)) {
      best = { day, items }
    }
  }
  const weeks = trend.map((t) => t.week)
  const weekIndex = weekOf(best.day, weeks)
  const hosts = [...new Map(best.items.map((a) => [a.host_id, { id: a.host_id, name: a.host_name }])).values()]
    .sort((a, b) => a.name.localeCompare(b.name))
  const rules = [...best.items].sort((a, b) => a.host_name.localeCompare(b.host_name) || a.stig_id.localeCompare(b.stig_id))
  return { day: best.day, week: weekIndex, hosts, rules, total: regressions.length }
}

/** 1-based week of a date among weekly trend points (the last point on or before the date). */
export function weekOf(day, weeks) {
  let index = null
  weeks.forEach((w, i) => { if (w <= day) index = i + 1 })
  return index
}

// -- chart scales -----------------------------------------------------------------------------

/** A round axis maximum at or above `value` (1, 2, 2.5, 5 x 10^n), never below 1. */
export function niceMax(value) {
  if (!(value > 0)) return 1
  const exp = 10 ** Math.floor(Math.log10(value))
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * exp >= value) return step * exp
  }
  return 10 * exp
}

// -- STIG text ---------------------------------------------------------------------------------

/**
 * Splits DISA check/fix text into readable blocks: prose paragraphs and command/output
 * blocks. A line is code when it starts with "$ " or "# " (a prompt), or is indented by
 * 4+ spaces or a tab, or follows a code line directly. Text only: rendered as React text.
 */
export function splitStigText(text) {
  const blocks = []
  if (!text) return blocks
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n')
  let current = null
  const flush = () => {
    if (current) {
      const body = current.type === 'code'
        ? dedent(current.lines).join('\n').replace(/\s+$/, '')
        : current.lines.join(' ').replace(/\s+/g, ' ').trim()
      if (body) blocks.push({ type: current.type, text: body })
    }
    current = null
  }
  for (const line of lines) {
    if (!line.trim()) { flush(); continue }
    const isPrompt = /^\s*[$#] \S/.test(line) || /^\s*PS [A-Z]:\\?>/.test(line)
    const isIndented = /^(\s{4,}|\t)\S/.test(line)
    const type = isPrompt || isIndented || current?.type === 'code' ? 'code' : 'p'
    if (current && current.type !== type) flush()
    if (!current) current = { type, lines: [] }
    current.lines.push(line)
  }
  flush()
  return blocks
}

function dedent(lines) {
  const indents = lines.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length)
  const min = indents.length ? Math.min(...indents) : 0
  return lines.map((l) => l.slice(min))
}

/** A JSON-ish observed value as display text. */
export function formatObserved(value) {
  if (value === null || value === undefined) return 'none'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'object') return JSON.stringify(value, null, 2)
  return String(value)
}

// -- dates ---------------------------------------------------------------------------------------

/** Dates are shown in UTC, which is how the API stores them. */
export function formatDate(iso, { withYear = true } = {}) {
  if (!iso) return '—'
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString('en-US', {
    year: withYear ? 'numeric' : undefined, month: 'short', day: 'numeric', timeZone: 'UTC',
  })
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${formatDate(iso)}, ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC`
}

// -- fleet-wide findings (Findings page) -------------------------------------------------------

/**
 * Groups the latest-scan results of every host by STIG ID.
 * `perHost` is [{ host: {id, name, os}, results: [{stig_id, cat, status, title, ...}] }].
 * Each group lists the hosts where the rule is Open (`open`) and, separately, the hosts where it
 * is Not reviewed (`unchecked`): a rule nobody could check is not a finding and not a pass.
 * Rules that are not Open on any host are left out. Sorted by CAT, then most hosts, then STIG ID.
 */
export function groupFindings(perHost) {
  const groups = new Map()
  for (const { host, results } of perHost) {
    for (const r of results) {
      if (r.status !== 'Open' && r.status !== 'Not_Reviewed') continue
      let g = groups.get(r.stig_id)
      if (!g) {
        g = { stig_id: r.stig_id, title: r.title || '', cat: r.cat, os: host.os, open: [], unchecked: [] }
        groups.set(r.stig_id, g)
      }
      if (!g.title && r.title) g.title = r.title
      ;(r.status === 'Open' ? g.open : g.unchecked).push({ id: host.id, name: host.name })
    }
  }
  const catIndex = (c) => { const i = CATS.indexOf(c); return i === -1 ? 9 : i }
  return [...groups.values()]
    .filter((g) => g.open.length > 0)
    .map((g) => ({ ...g, open: sortByName(g.open), unchecked: sortByName(g.unchecked) }))
    .sort((a, b) => catIndex(a.cat) - catIndex(b.cat) || b.open.length - a.open.length || a.stig_id.localeCompare(b.stig_id))
}

function sortByName(list) {
  return [...list].sort((a, b) => String(a.name).localeCompare(String(b.name)))
}

/** { cat, os, q } filter for finding groups; empty means any. */
export function filterFindings(groups, { cat = '', os = '', q = '' } = {}) {
  const needle = q.trim().toLowerCase()
  return groups.filter((g) => {
    if (cat && g.cat !== cat) return false
    if (os && g.os !== os) return false
    if (needle && !`${g.stig_id} ${g.title}`.toLowerCase().includes(needle)) return false
    return true
  })
}

// -- fleet drift timeline (Drift page) ---------------------------------------------------------

/** Monday (UTC) of the week of an ISO date or timestamp, as YYYY-MM-DD: the key of a fleet trend point. */
export function weekStart(iso) {
  const d = new Date(`${String(iso).slice(0, 10)}T00:00:00Z`)
  if (Number.isNaN(d.getTime())) return ''
  const back = (d.getUTCDay() + 6) % 7
  d.setUTCDate(d.getUTCDate() - back)
  return d.toISOString().slice(0, 10)
}

const catChange = (now, before) => Object.fromEntries(CATS.map((c) => [c, (now?.[c] ?? 0) - (before?.[c] ?? 0)]))

/**
 * The weekly fleet timeline. `trend` is the fleet trend (oldest first); `hostScans` is
 * [{ host: {id, name}, scans: [...] }] with each scan {id, collected_at, open};
 * `alerts` are CAT I regression alerts ({scan_id, host_id, host_name, stig_id, ...}).
 * Each week lists the scans collected in it, with the host's net change in open findings
 * against the host's previous scan (a quick signal; the drift detail comes from the API),
 * and the CAT I regression alerts raised by those scans (matched by scan id, so the week is the
 * one the scan was collected in). Weeks are numbered from 1 like the fleet chart.
 */
export function buildTimeline(trend, hostScans, alerts) {
  const scanWeek = new Map()
  const weeks = trend.map((t, i) => ({
    week: t.week, n: i + 1, open: t.open, hosts: t.hosts, scans: [], alerts: [],
    change: i === 0 ? null : catChange(t.open, trend[i - 1].open),
  }))
  const byWeek = new Map(weeks.map((w) => [w.week, w]))
  for (const { host, scans } of hostScans) {
    const ordered = [...scans].sort((a, b) => String(a.collected_at).localeCompare(String(b.collected_at)) || a.id - b.id)
    ordered.forEach((s, i) => {
      const w = byWeek.get(weekStart(s.collected_at))
      if (!w) return
      scanWeek.set(s.id, w)
      const prev = ordered[i - 1]
      w.scans.push({
        id: s.id, host_id: host.id, host_name: host.name, collected_at: s.collected_at,
        first: !prev, change: prev ? catChange(s.open, prev.open) : null,
      })
    })
  }
  for (const a of alerts) {
    const w = scanWeek.get(a.scan_id)
    if (w) w.alerts.push(a)
  }
  for (const w of weeks) w.scans.sort((a, b) => a.host_name.localeCompare(b.host_name))
  return weeks
}

/** The week to open first: the latest one with a CAT I regression, otherwise the latest. */
export function defaultWeek(weeks) {
  const flagged = [...weeks].reverse().find((w) => w.alerts.length > 0)
  return (flagged || weeks[weeks.length - 1] || null)?.week ?? null
}

/** Section order and wording of drift categories, shared by the fleet Drift page. */
export const DRIFT_KINDS = [
  { id: 'regressed', label: 'Regressed', tone: 'bad', icon: 'up',
    help: 'Was Not a finding or Not applicable; Open now.' },
  { id: 'newly_visible_cat1', label: 'Newly visible CAT I', tone: 'bad', icon: 'eye',
    help: 'Not reviewed before, Open now. The finding may be old; it was not visible before.' },
  { id: 'newly_open', label: 'Newly open (other CATs)', tone: 'warn', icon: 'eye',
    help: 'Not reviewed before, Open now.' },
  { id: 'lost_visibility', label: 'Lost visibility', tone: 'warn', icon: 'eyeOff',
    help: 'Open before, Not reviewed now. Not known to be fixed: the collector could not check it this time.' },
  { id: 'fixed', label: 'Fixed', tone: 'good', icon: 'down',
    help: 'Was Open; Not a finding or Not applicable now.' },
]

/**
 * Merges per-scan drift documents into the DRIFT_KINDS groups. `drifts` is
 * [{ scan, drift }] where drift is the API's drift object. A host's first scan has nothing to
 * compare and is counted apart. Newly open leaves out CAT I (those are listed as newly visible
 * CAT I), like the host page.
 */
export function mergeDrift(drifts) {
  const out = { first: [], compared: 0 }
  for (const k of DRIFT_KINDS) out[k.id] = []
  for (const { scan, drift } of drifts) {
    if (!drift || drift.first_scan) { out.first.push(scan); continue }
    out.compared += 1
    for (const k of DRIFT_KINDS) {
      let items = drift[k.id] || []
      if (k.id === 'newly_open') items = items.filter((r) => r.cat !== 'CAT I')
      for (const r of items) out[k.id].push({ ...r, host_id: scan.host_id, host_name: scan.host_name, scan_id: scan.id })
    }
  }
  const catIndex = (c) => { const i = CATS.indexOf(c); return i === -1 ? 9 : i }
  for (const k of DRIFT_KINDS) {
    out[k.id].sort((a, b) => catIndex(a.cat) - catIndex(b.cat) || a.host_name.localeCompare(b.host_name) || a.stig_id.localeCompare(b.stig_id))
  }
  return out
}

/** Previous status of a CAT I regression alert ("went from NotAFinding to Open"), or ''. */
export function alertFrom(alert) {
  const m = /went from (NotAFinding|Not_Applicable|Open|Not_Reviewed) to Open/.exec(alert?.message || '')
  return m ? m[1] : ''
}

// -- remediation, reports, benchmarks ------------------------------------------------------------

/** The header every generated remediation file starts with. */
export const REVIEW_HEADER = 'Review before applying; test on a non-production host.'

export function remediationKind(os) {
  return os === 'windows'
    ? { label: 'PowerShell script', ext: '.ps1', lang: 'powershell' }
    : { label: 'Ansible playbook', ext: '.yml', lang: 'yaml' }
}

/** Collector instructions per OS, as copyable commands. Nothing here changes a host. */
export const COLLECTOR_STEPS = {
  linux: {
    title: 'Ubuntu 22.04 LTS',
    file: 'collectors/collect-linux.sh',
    commands: [
      '# read-only; writes one JSON file in the current directory',
      'sudo sh collect-linux.sh -o "stigwatch-$(hostname).json"',
      '# add -r to replace account names with account-N before the file leaves the host',
    ],
    note: 'Run it with sudo. Without root the privileged facts are recorded as unavailable and those rules are Not reviewed.',
  },
  windows: {
    title: 'Windows Server 2022',
    file: 'collectors/collect-windows.ps1',
    commands: [
      '# from an elevated PowerShell (Run as administrator); read-only',
      'powershell -ExecutionPolicy Bypass -File .\\collect-windows.ps1 -OutFile "stigwatch-$env:COMPUTERNAME.json"',
    ],
    note: 'Run it elevated. Without Administrator rights secedit, auditpol, BitLocker and similar facts are unavailable and those rules are Not reviewed.',
  },
}

export function formatBytes(n) {
  if (!(n >= 0)) return ''
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

/** Friendly sentence for a failed admin write (upload, add host). */
export function writeErrorMessage(err, what = 'The request') {
  const status = err?.status
  if (status === 403) return 'This demo is read-only: only an admin can make changes. Sign in as admin to continue.'
  if (status === 413) {
    // The API's own 413 names its limit; a platform 413 (for example Vercel's plain-text
    // FUNCTION_PAYLOAD_TOO_LARGE) has no usable text, so a fixed sentence is shown instead.
    const lead = err.fromApi && err.message ? err.message : 'The file is larger than the server accepts.'
    return `${lead} Collector output is normally well under a megabyte; check it is the right file.`
  }
  if (status === 502 || status === 504) return 'The server or gateway did not answer. Try again.'
  if (status === 503) return 'The server is not ready yet (the demo data is still being prepared). Wait a few seconds and try again.'
  if (status === 401) return 'Your session has expired. Sign in again.'
  if (status === 0) return 'Cannot reach the STIGWatch API. Check your connection and try again.'
  if (status === 400 || status === 409 || status === 415 || status === 422) return err.message || `${what} was refused.`
  return err?.message || `${what} failed.`
}

// -- async state ---------------------------------------------------------------------------------

/**
 * What a component may show for an async load. `state.owner` is the loader the state belongs to;
 * when the loader has changed (another host, another rule) the old data is withheld at once, in
 * the same render, so the previous host or rule is never shown or acted on.
 */
export function asyncView(state, load) {
  return state.owner === load ? state : { loading: true, error: null, data: null }
}
