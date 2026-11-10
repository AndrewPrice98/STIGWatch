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

/**
 * Compliance percentage: NotAFinding ÷ (Open + NotAFinding), one decimal. Not_Reviewed and
 * Not_Applicable are excluded (shown separately), so a rule nobody could check never counts
 * as compliant. Returns null when nothing was decided.
 */
export function compliancePct(status) {
  const open = status?.Open || 0
  const naf = status?.NotAFinding || 0
  const decided = open + naf
  if (!decided) return null
  return Math.round((1000 * naf) / decided) / 10
}

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

// -- privilege gaps: Not_Reviewed because the collector ran without root / Administrator ------

const PRIVILEGE_PATTERNS = [
  /requires root/i,
  /permission denied/i,
  /access (is )?denied/i,
  /run the collector (with sudo|as root|elevated|as administrator)/i,
  /not (running )?elevated/i,
  /requires (administrator|elevation|admin)/i,
  /run as administrator/i,
]

export function isPrivilegeGap(result) {
  return result.status === 'Not_Reviewed' && PRIVILEGE_PATTERNS.some((p) => p.test(result.reason || ''))
}

/**
 * Not_Reviewed results that a privileged collector run would have decided.
 * { count, cat1, unprivileged } where unprivileged is true when it is a pattern (5 or more),
 * not a single unreadable file.
 */
export function privilegeGaps(results) {
  const gaps = results.filter(isPrivilegeGap)
  return {
    count: gaps.length,
    cat1: gaps.filter((r) => r.cat === 'CAT I').length,
    unprivileged: gaps.length >= 5,
  }
}

// -- the regression story (Start here) --------------------------------------------------------

/**
 * Turns CAT I regression alerts into the "Start here" story: the scan week with the most
 * CAT I regressions (the latest such week on a tie). Week numbers come from the fleet trend
 * (week 1 is the first trend point). Returns null when there are no alerts.
 */
export function regressionStory(alerts, trend = []) {
  const regressions = (alerts || []).filter((a) => a.kind === 'cat1_regression' || a.cat === 'CAT I')
  if (!regressions.length) return null
  const byDay = new Map()
  for (const a of regressions) {
    const day = String(a.created_at).slice(0, 10)
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

/** Evenly spaced integer-friendly ticks from 0 to max. */
export function ticks(max, count = 4) {
  const step = max / count
  return Array.from({ length: count + 1 }, (_, i) => Math.round(i * step * 100) / 100)
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
