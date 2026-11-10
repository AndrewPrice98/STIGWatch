import { useEffect, useMemo, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { api } from '../api.js'
import {
  CATS, COMPLIANCE_DEFINITION, STATUSES, STATUS_INFO, catBreakdown, filterResults, formatDate,
  formatDateTime, formatPct, notReviewedCount, plural, ranUnprivileged, sortResults,
} from '../lib.js'
import { UploadScan } from '../components/admin.jsx'
import { CatBars } from '../components/charts.jsx'
import { OsTag } from '../components/hosts.jsx'
import {
  CatBadge, Empty, ErrorState, Icon, Loading, Notice, OpenCount, PageHead, Panel, StatusChip, useAsync, usePageTitle,
  useSession,
} from '../components/ui.jsx'
import { useUrlFilters } from '../useUrlFilters.js'

const ruleLink = (hostId, stigId) => `/hosts/${hostId}/rules/${encodeURIComponent(stigId)}`

/** Shown only when the scan's `privileged` flag is false; unknown (null) makes no claim. */
function PrivilegeNotice({ host, scan, cat1NotReviewed, onShow }) {
  const how = host.os === 'windows'
    ? 'Run the collector from an elevated PowerShell (as Administrator)'
    : 'Run the collector as root (sudo sh collectors/collect-linux.sh)'
  const n = notReviewedCount(scan)
  return (
    <Notice icon="lock" tone="warn" title={`This scan ran without ${host.os === 'windows' ? 'Administrator' : 'root'} rights`}
      actions={<button type="button" className="btn secondary" onClick={onShow}>Show the Not reviewed results</button>}>
      <p>
        <strong>{plural(n, 'rule')}</strong>{cat1NotReviewed > 0 && <> (including {cat1NotReviewed} CAT I)</>} {n === 1 ? 'is' : 'are'} Not reviewed
        in this scan. Rules that need privileged files or settings could not be decided, so they are <strong>Not reviewed</strong>,
        never Not a finding, and they are excluded from the compliance figure, which therefore covers fewer rules than
        on other hosts. {how} for full coverage.
      </p>
    </Notice>
  )
}

function ScanSummary({ scan, results }) {
  const breakdown = useMemo(() => catBreakdown(results), [results])
  return (
    <div className="panel summary-grid">
      <section className="summary-col" aria-labelledby="summary-title">
        <h2 id="summary-title">Scan summary</h2>
        <p className="panel-desc">Collected {formatDateTime(scan.collected_at)} · benchmark {scan.benchmark_release}</p>
        <p className="kpi-num">{formatPct(scan.compliance)}</p>
        <p className="kpi-sub">compliance = {COMPLIANCE_DEFINITION}</p>
        <dl className="status-counts">
          {STATUSES.map((s) => (
            <div key={s} className="status-count">
              <dt><StatusChip status={s} /></dt>
              <dd>{scan.status[s]}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section className="summary-col" aria-labelledby="cat-title">
        <h2 id="cat-title">Results by CAT</h2>
        <CatBars breakdown={breakdown} />
      </section>
    </div>
  )
}

function Timeline({ scans, selectedId, alertsByScan, hostId, search }) {
  const ordered = [...scans].reverse() // oldest first
  const latestId = scans[0]?.id
  return (
    <Panel id="timeline" flush title="Scan timeline" desc="Choose a scan to see its results and its drift from the scan before it.">
      <ol className="timeline">
        {ordered.map((s, i) => {
          const alerts = alertsByScan.get(s.id) || []
          const selected = s.id === selectedId
          const sp = new URLSearchParams(search)
          sp.set('scan', String(s.id))
          return (
            <li key={s.id} className={`tl-item${selected ? ' selected' : ''}${alerts.length ? ' alerted' : ''}`}>
              <Link to={`/hosts/${hostId}?${sp.toString()}`} replace aria-current={selected ? 'true' : undefined}
                className="tl-link">
                <span className="tl-week">Week {i + 1}{s.id === latestId && <span className="tl-latest"> · latest</span>}</span>
                <span className="tl-date">{formatDate(s.collected_at, { withYear: false })}</span>
                <span className="tl-counts">
                  {CATS.map((c) => (
                    <span key={c} className="tl-count"><span className="tl-cat" aria-hidden="true">{c.replace('CAT ', '')}</span><OpenCount n={s.open[c]} cat={c} /></span>
                  ))}
                </span>
                {alerts.length > 0 && <span className="tl-alert">{plural(alerts.length, 'CAT I regression')}</span>}
                {selected && <span className="sr-only"> (selected)</span>}
              </Link>
            </li>
          )
        })}
      </ol>
    </Panel>
  )
}

const DRIFT_GROUPS = [
  ['regressed', 'Regressed', 'bad', 'Was Not a finding or Not applicable; Open now.'],
  ['newly_visible_cat1', 'Newly visible CAT I', 'bad', 'Not reviewed before, Open now. The finding may be old; it was not visible before.'],
  ['newly_open', 'Newly open (other CATs)', 'warn', 'Not reviewed before, Open now.'],
  ['lost_visibility', 'Lost visibility', 'warn', 'Open before, Not reviewed now. Not known to be fixed: the collector could not check it this time.'],
  ['fixed', 'Fixed', 'good', 'Was Open; Not a finding or Not applicable now.'],
]

function DriftPanel({ drift, hostId, titles }) {
  if (drift.first_scan) {
    return (
      <Panel id="drift" title="Drift">
        <p className="muted">This is the host&apos;s first scan, so there is nothing to compare it with.</p>
      </Panel>
    )
  }
  const groups = {
    ...drift,
    newly_open: (drift.newly_open || []).filter((r) => r.cat !== 'CAT I'),
  }
  const total = DRIFT_GROUPS.reduce((n, [key]) => n + (groups[key]?.length || 0), 0)
  return (
    <Panel id="drift" title="Drift since the previous scan"
      desc={(
        <>
          Compared by STIG ID with scan #{drift.prev_scan_id}
          {drift.benchmark_changed && <> (benchmark {drift.prev_release} → {drift.release})</>}.
          {' '}{plural(total, 'rule')} changed status in a way that needs attention.
        </>
      )}>
      {total === 0 && (
        <p className="state compact-state">No rule regressed, was fixed, became visible or lost visibility since the previous scan.</p>
      )}
      {total > 0 && (
        <div className="drift-grid">
          {DRIFT_GROUPS.filter(([key]) => groups[key]?.length).map(([key, label, tone, help]) => {
            const items = groups[key]
            return (
              <div key={key} className={`drift-group ${tone}`}>
                <h3><i className="dot" aria-hidden="true" />{label} <span className="drift-n">{items.length}</span></h3>
                <p className="drift-help">{help}</p>
                <ul className="drift-list">
                  {items.map((r) => (
                    <li key={r.stig_id}>
                      <CatBadge cat={r.cat} />
                      <Link className="mono" to={ruleLink(hostId, r.stig_id)}>{r.stig_id}</Link>
                      <span className="drift-title">{titles.get(r.stig_id)}</span>
                      <span className="drift-change">
                        <StatusChip status={r.from} /><Icon name="arrow" size={13} /><span className="sr-only"> to </span><StatusChip status={r.to} />
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      )}
      <ul className="drift-zero">
        {DRIFT_GROUPS.filter(([key]) => !groups[key]?.length).map(([key, label, , help]) => (
          <li key={key} title={help}>{label}: <strong>0</strong></li>
        ))}
      </ul>
      {(drift.other_changes?.length > 0 || drift.new_rules?.length > 0 || drift.removed_rules?.length > 0) && (
        <p className="muted drift-foot">
          Also: {plural(drift.other_changes?.length || 0, 'other status change')} (for example Not applicable → Not a finding)
          {drift.new_rules?.length > 0 && <>, {plural(drift.new_rules.length, 'rule')} only in this scan</>}
          {drift.removed_rules?.length > 0 && <>, {plural(drift.removed_rules.length, 'rule')} only in the previous scan</>}.
          {' '}Rules present in only one scan are never counted as fixed or regressed.
        </p>
      )}
    </Panel>
  )
}

const PAGE = 40

const RESULT_SPEC = {
  status: { param: 'status', default: '', allow: STATUSES },
  cat: { param: 'cat', default: '', allow: CATS },
  q: { param: 'q', default: '', max: 100, search: true },
}

function ResultsTable({ results, hostId, url }) {
  const { filters, update, clear, search, setSearch, submitSearch, any: anyFilter } = url
  const sorted = useMemo(() => sortResults(results), [results])
  const shown = useMemo(() => filterResults(sorted, filters), [sorted, filters.status, filters.cat, filters.q]) // eslint-disable-line react-hooks/exhaustive-deps
  const [limit, setLimit] = useState(PAGE)
  useEffect(() => { setLimit(PAGE) }, [filters.status, filters.cat, filters.q, results])
  const visible = shown.slice(0, limit)

  return (
    <Panel id="results" flush live title="Results"
      desc={`${anyFilter ? `${shown.length} of ${plural(results.length, 'rule')}` : plural(results.length, 'rule')} in this scan`}>
      <form className="toolbar inset" role="search" aria-label="Filter results"
        onSubmit={(e) => { e.preventDefault(); submitSearch() }}>
        <label className="field grow search">
          <span>Search</span>
          <Icon name="search" />
          <input type="search" value={search} maxLength={100} placeholder="Search STIG ID, title or reason"
            onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="field">
          <span>Status</span>
          <select value={filters.status} onChange={(e) => update({ status: e.target.value })}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => <option key={s} value={s}>{STATUS_INFO[s].label}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Severity</span>
          <select value={filters.cat} onChange={(e) => update({ cat: e.target.value })}>
            <option value="">All CATs</option>
            {CATS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        {anyFilter && (
          <button type="button" className="btn ghost clear-btn" onClick={clear}>Clear</button>
        )}
      </form>
      {shown.length ? (
        <div className="table-wrap">
          <table className="table cards results-table">
            <caption className="sr-only">Rule results</caption>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">CAT</th>
                <th scope="col">Status</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((r) => (
                <tr key={r.stig_id}>
                  <th scope="row">
                    <div className="rule-cell">
                      <Link className="mono rule-id" to={ruleLink(hostId, r.stig_id)}>{r.stig_id}</Link>
                      <span className="rule-title">{r.title || <span className="muted">Untitled rule</span>}</span>
                    </div>
                  </th>
                  <td data-label="CAT"><CatBadge cat={r.cat} /></td>
                  <td data-label="Status"><StatusChip status={r.status} /></td>
                  <td data-label="Why" className="reason-cell">
                    <div className="reason-wrap">
                      <span className="reason">{r.reason}</span>
                      {r.comment && <span className="comment-flag"><Icon name="edit" size={13} /> Assessor comment</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length > visible.length && (
            <div className="more-row">
              <span className="muted">Showing {visible.length} of {shown.length}, Open first.</span>
              <button type="button" className="btn secondary" onClick={() => setLimit(shown.length)}>
                Show all {shown.length} results
              </button>
            </div>
          )}
        </div>
      ) : <Empty>No result matches these filters.</Empty>}
    </Panel>
  )
}

async function loadHost(hostId) {
  const [host, scans] = await Promise.all([api.host(hostId), api.hostScans(hostId)])
  return { host, scans }
}

async function loadScan(scanId) {
  const [res, drift] = await Promise.all([api.scanResults(scanId), api.scanDrift(scanId)])
  return { results: res.results, drift }
}

/** Keyed by host: opening another host starts from a clean slate, never showing the previous one. */
export default function HostDetailRoute() {
  const { hostId } = useParams()
  return <HostDetail key={hostId} hostId={hostId} />
}

function HostDetail({ hostId }) {
  const location = useLocation()
  const url = useUrlFilters(RESULT_SPEC)
  const { params } = url
  const { guest } = useSession()
  const base = useAsync(() => loadHost(hostId), [hostId])
  usePageTitle(base.data?.host?.name || 'Host')

  const scans = base.data?.scans || []
  const requested = Number(params.get('scan'))
  const found = scans.find((s) => s.id === requested)
  const badScan = params.has('scan') && scans.length > 0 && !found
  const selected = found || scans[0] || null
  const scanData = useAsync(() => (selected ? loadScan(selected.id) : Promise.resolve(null)), [selected?.id])

  const alertsByScan = useMemo(() => {
    const map = new Map()
    for (const a of base.data?.host?.alerts || []) {
      if (!map.has(a.scan_id)) map.set(a.scan_id, [])
      map.get(a.scan_id).push(a)
    }
    return map
  }, [base.data])
  const titles = useMemo(() => new Map((scanData.data?.results || []).map((r) => [r.stig_id, r.title])), [scanData.data])
  const cat1NotReviewed = useMemo(
    () => (scanData.data ? catBreakdown(scanData.data.results)['CAT I'].Not_Reviewed : 0), [scanData.data])

  // Links to #drift or #results scroll there once the scan has loaded.
  useEffect(() => {
    if (!scanData.data || !location.hash) return
    const el = document.getElementById(location.hash.slice(1))
    if (el) el.scrollIntoView({ block: 'start' })
  }, [scanData.data, location.hash])

  if (base.loading && !base.data) return <div className="page"><Loading label="Loading the host…" /></div>
  if (base.error) {
    return (
      <div className="page">
        <PageHead back={{ to: '/hosts', label: 'All hosts' }} title={base.error.status === 404 ? 'Host not found' : 'Host'} />
        <ErrorState error={base.error} onRetry={base.error.status === 404 ? undefined : base.reload} />
      </div>
    )
  }
  const { host } = base.data
  const isLatest = selected && selected.id === scans[0]?.id

  function showNotReviewed() {
    url.setSearch('')
    url.update({ status: 'Not_Reviewed', cat: '', q: '' })
    requestAnimationFrame(() => document.getElementById('results')?.scrollIntoView({ block: 'start' }))
  }

  return (
    <div className="page">
      <PageHead back={{ to: '/hosts', label: 'All hosts' }} title={host.name}
        actions={selected && (
          <div className="exports" role="group" aria-label="Exports">
            <span className="exports-label">Exports{isLatest ? '' : ` (scan of ${formatDate(selected.collected_at)})`}</span>
            <a className="btn secondary" href={api.cklUrl(selected.id)} download><Icon name="download" />Checklist .ckl</a>
            <a className="btn secondary" href={api.cklbUrl(selected.id)} download><Icon name="download" />.cklb</a>
            {isLatest && host.status.Open > 0 && (
              <a className="btn secondary" href={api.remediationUrl(host.id)} download>
                <Icon name="download" />Remediation {host.os === 'windows' ? '.ps1' : '.yml'}
              </a>
            )}
          </div>
        )}>
        <div className="host-meta">
          <OsTag os={host.os} />
          <span>{host.benchmark_id}{host.latest_scan ? ` ${host.latest_scan.benchmark_release}` : ''}</span>
          {host.environment && <span>{host.environment}</span>}
          {host.owner && <span>Owner: {host.owner}</span>}
          <span>{plural(host.scan_count, 'scan')}</span>
          {host.tags?.length > 0 && (
            <ul className="tags" aria-label="Tags">{host.tags.map((t) => <li key={t}>{t}</li>)}</ul>
          )}
        </div>
      </PageHead>

      {!selected && <Empty>This host has no scans yet. Upload collector output to see its findings.</Empty>}

      {selected && (
        <>
          {badScan && (
            <p className="state info-strip" role="status">
              The scan in this link (#{params.get('scan').slice(0, 20)}) is not one of this host&apos;s scans, so the latest scan is shown.
            </p>
          )}
          {!isLatest && (
            <p className="state info-strip" role="status">
              Showing the scan of {formatDate(selected.collected_at)}, not the latest.{' '}
              <Link to={`/hosts/${host.id}`} replace>Back to the latest scan</Link>
            </p>
          )}
          {ranUnprivileged(selected) && <PrivilegeNotice host={host} scan={selected} cat1NotReviewed={cat1NotReviewed} onShow={showNotReviewed} />}
          {scanData.data && <ScanSummary scan={selected} results={scanData.data.results} />}
          <Timeline scans={scans} selectedId={selected.id} alertsByScan={alertsByScan} hostId={host.id}
            search={params.toString()} />
          {scanData.loading && !scanData.data && <Loading label="Loading the scan…" />}
          {scanData.error && <ErrorState error={scanData.error} onRetry={scanData.reload} />}
          {scanData.data && (
            <>
              <DriftPanel drift={scanData.data.drift} hostId={host.id} titles={titles} />
              <ResultsTable results={scanData.data.results} hostId={host.id} url={url} />
            </>
          )}
          {!guest && (
            <section className="panel" aria-label="Upload a scan for this host">
              <UploadScan hostId={host.id} heading={`Upload a scan for ${host.name}`} onDone={base.reload} />
            </section>
          )}
          {guest && <p className="muted read-only-note"><Icon name="lock" size={13} /> Read-only demo: assessor comments are shown but only an admin can edit them.</p>}
        </>
      )}
    </div>
  )
}
