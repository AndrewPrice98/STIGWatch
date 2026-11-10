import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import {
  CatBadge, Empty, ErrorState, Icon, Loading, OpenCount, PageHead, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { loadHostScans, mapLimit } from '../data.js'
import {
  CATS, DRIFT_KINDS, alertFrom, buildTimeline, defaultWeek, describeDelta, formatDate, mergeDrift, plural,
} from '../lib.js'

const ruleLink = (hostId, stigId) => `/hosts/${hostId}/rules/${encodeURIComponent(stigId)}`
const ALERTS_SHOWN = 12

async function loadDrift() {
  const [fleet, alerts, hosts] = await Promise.all([api.fleet(), api.alerts(), api.hosts()])
  const hostScans = await loadHostScans(hosts)
  const cat1 = alerts.filter((a) => a.kind === 'cat1_regression' || a.cat === 'CAT I')
  return { fleet, hosts, weeks: buildTimeline(fleet.trend, hostScans, cat1), alerts: cat1 }
}

/** Drift of every scan collected in a week (one API call per scan), plus rule titles for the hosts that changed. */
async function loadWeek(week) {
  const drifts = await mapLimit(week.scans, 6, async (scan) => ({ scan, drift: await api.scanDrift(scan.id) }))
  const merged = mergeDrift(drifts)
  const scanIds = new Set(DRIFT_KINDS.flatMap((k) => merged[k.key].map((r) => r.scan_id)))
  const titles = new Map()
  await mapLimit([...scanIds], 6, async (scanId) => {
    try {
      const { results } = await api.scanResults(scanId)
      for (const r of results) titles.set(`${scanId}:${r.stig_id}`, r.title)
    } catch { /* titles are a convenience */ }
  })
  return { merged, titles }
}

function AlertList({ alerts, weekByScan }) {
  const [all, setAll] = useState(false)
  const shown = all ? alerts : alerts.slice(0, ALERTS_SHOWN)
  if (!alerts.length) return <Empty>No CAT I regression has been raised: no CAT I rule went from closed to Open between two scans.</Empty>
  return (
    <>
      <ul className="alert-list">
        {shown.map((a) => {
          const from = alertFrom(a)
          const w = weekByScan.get(a.scan_id)
          return (
            <li key={a.id} className="alert-item">
              <CatBadge cat="CAT I" />
              <Link className="mono" to={ruleLink(a.host_id, a.stig_id)}>{a.stig_id}</Link>
              <span>on <Link to={`/hosts/${a.host_id}`}>{a.host_name}</Link></span>
              {from && <span className="drift-change small"><StatusChip status={from} small /><span aria-hidden="true"> → </span><span className="sr-only"> to </span><StatusChip status="Open" small /></span>}
              {w && <span className="muted small">week {w.n}, {formatDate(w.week, { withYear: false })}</span>}
              <Link className="small" to={`/hosts/${a.host_id}?scan=${a.scan_id}#drift`}>Drift on {a.host_name}</Link>
            </li>
          )
        })}
      </ul>
      {alerts.length > shown.length && (
        <div className="more-row">
          <span className="muted small">Showing {shown.length} of {alerts.length}, newest first.</span>
          <button type="button" className="btn secondary small" onClick={() => setAll(true)}>Show all {alerts.length}</button>
        </div>
      )}
    </>
  )
}

function Timeline({ weeks, selected }) {
  const last = weeks[weeks.length - 1]?.week
  return (
    <ol className="timeline">
      {weeks.map((w) => {
        const sel = w.week === selected
        return (
          <li key={w.week} className={`tl-item${sel ? ' selected' : ''}${w.alerts.length ? ' alerted' : ''}`}>
            <Link to={`?week=${w.week}`} replace className="tl-link" aria-current={sel ? 'true' : undefined}>
              <span className="tl-week">Week {w.n}{w.week === last && <span className="tl-latest"> · latest</span>}</span>
              <span className="tl-date">{formatDate(w.week, { withYear: false })}</span>
              <span className="tl-counts">
                {CATS.map((c) => (
                  <span key={c} className="tl-count"><span className="tl-cat" aria-hidden="true">{c.replace('CAT ', '')}</span><OpenCount n={w.open?.[c] ?? 0} cat={c} /></span>
                ))}
              </span>
              <span className="tl-sub small muted">{plural(w.scans.length, 'scan')}</span>
              {w.alerts.length > 0 && <span className="tl-alert"><Icon name="alert" size={13} /> {plural(w.alerts.length, 'CAT I regression')}</span>}
              {sel && <span className="sr-only"> (selected)</span>}
            </Link>
          </li>
        )
      })}
    </ol>
  )
}

function Change({ value }) {
  const d = describeDelta(value)
  return d ? <span className={`delta-inline ${d.tone}`}><span aria-hidden="true">{d.arrow} {value > 0 ? `+${value}` : value}</span><span className="sr-only">{d.text}</span></span> : null
}

function WeekDetail({ week }) {
  const { data, error, loading, reload } = useAsync(() => loadWeek(week), [week.week])
  return (
    <section className="card" id="week" aria-labelledby="week-title">
      <div className="card-head">
        <div>
          <h2 id="week-title">Week {week.n}: week of {formatDate(week.week)}</h2>
          <p className="muted small">
            {plural(week.scans.length, 'scan')} collected. Each is compared by STIG ID with the same host&apos;s previous scan.
            {week.change && <> Fleet open findings vs the week before:{' '}
              {CATS.map((c) => <span key={c} className="wk-change">{c} <Change value={week.change[c]} /></span>)}</>}
          </p>
        </div>
      </div>
      {loading && !data && <Loading label="Loading the week's drift…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && <DriftGroups data={data} week={week} />}
      {week.scans.length > 0 && (
        <details className="week-hosts">
          <summary>Net change in open findings per host</summary>
          <table className="table compact cards">
            <caption className="sr-only">Net change in open findings per host this week</caption>
            <thead><tr><th scope="col">Host</th>{CATS.map((c) => <th key={c} scope="col" className="num">{c}</th>)}</tr></thead>
            <tbody>
              {week.scans.map((s) => (
                <tr key={s.id}>
                  <th scope="row"><Link className="host-link" to={`/hosts/${s.host_id}?scan=${s.id}#drift`}>{s.host_name}</Link></th>
                  {s.change
                    ? CATS.map((c) => <td key={c} data-label={c} className="num"><Change value={s.change[c]} />{s.change[c] === 0 && <span className="muted">0</span>}</td>)
                    : <td colSpan={3} className="muted">First scan of this host</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  )
}

function DriftGroups({ data, week }) {
  const { merged, titles } = data
  const total = DRIFT_KINDS.reduce((n, k) => n + merged[k.key].length, 0)
  if (!week.scans.length) return <Empty>No host was scanned this week.</Empty>
  return (
    <>
      {total === 0 && (
        <p className="state compact-state">
          No rule regressed, was fixed, became visible or lost visibility in this week&apos;s scans
          {merged.first.length > 0 && <> ({plural(merged.first.length, 'first scan')} had nothing to compare with)</>}.
        </p>
      )}
      {total > 0 && (
        <div className="drift-grid">
          {DRIFT_KINDS.filter((k) => merged[k.key].length).map((k) => (
            <div key={k.key} className={`drift-group ${k.tone}`}>
              <h3><Icon name={k.icon} size={16} /> {k.label} <span className="drift-n">{merged[k.key].length}</span></h3>
              <p className="muted small">{k.help}</p>
              <ul className="drift-list">
                {merged[k.key].map((r) => {
                  const title = titles.get(`${r.scan_id}:${r.stig_id}`)
                  return (
                    <li key={`${r.scan_id}-${r.stig_id}`}>
                      <CatBadge cat={r.cat} />
                      <Link className="mono" to={ruleLink(r.host_id, r.stig_id)}>{r.stig_id}</Link>
                      <span className="muted small">on <Link to={`/hosts/${r.host_id}?scan=${r.scan_id}#drift`}>{r.host_name}</Link></span>
                      {title && <span className="drift-title">{title}</span>}
                      <span className="drift-change small">
                        <StatusChip status={r.from} small /><span aria-hidden="true"> → </span><span className="sr-only"> to </span><StatusChip status={r.to} small />
                      </span>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>
      )}
      <ul className="drift-zero">
        {DRIFT_KINDS.filter((k) => !merged[k.key].length).map((k) => (
          <li key={k.key} title={k.help}><Icon name={k.icon} size={14} /> {k.label}: <strong>0</strong></li>
        ))}
      </ul>
      <p className="muted small drift-foot">
        Lost visibility is never counted as fixed: the rule is Not reviewed now, so nobody knows whether it is still open.
      </p>
    </>
  )
}

export default function Drift() {
  usePageTitle('Drift')
  const { data, error, loading, reload } = useAsync(loadDrift, [])
  const [params] = useSearchParams()
  const weeks = data?.weeks || []
  const requested = params.get('week')
  const selectedKey = weeks.find((w) => w.week === requested)?.week ?? defaultWeek(weeks)
  const selected = weeks.find((w) => w.week === selectedKey) || null
  const weekByScan = useMemo(() => {
    const map = new Map()
    for (const w of weeks) for (const s of w.scans) map.set(s.id, w)
    return map
  }, [weeks])

  // A link with #week scrolls to the detail once it exists.
  useEffect(() => {
    if (data && window.location.hash === '#week') document.getElementById('week')?.scrollIntoView({ block: 'start' })
  }, [data])

  return (
    <div className="page">
      <PageHead eyebrow="Change between scans" title="Drift">
        <p className="lede">
          What changed across the fleet from one weekly scan to the next. Rules are matched by STIG ID, so a new
          benchmark release does not hide a change. CAT I regressions are raised as alerts.
        </p>
      </PageHead>

      {loading && !data && <Loading label="Loading the fleet timeline…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.hosts.length === 0 && <NoData onChanged={reload} />}
      {data && data.hosts.length > 0 && (
        <>
          <section className="card notice" aria-labelledby="alerts-title">
            <div className="card-head">
              <div>
                <h2 id="alerts-title"><Icon name="alert" size={17} /> CAT I regression alerts</h2>
                <p className="muted small">A CAT I rule that was Not a finding or Not applicable in a host&apos;s previous scan and is Open now.</p>
              </div>
              <span className="count-pill">{data.alerts.length}</span>
            </div>
            <AlertList alerts={data.alerts} weekByScan={weekByScan} />
          </section>

          {data.fleet.newly_visible_cat1?.length > 0 && (
            <section className="card notice warn" aria-labelledby="nv-title">
              <h2 id="nv-title"><Icon name="eye" size={17} /> CAT I findings that became visible</h2>
              <p className="small">These were Not reviewed in the previous scan and are Open in the latest. The finding may be old; it was not visible before.</p>
              <ul className="plain-list">
                {data.fleet.newly_visible_cat1.map((r) => (
                  <li key={`${r.host_id}-${r.stig_id}`}>
                    <Link className="mono" to={ruleLink(r.host_id, r.stig_id)}>{r.stig_id}</Link> on {r.host}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card" aria-labelledby="timeline-title">
            <div className="card-head">
              <div>
                <h2 id="timeline-title">Fleet timeline</h2>
                <p className="muted small">Open findings per week across all hosts (each host&apos;s latest scan up to that week). Choose a week to see what changed.</p>
              </div>
            </div>
            <Timeline weeks={weeks} selected={selectedKey} />
          </section>

          {selected ? <WeekDetail key={selected.week} week={selected} /> : <Empty>No weekly scans yet.</Empty>}
        </>
      )}
    </div>
  )
}
