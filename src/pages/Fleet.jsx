import { Link } from 'react-router-dom'
import { api } from '../api.js'
import {
  CATS, DISCLAIMER, describeDelta, formatDate, hostsAtRisk, listWords, plural, regressionStory, weekDelta,
} from '../lib.js'
import { ComplianceGauge, Sparkline, TrendChart } from '../components/charts.jsx'
import { HostTable } from '../components/hosts.jsx'
import {
  CatBadge, ErrorState, Icon, Loading, PageHead, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'

async function loadFleet() {
  const [fleet, alerts, hosts] = await Promise.all([api.fleet(), api.alerts(), api.hosts()])
  const story = regressionStory(alerts, fleet.trend)
  if (story) {
    // Title and current status of each regressed rule (a handful of requests at most).
    const details = await Promise.all(story.rules.slice(0, 8).map((a) => api.rule(a.host_id, a.stig_id).catch(() => null)))
    story.rules = story.rules.map((a, i) => {
      const d = details[i]
      return { ...a, title: d?.rule?.title || '', now: d?.history?.at(-1)?.status || null }
    })
  }
  return { fleet, hosts, story }
}

function StartHere({ story }) {
  const stillOpen = story.rules.filter((r) => r.now === 'Open').length
  const hostNames = story.hosts.map((h) => h.name)
  return (
    <section className="card start-here" aria-labelledby="start-title">
      <div className="start-head">
        <p className="eyebrow accent"><Icon name="alert" size={15} /> Start here</p>
        <h2 id="start-title">
          {story.week ? `Week ${story.week}: ` : ''}{plural(story.rules.length, 'CAT I rule')} regressed on {listWords(hostNames)}
        </h2>
        <p>
          In the scans of {formatDate(story.day)}, {story.rules.length === 1 ? 'this rule' : 'these rules'} went
          from Not a finding to Open, and STIGWatch raised a CAT I alert for each.{' '}
          {stillOpen > 0
            ? <><strong>{plural(stillOpen, 'is', 'are')} still open</strong> in the latest scan.</>
            : <>All of them have been fixed since.</>}
        </p>
      </div>
      <ul className="story-list">
        {story.rules.map((r) => (
          <li key={`${r.host_id}-${r.stig_id}`} className="story-item">
            <div className="story-id">
              <CatBadge cat="CAT I" />
              <Link className="mono story-link" to={`/hosts/${r.host_id}/rules/${encodeURIComponent(r.stig_id)}`}>
                {r.stig_id}<span className="sr-only"> on {r.host_name}</span>
              </Link>
              <span className="muted small">on <Link to={`/hosts/${r.host_id}`}>{r.host_name}</Link></span>
            </div>
            {r.title && <p className="story-title">{r.title}</p>}
            {r.now && (
              <p className="story-now small"><span className="muted">Latest scan:</span> <StatusChip status={r.now} small /></p>
            )}
          </li>
        ))}
      </ul>
      <div className="start-actions">
        {story.hosts.map((h) => (
          <Link key={h.id} className="btn secondary small"
            to={`/hosts/${h.id}?scan=${story.rules.find((r) => r.host_id === h.id)?.scan_id ?? ''}#drift`}>
            See drift on {h.name} <Icon name="arrow" size={15} />
          </Link>
        ))}
      </div>
    </section>
  )
}

function CatTile({ cat, trend, hosts }) {
  const d = weekDelta(trend, cat)
  const delta = describeDelta(d?.change)
  const onHosts = hosts.filter((h) => (h.open?.[cat] || 0) > 0).length
  const value = d ? d.current : trend.at(-1)?.open?.[cat] ?? 0
  return (
    <section className={`card tile ${cat === 'CAT I' ? 'cat1' : cat === 'CAT II' ? 'cat2' : 'cat3'}`} aria-label={`Open ${cat} findings`}>
      <div className="tile-head"><CatBadge cat={cat} withSeverity /></div>
      <p className="tile-num">{value}<span className="tile-unit"> open</span></p>
      <p className="tile-sub muted small">on {plural(onHosts, 'host')}</p>
      <Sparkline values={trend.map((t) => t.open?.[cat] ?? 0)} width={160} height={34}
        className={cat === 'CAT I' ? 'cat1' : cat === 'CAT II' ? 'cat2' : 'cat3'} />
      {delta && (
        <p className={`delta ${delta.tone}`}>
          <span aria-hidden="true">{delta.arrow} {delta.text}</span>
          <span className="sr-only">{delta.sr}</span>
          <span className="muted"> vs {formatDate(d.since, { withYear: false })}</span>
        </p>
      )}
    </section>
  )
}

export default function Fleet() {
  usePageTitle('Fleet')
  const { data, error, loading, reload } = useAsync(loadFleet, [])

  if (loading && !data) return <div className="page"><Loading label="Loading the fleet…" /></div>
  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>
  const { fleet, hosts, story } = data
  const lastWeek = fleet.trend.at(-1)?.week
  const atRisk = hostsAtRisk(hosts, 6)
  const annotation = story?.week
    ? { week: story.week, label: `${plural(story.rules.length, 'CAT I regression')} on ${plural(story.hosts.length, 'host')}` }
    : null

  return (
    <div className="page">
      <PageHead eyebrow={`Fleet overview · ${plural(fleet.hosts, 'host')} · ${plural(fleet.scans, 'scan')}`} title="Fleet">
        <p className="lede">
          STIGWatch checks each host against the DISA STIG for its operating system, using read-only collector
          output, and tracks how its findings change from one weekly scan to the next.
        </p>
        <p className="disclaimer-note"><Icon name="info" size={15} /> {DISCLAIMER}</p>
      </PageHead>

      {story && <StartHere story={story} />}

      {fleet.newly_visible_cat1?.length > 0 && (
        <section className="card notice warn" aria-labelledby="nv-title">
          <h2 id="nv-title"><Icon name="eye" size={17} /> CAT I findings that became visible</h2>
          <p className="small">These were Not reviewed in the previous scan and are Open now. The finding may be old; it was not visible before.</p>
          <ul className="plain-list">
            {fleet.newly_visible_cat1.map((r) => (
              <li key={`${r.host_id}-${r.stig_id}`}>
                <Link className="mono" to={`/hosts/${r.host_id}/rules/${encodeURIComponent(r.stig_id)}`}>{r.stig_id}</Link> on {r.host}
              </li>
            ))}
          </ul>
        </section>
      )}

      <h2 className="section-title">Latest scans{lastWeek && <span className="muted"> · week of {formatDate(lastWeek)}</span>}</h2>
      <div className="kpi-grid">
        {CATS.map((cat) => <CatTile key={cat} cat={cat} trend={fleet.trend} hosts={hosts} />)}
        <section className="card tile gauge-tile" aria-labelledby="gauge-title">
          <h3 id="gauge-title" className="tile-label">Fleet compliance</h3>
          <ComplianceGauge value={fleet.compliance} notReviewed={fleet.status.Not_Reviewed}
            notApplicable={fleet.status.Not_Applicable} />
        </section>
      </div>

      <section className="card" aria-labelledby="trend-title">
        <div className="card-head">
          <div>
            <h2 id="trend-title">Open findings by CAT, last {plural(fleet.trend.length, 'week')}</h2>
            <p className="muted small">Each CAT on its own scale. Totals across all hosts, one scan per host per week.</p>
          </div>
        </div>
        <TrendChart trend={fleet.trend} annotation={annotation} />
      </section>

      <section className="card" aria-labelledby="risk-title">
        <div className="card-head">
          <div>
            <h2 id="risk-title">Hosts at risk</h2>
            <p className="muted small">Hosts with open CAT I or CAT II findings, highest severity first.</p>
          </div>
          <Link className="btn ghost small" to="/hosts">All {fleet.hosts} hosts <Icon name="arrow" size={15} /></Link>
        </div>
        {atRisk.length
          ? <HostTable hosts={atRisk} caption="Hosts at risk" showScans={false} />
          : <p className="state">No host has an open CAT I or CAT II finding.</p>}
      </section>
    </div>
  )
}
