import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import {
  CATS, describeDelta, formatDate, hostsAtRisk, listWords, plural, regressionStory, weekDelta,
} from '../lib.js'
import { ComplianceMeter, Sparkline, TrendChart } from '../components/charts.jsx'
import { HostTable } from '../components/hosts.jsx'
import {
  About, ErrorState, Icon, Loading, Notice, PageHead, Panel, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'

const CAT_KEY = { 'CAT I': 'cat1', 'CAT II': 'cat2', 'CAT III': 'cat3' }
const CAT_WORD = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

async function loadFleet() {
  const [fleet, alerts, hosts] = await Promise.all([api.fleet(), api.alerts(), api.hosts()])
  // Each alert carries the collected_at of the scan it was raised for.
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

/** The one thing to look at first: the latest week's CAT I regressions, as a plain heading over a table. */
function Regressions({ story }) {
  const stillOpen = story.rules.filter((r) => r.now === 'Open').length
  const closedNow = story.rules.filter((r) => r.now === 'NotAFinding' || r.now === 'Not_Applicable').length
  const unknownNow = story.rules.filter((r) => r.now === 'Not_Reviewed').length
  const hostNames = story.hosts.map((h) => h.name)
  return (
    <Panel id="start" flush
      title={`${story.week ? `Week ${story.week}: ` : ''}${plural(story.rules.length, 'CAT I rule')} regressed on ${listWords(hostNames)}`}
      desc={(
        <>
          In the scans of {formatDate(story.day)}, {story.rules.length === 1 ? 'this rule' : 'these rules'}{' '}
          went from closed (Not a finding or Not applicable) to Open, and STIGWatch raised a CAT I alert for each.{' '}
          {stillOpen > 0
            ? <><strong>{plural(stillOpen, 'is', 'are')} still open</strong> in the latest scan.</>
            : <>None is Open in the latest scan.</>}
          {closedNow > 0 && <> {plural(closedNow, 'rule')} closed again (Not a finding or Not applicable).</>}
          {unknownNow > 0 && <> {plural(unknownNow, 'rule')} {unknownNow === 1 ? 'is' : 'are'} Not reviewed in the latest scan, so it is not known whether {unknownNow === 1 ? 'it is' : 'they are'} fixed.</>}
        </>
      )}
      actions={story.hosts.map((h) => (
        <Link key={h.id} className="btn secondary"
          to={`/hosts/${h.id}?scan=${story.rules.find((r) => r.host_id === h.id)?.scan_id ?? ''}#drift`}>
          Drift on {h.name} <Icon name="arrow" />
        </Link>
      ))}>
      <div className="table-wrap">
        <table className="table cards">
          <caption className="sr-only">CAT I rules that regressed</caption>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Host</th>
              <th scope="col">Title</th>
              <th scope="col">Latest scan</th>
            </tr>
          </thead>
          <tbody>
            {story.rules.map((r) => (
              <tr key={`${r.host_id}-${r.stig_id}`}>
                <th scope="row">
                  <Link className="mono" to={`/hosts/${r.host_id}/rules/${encodeURIComponent(r.stig_id)}`}>
                    {r.stig_id}<span className="sr-only"> on {r.host_name}</span>
                  </Link>
                </th>
                <td data-label="Host" className="nowrap"><Link to={`/hosts/${r.host_id}`}>{r.host_name}</Link></td>
                <td data-label="Title" className="title-cell">{r.title}</td>
                <td data-label="Latest scan">{r.now && <StatusChip status={r.now} />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function CatTile({ cat, value, trend, hosts }) {
  const d = weekDelta(trend, cat) // the trend supplies the week-over-week change and the sparkline
  const delta = describeDelta(d?.change, d?.lost)
  const onHosts = hosts.filter((h) => (h.open?.[cat] || 0) > 0).length
  const key = CAT_KEY[cat]
  return (
    <div className="kpi" role="group" aria-label={`Open ${cat} findings`}>
      <p className="kpi-label"><i className={`sev-dot ${key}`} aria-hidden="true" />{cat}<span className="kpi-word"> · {CAT_WORD[cat]}</span></p>
      <div className="kpi-row">
        <p className="kpi-num">{value}<span className="kpi-unit"> open</span></p>
        <Sparkline values={trend.map((t) => t.open?.[cat] ?? 0)} width={96} height={30} className={key} />
      </div>
      <p className="kpi-sub">on {plural(onHosts, 'host')}</p>
      {delta && (
        <p className={`delta ${delta.tone}`}>
          <span aria-hidden="true">{delta.arrow} {delta.text}</span>
          <span className="sr-only">{delta.sr}</span>
          <span className="muted"> vs {formatDate(d.since, { withYear: false })}</span>
        </p>
      )}
    </div>
  )
}

const ABOUT = (
  <p>
    STIGWatch checks each host against the DISA STIG for its operating system, using read-only collector
    output, and tracks how its findings change from one weekly scan to the next. Open findings are counted from
    each host&apos;s latest scan; a rule that could not be checked is Not reviewed, never a pass.
  </p>
)

export default function Fleet() {
  usePageTitle('Fleet')
  const { data, error, loading, reload } = useAsync(loadFleet, [])

  if (loading && !data) return <div className="page"><Loading label="Loading the fleet…" /></div>
  if (error) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>
  const { fleet, hosts, story } = data
  if (!hosts.some((h) => h.latest_scan)) {
    return (
      <div className="page">
        <PageHead title="Fleet" sub="DISA STIG results for each host, from read-only collector output." />
        <NoData onChanged={reload} />
      </div>
    )
  }
  const lastWeek = fleet.trend.at(-1)?.week
  const atRisk = hostsAtRisk(hosts, 6)
  const annotation = story?.week
    ? { week: story.week, label: `${plural(story.rules.length, 'CAT I regression')} on ${plural(story.hosts.length, 'host')}` }
    : null

  return (
    <div className="page">
      <PageHead title="Fleet" sub={`${plural(fleet.hosts, 'host')} and ${plural(fleet.scans, 'scan')}, compared week over week.`}>
        <About>{ABOUT}</About>
      </PageHead>

      {story && <Regressions story={story} />}

      {fleet.newly_visible_cat1?.length > 0 && (
        <Notice icon="eye" tone="warn" title="CAT I findings that became visible">
          <p>These were Not reviewed in the previous scan and are Open now. The finding may be old; it was not visible before.</p>
          <ul className="plain-list">
            {fleet.newly_visible_cat1.map((r) => (
              <li key={`${r.host_id}-${r.stig_id}`}>
                <Link className="mono" to={`/hosts/${r.host_id}/rules/${encodeURIComponent(r.stig_id)}`}>{r.stig_id}</Link> on {r.host}
              </li>
            ))}
          </ul>
        </Notice>
      )}

      <Panel id="latest" flush title="Latest scans" desc={lastWeek && `Week of ${formatDate(lastWeek)}`}>
        <div className="kpi-grid">
          {CATS.map((cat) => <CatTile key={cat} cat={cat} value={fleet.open?.[cat] ?? 0} trend={fleet.trend} hosts={hosts} />)}
          <div className="kpi" role="group" aria-label="Fleet compliance">
            <p className="kpi-label">Fleet compliance</p>
            <ComplianceMeter value={fleet.compliance} notReviewed={fleet.status.Not_Reviewed}
              notApplicable={fleet.status.Not_Applicable} />
          </div>
        </div>
      </Panel>

      <Panel id="trend" title={`Open findings by CAT, last ${plural(fleet.trend.length, 'week')}`}
        desc="Each CAT on its own scale. Totals across all hosts, one scan per host per week.">
        <TrendChart trend={fleet.trend} annotation={annotation} />
      </Panel>

      <Panel id="risk" flush title="Hosts at risk" desc="Hosts with open CAT I or CAT II findings, highest severity first."
        actions={<Link className="btn ghost" to="/hosts">All {fleet.hosts} hosts <Icon name="arrow" /></Link>}>
        {atRisk.length
          ? <HostTable hosts={atRisk} caption="Hosts at risk" showScans={false} />
          : <p className="state">No host has an open CAT I or CAT II finding.</p>}
      </Panel>
    </div>
  )
}
