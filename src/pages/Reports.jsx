import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import { OsTag } from '../components/hosts.jsx'
import {
  About, CatBadge, ErrorState, Icon, Loading, OpenCount, PageHead, Panel, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { scannedHosts } from '../data.js'
import {
  CATS, COMPLIANCE_DEFINITION, DISCLAIMER, formatDate, formatDateTime, formatPct, plural, sortHostsByRisk,
} from '../lib.js'

async function loadReports() {
  const [fleet, hosts] = await Promise.all([api.fleet(), api.hosts()])
  return { fleet, hosts }
}

function HostChecklists({ hosts }) {
  const [params, setParams] = useSearchParams()
  const sorted = useMemo(() => [...hosts].sort((a, b) => a.name.localeCompare(b.name)), [hosts])
  const host = sorted.find((h) => h.id === Number(params.get('host'))) || sorted[0]
  const { data: scans, error, loading, reload } = useAsync(() => (host ? api.hostScans(host.id) : Promise.resolve([])), [host?.id])
  const scan = scans?.find((s) => s.id === Number(params.get('scan'))) || scans?.[0]
  const set = (changes) => setParams((p) => {
    const sp = new URLSearchParams(p)
    for (const [k, v] of Object.entries(changes)) { if (v) sp.set(k, v); else sp.delete(k) }
    return sp
  }, { replace: true })
  return (
    <div className="report-col">
      <h3>STIG Viewer checklists</h3>
      <p className="muted">
        One host and one scan at a time: a <code>.ckl</code> (STIG Viewer 2, XML) or <code>.cklb</code> (STIG Viewer 3, JSON)
        with every rule&apos;s status, finding details and comments.
      </p>
      <div className="stack">
        <label className="field">
          <span>Host</span>
          <select value={host?.id ?? ''} onChange={(e) => set({ host: e.target.value, scan: '' })}>
            {sorted.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Scan</span>
          <select value={scan?.id ?? ''} disabled={!scans?.length} onChange={(e) => set({ scan: e.target.value })}>
            {(scans || []).map((s, i) => (
              <option key={s.id} value={s.id}>{formatDate(s.collected_at)}{i === 0 ? ' (latest)' : ''} · {s.benchmark_release}</option>
            ))}
          </select>
        </label>
      </div>
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !scans && <Loading label="Loading scans…" />}
      {scan && (
        <div className="exports left" role="group" aria-label="Checklist downloads">
          <a className="btn secondary" href={api.cklUrl(scan.id)} download><Icon name="download" />Checklist .ckl</a>
          <a className="btn secondary" href={api.cklbUrl(scan.id)} download><Icon name="download" />Checklist .cklb</a>
        </div>
      )}
    </div>
  )
}

/**
 * The fleet report drawn from the API's own numbers. The downloadable HTML report is served as
 * an attachment that may not be framed, and its text is never inserted into this page, so the
 * preview is built here from the same JSON as plain React text.
 */
function FleetPreview({ fleet, hosts }) {
  const rows = useMemo(() => sortHostsByRisk(scannedHosts(hosts)), [hosts])
  const asOf = rows.map((h) => h.latest_scan.collected_at).sort().at(-1)
  const regressions = fleet.regressions || []
  return (
    <Panel id="preview" flush title="Fleet report preview"
      desc="Drawn from the same data as the downloadable HTML report, which is a standalone page to open from disk.">
      <article className="report-preview">
        <div className="report-head">
          <h3 className="paper-title">STIGWatch fleet report</h3>
          <p className="muted">
            {plural(fleet.hosts, 'host')}. Latest scan collected {asOf ? formatDateTime(asOf) : 'n/a'}. Open findings are counted from each host&apos;s latest scan.
          </p>
          <dl className="report-stats">
            {CATS.map((c) => (
              <div key={c}><dt><CatBadge cat={c} /></dt><dd>{fleet.open?.[c] ?? 0}<span className="muted"> open</span></dd></div>
            ))}
            <div><dt>Compliance</dt><dd>{formatPct(fleet.compliance)}</dd><dd className="muted def">{COMPLIANCE_DEFINITION}</dd></div>
          </dl>
        </div>
        <h4 className="report-h">Hosts</h4>
        <div className="table-wrap">
          <table className="table compact cards">
            <caption className="sr-only">Hosts in the fleet report</caption>
            <thead>
              <tr>
                <th scope="col">Host</th><th scope="col">System</th><th scope="col">Last scan</th>
                {CATS.map((c) => <th key={c} scope="col" className="num">{c}</th>)}
                <th scope="col" className="num">Compliance</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.id}>
                  <th scope="row"><Link to={`/hosts/${h.id}`} className="host-link">{h.name}</Link></th>
                  <td data-label="System"><OsTag os={h.os} /></td>
                  <td data-label="Last scan" className="date-cell">{formatDate(h.latest_scan.collected_at)} · {h.latest_scan.benchmark_release}</td>
                  {CATS.map((c) => <td key={c} data-label={c} className="num count-cell"><OpenCount n={h.open?.[c] || 0} cat={c} /></td>)}
                  <td data-label="Compliance" className="num">{formatPct(h.compliance)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <h4 className="report-h">Top regressions</h4>
        {regressions.length ? (
          <>
            <p className="muted report-note">Rules that were Not a finding or Not applicable in a host&apos;s previous scan and are Open in its latest.</p>
            <div className="table-wrap">
              <table className="table compact cards">
                <caption className="sr-only">Top regressions</caption>
                <thead>
                  <tr>
                    <th scope="col">Rule</th><th scope="col">CAT</th><th scope="col">Host</th>
                    <th scope="col">Title</th><th scope="col">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {regressions.slice(0, 15).map((r) => (
                    <tr key={`${r.host}-${r.stig_id}`}>
                      <th scope="row" className="mono">{r.stig_id}</th>
                      <td data-label="CAT"><CatBadge cat={r.cat} /></td>
                      <td data-label="Host">{r.host}</td>
                      <td data-label="Title" className="title-cell">{r.title}</td>
                      <td data-label="Change">
                        <span className="drift-change"><StatusChip status={r.from} /><Icon name="arrow" size={13} /><span className="sr-only"> to </span><StatusChip status="Open" /></span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {regressions.length > 15 && <p className="muted report-note">{regressions.length - 15} more not shown.</p>}
          </>
        ) : <p className="muted report-note">No regressions between the latest two scans of any host.</p>}
        <h4 className="report-h">How to read this</h4>
        <p className="muted report-note">
          Compliance is Not a finding divided by Open plus Not a finding in the latest scan; Not reviewed and Not applicable
          rules are not counted. A high percentage with many Not reviewed rules means little was checked, so read it
          with the scan coverage.
        </p>
        <p className="disclaimer report-note">{DISCLAIMER}</p>
      </article>
    </Panel>
  )
}

export default function Reports() {
  usePageTitle('Reports')
  const { data, error, loading, reload } = useAsync(loadReports, [])
  const scanned = scannedHosts(data?.hosts || [])
  return (
    <div className="page">
      <PageHead title="Reports" sub="Fleet reports and STIG Viewer checklists, generated on demand from the stored scans.">
        <About>
          <p>
            Download the fleet report for a meeting, or a STIG Viewer checklist for an assessor. Every file is
            generated on demand from the stored scans.
          </p>
        </About>
      </PageHead>

      {loading && !data && <Loading label="Loading reports…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && !scanned.length && <NoData onChanged={reload} />}
      {data && scanned.length > 0 && (
        <>
          <Panel id="downloads" title="Downloads">
            <div className="report-grid">
              <div className="report-col">
                <h3>Fleet report</h3>
                <p className="muted">All hosts in one file. HTML is self-contained and printable; CSV opens in a spreadsheet.</p>
                <div className="exports left" role="group" aria-label="Fleet downloads">
                  <a className="btn secondary" href={api.fleetHtmlUrl()} download><Icon name="download" />Fleet report (HTML)</a>
                  <a className="btn secondary" href={api.fleetCsvUrl()} download><Icon name="download" />Fleet summary (CSV)</a>
                </div>
              </div>
              <HostChecklists hosts={scanned} />
            </div>
          </Panel>
          <FleetPreview fleet={data.fleet} hosts={data.hosts} />
        </>
      )}
    </div>
  )
}
