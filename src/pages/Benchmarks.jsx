import { api } from '../api.js'
import { CommandBlock } from '../components/code.jsx'
import { About, CatBadge, ErrorState, Icon, Loading, PageHead, Panel, useAsync, usePageTitle } from '../components/ui.jsx'
import { CATS, COLLECTOR_STEPS, formatDate, plural } from '../lib.js'

async function loadBenchmarks() {
  const list = await api.benchmarks()
  return Promise.all(list.map(async (b) => ({
    ...b,
    coverage: await api.coverage(b.id).catch(() => null), // a benchmark without checks still lists
  })))
}

const pct = (n, total) => (total ? Math.round((100 * n) / total) : 0)

function CoverageTable({ b }) {
  const cov = b.coverage
  if (!cov) return <p className="muted pad">STIGWatch has no automated checks for this benchmark; every rule is a manual review.</p>
  const totals = CATS.reduce((t, c) => {
    const row = cov.by_cat[c] || {}
    for (const k of ['total', 'automated', 'full', 'partial', 'evidence', 'manual']) t[k] += row[k] || 0
    return t
  }, { total: 0, automated: 0, full: 0, partial: 0, evidence: 0, manual: 0 })
  const rows = [...CATS.map((c) => [c, cov.by_cat[c] || { total: 0, automated: 0, full: 0, partial: 0, evidence: 0, manual: 0 }]), ['All', totals]]
  return (
    <div className="table-wrap">
      <table className="table cards coverage-table">
        <caption className="sr-only">Automated and manual rules by CAT for {b.title}</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col" className="num">Rules</th>
            <th scope="col" className="num">Automated</th>
            <th scope="col" className="num">Manual</th>
            <th scope="col">Share automated</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, r]) => (
            <tr key={label} className={label === 'All' ? 'total-row' : ''}>
              <th scope="row">{label === 'All' ? 'All rules' : <CatBadge cat={label} />}</th>
              <td data-label="Rules" className="num">{r.total}</td>
              <td data-label="Automated" className="num">
                {r.automated}
                {r.automated > 0 && (
                  <span className="muted"> ({r.full} full{r.partial ? `, ${r.partial} partial` : ''}{r.evidence ? `, ${r.evidence} evidence` : ''})</span>
                )}
              </td>
              <td data-label="Manual" className="num">{r.manual}</td>
              <td data-label="Share automated" className="cov-cell">
                <span className="cov-bar" role="img" aria-label={`${pct(r.automated, r.total)} percent automated`}>
                  <span className="cov-fill" style={{ width: `${pct(r.automated, r.total)}%` }} />
                </span>
                <span className="cov-pct">{pct(r.automated, r.total)}%</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BenchmarkPanel({ b }) {
  return (
    <Panel id={`bm-${b.id}`} flush title={b.title}
      desc={`Version ${b.version}, release ${b.release} (${b.label}) · benchmark date ${formatDate(b.date)} · ${plural(b.rules, 'rule')}${b.metadata_only ? ' · metadata only' : ''}`}
      actions={b.source_url && (
        <a className="btn ghost" href={b.source_url} target="_blank" rel="noreferrer noopener">
          <Icon name="external" />DISA package<span className="sr-only"> (opens in a new tab)</span>
        </a>
      )}>
      <ul className="cat-counts" aria-label="Rules by severity">
        {CATS.map((c) => <li key={c}><CatBadge cat={c} /> <strong>{b.severity?.[c] ?? 0}</strong></li>)}
      </ul>
      <h3 className="sub-title">Coverage: automated and manual rules</h3>
      <CoverageTable b={b} />
      <p className="muted cov-legend">
        <strong>Full</strong>: the check can return both Open and Not a finding. <strong>Partial</strong>: it can
        return only one of them; the other outcome stays Not reviewed. <strong>Evidence</strong>: facts are collected for
        the assessor, who decides. <strong>Manual</strong>: no automated check, always Not reviewed.
      </p>
    </Panel>
  )
}

function Collectors() {
  return (
    <Panel id="collectors" title="Collector instructions"
      desc="A collector is a read-only script. It changes no setting and writes one JSON file, which an admin uploads. It never sends anything over the network.">
      <div className="collector-grid">
        {Object.entries(COLLECTOR_STEPS).map(([os, c]) => (
          <div key={os} className="collector">
            <h3>{c.title}</h3>
            <p className="muted">Script: <code>{c.file}</code> in the STIGWatch repository.</p>
            <CommandBlock commands={c.commands} label={`${c.title} collector commands`} />
            <p>{c.note}</p>
          </div>
        ))}
      </div>
      <p className="muted collector-foot">
        Then upload the file from the Hosts page (admin sign-in required). Scans are compared by STIG ID, so run the
        collector on the same schedule, for example weekly, to see drift.
      </p>
    </Panel>
  )
}

export default function Benchmarks() {
  usePageTitle('Benchmarks')
  const { data, error, loading, reload } = useAsync(loadBenchmarks, [])
  return (
    <div className="page">
      <PageHead title="Benchmarks" sub="The DISA STIG releases STIGWatch checks against, and how much of each it can decide on its own.">
        <About>
          <p>
            Automated means the rule is decided from collected facts; the rest stay Not reviewed for a person to assess.
            STIG rule text is DISA content, reproduced unmodified apart from whitespace; STIGWatch is not a DISA product.
          </p>
        </About>
      </PageHead>
      {loading && !data && <Loading label="Loading benchmarks…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.map((b) => <BenchmarkPanel key={b.id} b={b} />)}
      <Collectors />
    </div>
  )
}
