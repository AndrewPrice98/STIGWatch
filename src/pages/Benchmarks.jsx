import { api } from '../api.js'
import { CommandBlock } from '../components/code.jsx'
import { CatBadge, ErrorState, Icon, Loading, PageHead, useAsync, usePageTitle } from '../components/ui.jsx'
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
  if (!cov) return <p className="muted">STIGWatch has no automated checks for this benchmark; every rule is a manual review.</p>
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
                  <span className="muted small"> ({r.full} full{r.partial ? `, ${r.partial} partial` : ''}{r.evidence ? `, ${r.evidence} evidence` : ''})</span>
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

function BenchmarkCard({ b }) {
  return (
    <section className="card" aria-labelledby={`bm-${b.id}`}>
      <div className="card-head">
        <div>
          <h2 id={`bm-${b.id}`}>{b.title}</h2>
          <p className="muted small">
            Version {b.version}, release {b.release} ({b.label}) · benchmark date {formatDate(b.date)} · {plural(b.rules, 'rule')}
            {b.metadata_only && ' · metadata only'}
          </p>
        </div>
        {b.source_url && (
          <a className="btn ghost small" href={b.source_url} target="_blank" rel="noreferrer noopener">
            <Icon name="external" size={15} />DISA package<span className="sr-only"> (opens in a new tab)</span>
          </a>
        )}
      </div>
      <ul className="cat-counts" aria-label="Rules by severity">
        {CATS.map((c) => <li key={c}><CatBadge cat={c} /> <strong>{b.severity?.[c] ?? 0}</strong></li>)}
      </ul>
      <h3 className="sub-title">Coverage: automated and manual rules</h3>
      <CoverageTable b={b} />
      <p className="muted small cov-legend">
        <strong>Full</strong>: the check can return both Open and Not a finding. <strong>Partial</strong>: it can
        return only one of them; the other outcome stays Not reviewed. <strong>Evidence</strong>: facts are collected for
        the assessor, who decides. <strong>Manual</strong>: no automated check, always Not reviewed.
      </p>
    </section>
  )
}

function Collectors() {
  return (
    <section className="card" aria-labelledby="collectors-title">
      <div className="card-head">
        <div>
          <h2 id="collectors-title">Collector instructions</h2>
          <p className="muted small">
            A collector is a read-only script. It changes no setting and writes one JSON file, which an admin uploads.
            It never sends anything over the network.
          </p>
        </div>
      </div>
      <div className="collector-grid">
        {Object.entries(COLLECTOR_STEPS).map(([os, c]) => (
          <div key={os} className="collector">
            <h3>{c.title}</h3>
            <p className="muted small">Script: <code>{c.file}</code> in the STIGWatch repository.</p>
            <CommandBlock commands={c.commands} label={`${c.title} collector commands`} />
            <p className="small">{c.note}</p>
          </div>
        ))}
      </div>
      <p className="muted small">
        Then upload the file from the Hosts page (admin sign-in required). Scans are compared by STIG ID, so run the
        collector on the same schedule, for example weekly, to see drift.
      </p>
    </section>
  )
}

export default function Benchmarks() {
  usePageTitle('Benchmarks')
  const { data, error, loading, reload } = useAsync(loadBenchmarks, [])
  return (
    <div className="page">
      <PageHead eyebrow="DISA STIG catalogs" title="Benchmarks">
        <p className="lede">
          The DISA STIG releases STIGWatch checks against, and how much of each it can decide on its own.
          Automated means the rule is decided from collected facts; the rest stay Not reviewed for a person to assess.
        </p>
      </PageHead>
      {loading && !data && <Loading label="Loading benchmarks…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.map((b) => <BenchmarkCard key={b.id} b={b} />)}
      <Collectors />
    </div>
  )
}
