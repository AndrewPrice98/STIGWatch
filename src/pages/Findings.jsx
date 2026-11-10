import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import { OsTag } from '../components/hosts.jsx'
import { CatBadge, Empty, ErrorState, Loading, PageHead, useAsync, usePageTitle } from '../components/ui.jsx'
import { mapLimit, scannedHosts } from '../data.js'
import { CATS, OS_LABEL, filterFindings, groupFindings, plural } from '../lib.js'
import { useUrlFilters } from '../useUrlFilters.js'

const SPEC = {
  q: { param: 'q', default: '', max: 100, search: true },
  cat: { param: 'cat', default: '', allow: CATS },
  os: { param: 'os', default: '', allow: Object.keys(OS_LABEL) },
}

const PAGE = 40
const SHOWN_HOSTS = 6

async function loadFindings() {
  const hosts = await api.hosts()
  const perHost = await mapLimit(scannedHosts(hosts), 6, async (h) => ({
    host: { id: h.id, name: h.name, os: h.os },
    results: (await api.scanResults(h.latest_scan.id)).results,
  }))
  return { hosts, groups: groupFindings(perHost) }
}

const ruleLink = (hostId, stigId) => `/hosts/${hostId}/rules/${encodeURIComponent(stigId)}`

function HostLinks({ hosts, stigId }) {
  const first = hosts.slice(0, SHOWN_HOSTS)
  const rest = hosts.slice(SHOWN_HOSTS)
  const item = (h) => <li key={h.id}><Link className="host-chip" to={ruleLink(h.id, stigId)}>{h.name}</Link></li>
  return (
    <>
      <ul className="host-chips">{first.map(item)}</ul>
      {rest.length > 0 && (
        <details className="more-hosts">
          <summary>{rest.length} more host{rest.length === 1 ? '' : 's'}</summary>
          <ul className="host-chips">{rest.map(item)}</ul>
        </details>
      )}
    </>
  )
}

export default function Findings() {
  usePageTitle('Findings')
  const { data, error, loading, reload } = useAsync(loadFindings, [])
  const { filters, update, clear, search, setSearch, submitSearch, any } = useUrlFilters(SPEC)
  const [limit, setLimit] = useState(PAGE)

  const shown = useMemo(() => (data ? filterFindings(data.groups, filters) : []),
    [data, filters.q, filters.cat, filters.os]) // eslint-disable-line react-hooks/exhaustive-deps
  const hostsByOs = useMemo(() => {
    const counts = { linux: 0, windows: 0 }
    for (const h of scannedHosts(data?.hosts || [])) counts[h.os] = (counts[h.os] || 0) + 1
    return counts
  }, [data])
  const visible = shown.slice(0, limit)

  return (
    <div className="page">
      <PageHead eyebrow="Across the fleet" title="Findings">
        <p className="lede">
          Open findings from every host&apos;s latest scan, grouped by STIG ID, so you can see which rules fail on
          the most hosts. A rule that could not be checked is Not reviewed, not a pass, and is listed apart.
        </p>
      </PageHead>

      {loading && !data && <Loading label="Loading findings…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.hosts.length === 0 && <NoData onChanged={reload} />}
      {data && data.hosts.length > 0 && (
        <>
          <form className="filters card" role="search" aria-label="Filter findings" onSubmit={(e) => { e.preventDefault(); submitSearch() }}>
            <label className="field grow">
              <span>Search</span>
              <input type="search" value={search} maxLength={100} placeholder="STIG ID or rule title"
                onChange={(e) => setSearch(e.target.value)} />
            </label>
            <label className="field">
              <span>Severity</span>
              <select value={filters.cat} onChange={(e) => update({ cat: e.target.value })}>
                <option value="">All CATs</option>
                {CATS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
            <label className="field">
              <span>Operating system</span>
              <select value={filters.os} onChange={(e) => update({ os: e.target.value })}>
                <option value="">All</option>
                {Object.entries(OS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </label>
            {any && <button type="button" className="btn ghost small" onClick={clear}>Clear filters</button>}
          </form>

          <section className="card" aria-labelledby="findings-count">
            <div className="card-head">
              <div>
                <h2 id="findings-count" aria-live="polite">
                  {any ? `${shown.length} of ${plural(data.groups.length, 'rule')}` : plural(data.groups.length, 'rule')} open on at least one host
                </h2>
                <p className="muted small">
                  Most hosts first within each CAT. Host counts compare with the {plural(hostsByOs.linux, 'Ubuntu host')} and{' '}
                  {plural(hostsByOs.windows, 'Windows host')} scanned.
                </p>
              </div>
            </div>
            {shown.length ? (
              <div className="table-wrap">
                <table className="table cards findings-table">
                  <caption className="sr-only">Open findings grouped by STIG ID</caption>
                  <thead>
                    <tr>
                      <th scope="col">Rule</th>
                      <th scope="col">CAT</th>
                      <th scope="col" className="num">Open on</th>
                      <th scope="col">Hosts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((g) => {
                      const total = hostsByOs[g.os] || g.open.length
                      return (
                        <tr key={g.stig_id}>
                          <th scope="row">
                            <div className="rule-cell">
                              <span className="mono rule-id">{g.stig_id}</span>
                              <span className="rule-title">{g.title || <span className="muted">Untitled rule</span>}</span>
                              <OsTag os={g.os} />
                            </div>
                          </th>
                          <td data-label="CAT"><CatBadge cat={g.cat} /></td>
                          <td data-label="Open on" className="num">
                            <strong>{g.open.length}</strong><span className="muted small"> of {total} {g.os === 'windows' ? 'Windows' : 'Ubuntu'} hosts</span>
                          </td>
                          <td data-label="Hosts" className="hosts-cell">
                            <HostLinks hosts={g.open} stigId={g.stig_id} />
                            {g.unchecked.length > 0 && (
                              <p className="muted small unchecked">
                                Not reviewed on {g.unchecked.map((h) => h.name).slice(0, 4).join(', ')}
                                {g.unchecked.length > 4 ? ` and ${g.unchecked.length - 4} more` : ''}: not checked, so not counted as open or fixed.
                              </p>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                {shown.length > visible.length && (
                  <div className="more-row">
                    <span className="muted small">Showing {visible.length} of {shown.length}.</span>
                    <button type="button" className="btn secondary small" onClick={() => setLimit(shown.length)}>
                      Show all {shown.length} rules
                    </button>
                  </div>
                )}
              </div>
            ) : <Empty>{data.groups.length ? 'No finding matches these filters.' : 'No host has an open finding in its latest scan.'}</Empty>}
          </section>
        </>
      )}
    </div>
  )
}
