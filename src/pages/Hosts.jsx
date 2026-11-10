import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { HOST_SORTS, OS_LABEL, environments, filterHosts, plural, sortHosts } from '../lib.js'
import { HostTable } from '../components/hosts.jsx'
import { Empty, ErrorState, Loading, PageHead, useAsync, usePageTitle } from '../components/ui.jsx'

/** Read filters from the URL, dropping anything that is not on the allow-lists. */
function readFilters(params, envs) {
  const os = params.get('os') || ''
  const env = params.get('env') || ''
  const sort = params.get('sort') || 'risk'
  return {
    os: os in OS_LABEL ? os : '',
    environment: envs.includes(env) ? env : '',
    cat1: params.get('cat1') === '1',
    q: (params.get('q') || '').slice(0, 100),
    sort: sort in HOST_SORTS ? sort : 'risk',
  }
}

export default function Hosts() {
  usePageTitle('Hosts')
  const { data, error, loading, reload } = useAsync(() => api.hosts(), [])
  const [params, setParams] = useSearchParams()
  const envs = useMemo(() => environments(data || []), [data])
  const filters = readFilters(params, envs)
  const [search, setSearch] = useState(filters.q)

  useEffect(() => { setSearch((s) => (s.trim() === filters.q ? s : filters.q)) }, [filters.q])

  function update(changes) {
    // Read the URL as it is now, not as it was at the last render: router updates run in a
    // transition, so two quick changes would otherwise undo each other.
    const next = { ...readFilters(new URLSearchParams(window.location.search), envs), ...changes }
    const sp = new URLSearchParams()
    if (next.os) sp.set('os', next.os)
    if (next.environment) sp.set('env', next.environment)
    if (next.cat1) sp.set('cat1', '1')
    if (next.q) sp.set('q', next.q)
    if (next.sort !== 'risk') sp.set('sort', next.sort)
    setParams(sp, { replace: true })
  }

  useEffect(() => {
    const value = search.trim()
    if (value === filters.q) return undefined
    const t = setTimeout(() => update({ q: value }), 200)
    return () => clearTimeout(t)
  }, [search]) // eslint-disable-line react-hooks/exhaustive-deps

  const shown = useMemo(() => (data ? sortHosts(filterHosts(data, filters), filters.sort) : []),
    [data, filters.os, filters.environment, filters.cat1, filters.q, filters.sort]) // eslint-disable-line react-hooks/exhaustive-deps
  const anyFilter = filters.os || filters.environment || filters.cat1 || filters.q

  return (
    <div className="page">
      <PageHead eyebrow="Inventory" title="Hosts">
        <p className="lede">Every scanned host with the open findings, compliance and coverage of its latest scan.</p>
      </PageHead>

      <form className="filters card" role="search" aria-label="Filter hosts"
        onSubmit={(e) => { e.preventDefault(); update({ q: search.trim() }) }}>
        <label className="field grow">
          <span>Search</span>
          <input type="search" value={search} maxLength={100} placeholder="Name, owner or tag"
            onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="field">
          <span>Operating system</span>
          <select value={filters.os} onChange={(e) => update({ os: e.target.value })}>
            <option value="">All</option>
            {Object.entries(OS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Environment</span>
          <select value={filters.environment} onChange={(e) => update({ environment: e.target.value })}>
            <option value="">All</option>
            {envs.map((e) => <option key={e} value={e}>{e}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Sort</span>
          <select value={filters.sort} onChange={(e) => update({ sort: e.target.value })}>
            {Object.entries(HOST_SORTS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="check-field">
          <input type="checkbox" checked={filters.cat1} onChange={(e) => update({ cat1: e.target.checked })} />
          <span>Has open CAT I</span>
        </label>
      </form>

      {loading && !data && <Loading label="Loading hosts…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <section className="card" aria-labelledby="hosts-count">
          <div className="card-head">
            <h2 id="hosts-count" aria-live="polite">
              {anyFilter ? `${shown.length} of ${plural(data.length, 'host')}` : plural(data.length, 'host')}
            </h2>
            {anyFilter && (
              <button type="button" className="btn ghost small" onClick={() => { setSearch(''); setParams({}, { replace: true }) }}>
                Clear filters
              </button>
            )}
          </div>
          {shown.length
            ? <HostTable hosts={shown} caption="Hosts" />
            : <Empty>No host matches these filters.</Empty>}
        </section>
      )}
    </div>
  )
}
