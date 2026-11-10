import { useMemo } from 'react'
import { api } from '../api.js'
import { HOST_SORTS, OS_LABEL, environments, filterHosts, plural, sortHosts } from '../lib.js'
import { AdminTools, NoData } from '../components/admin.jsx'
import { HostTable } from '../components/hosts.jsx'
import { Empty, ErrorState, Loading, PageHead, useAsync, usePageTitle } from '../components/ui.jsx'
import { useUrlFilters } from '../useUrlFilters.js'

const SORT_KEYS = Object.keys(HOST_SORTS)

export default function Hosts() {
  usePageTitle('Hosts')
  const { data, error, loading, reload } = useAsync(() => api.hosts(), [])
  const envs = useMemo(() => environments(data || []), [data])
  // The environment list comes from the data, so the allow-list is built from it. Until the data
  // is here any value is kept, so a shared ?env= link is not dropped from the URL while loading.
  const spec = useMemo(() => ({
    os: { param: 'os', default: '', allow: Object.keys(OS_LABEL) },
    environment: data ? { param: 'env', default: '', allow: envs } : { param: 'env', default: '', max: 100 },
    cat1: { param: 'cat1', default: false, flag: true },
    q: { param: 'q', default: '', max: 100, search: true },
    sort: { param: 'sort', default: 'risk', allow: SORT_KEYS, view: true },
  }), [envs, data])
  const { filters, update, clear, search, setSearch, submitSearch, any: anyFilter } = useUrlFilters(spec)

  const shown = useMemo(() => (data ? sortHosts(filterHosts(data, filters), filters.sort) : []),
    [data, filters.os, filters.environment, filters.cat1, filters.q, filters.sort]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="page">
      <PageHead eyebrow="Inventory" title="Hosts">
        <p className="lede">Every scanned host with the open findings, compliance and coverage of its latest scan.</p>
      </PageHead>

      {(!data || data.length > 0) && <form className="filters card" role="search" aria-label="Filter hosts"
        onSubmit={(e) => { e.preventDefault(); submitSearch() }}>
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
      </form>}

      {loading && !data && <Loading label="Loading hosts…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && <NoData onChanged={reload} />}
      {data && data.length > 0 && (
        <section className="card" aria-labelledby="hosts-count">
          <div className="card-head">
            <h2 id="hosts-count" aria-live="polite">
              {anyFilter ? `${shown.length} of ${plural(data.length, 'host')}` : plural(data.length, 'host')}
            </h2>
            {anyFilter && (
              <button type="button" className="btn ghost small" onClick={clear}>Clear filters</button>
            )}
          </div>
          {shown.length
            ? <HostTable hosts={shown} caption="Hosts" />
            : <Empty>No host matches these filters.</Empty>}
        </section>
      )}
      {data && data.length > 0 && <AdminTools onChanged={reload} />}
    </div>
  )
}
