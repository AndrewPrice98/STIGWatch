import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { applyFilters, parseFilters } from './urlFilters.js'

/**
 * Filters that live in the URL, with a debounced search box.
 *
 * `spec` describes the filters once (define it at module level):
 *   { os: { param: 'os', default: '', allow: ['linux', 'windows'] },
 *     q:  { param: 'q', default: '', max: 100, search: true },
 *     cat1: { param: 'cat1', default: false, flag: true } }
 * A value outside `allow` (or longer than `max`) reads as the default, so a hand-edited URL can
 * never put anything unexpected into the page. Default values are left out of the URL, and any
 * other query parameter (for example ?scan=) is preserved.
 *
 * Returns { filters, update(changes), clear(), search, setSearch, submitSearch(), any }.
 * The search box is local state that is written to the URL 200 ms after typing stops.
 */
export function useUrlFilters(spec, { delay = 200 } = {}) {
  const [params, setParams] = useSearchParams()
  const filters = parseFilters(spec, params)
  const searchKey = Object.keys(spec).find((k) => spec[k].search)
  const urlSearch = searchKey ? filters[searchKey] : ''
  const [search, setSearch] = useState(urlSearch)

  // Back/forward, "clear" and links change the URL under the box: follow it.
  useEffect(() => { setSearch((s) => (s.trim() === urlSearch ? s : urlSearch)) }, [urlSearch])

  // Router updates run in a transition, so the params of the last render can lag behind a
  // change made a moment ago. Building each update on the last one we sent (until the router
  // catches up) lets two quick changes (a select, then a checkbox) both land.
  const pending = useRef(null)
  const paramsKey = params.toString()
  useEffect(() => { pending.current = null }, [paramsKey])
  const update = useCallback((changes) => {
    const base = pending.current || new URLSearchParams(paramsKey)
    const next = applyFilters(spec, base, { ...parseFilters(spec, base), ...changes })
    pending.current = next
    setParams(next, { replace: true })
  }, [setParams, spec, paramsKey])

  const updateRef = useRef(update)
  updateRef.current = update
  useEffect(() => {
    if (!searchKey) return undefined
    const value = search.trim()
    if (value === urlSearch) return undefined
    const t = setTimeout(() => updateRef.current({ [searchKey]: value }), delay)
    return () => clearTimeout(t)
  }, [search, urlSearch, searchKey, delay])

  const submitSearch = useCallback(() => {
    if (searchKey) update({ [searchKey]: search.trim() })
  }, [searchKey, search, update])

  const clear = useCallback(() => {
    setSearch('')
    const empty = {}
    for (const [key, def] of Object.entries(spec)) empty[key] = def.default
    update(empty)
  }, [spec, update])

  const any = Object.entries(spec).some(([key, def]) => filters[key] !== def.default && !def.view)
  return { filters, update, clear, search, setSearch, submitSearch, any, params, setParams }
}
