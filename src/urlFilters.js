// Pure helpers behind useUrlFilters (no React, so the Node test runner can import them).
// See useUrlFilters.js for the shape of `spec`.

export function parseFilters(spec, params) {
  const out = {}
  for (const [key, def] of Object.entries(spec)) {
    const raw = params.get(def.param)
    if (def.flag) out[key] = raw === '1'
    else if (raw == null) out[key] = def.default
    else if (def.allow) out[key] = def.allow.includes(raw) ? raw : def.default
    else out[key] = def.max ? raw.slice(0, def.max) : raw
  }
  return out
}

export function applyFilters(spec, params, filters) {
  const sp = new URLSearchParams(params)
  for (const [key, def] of Object.entries(spec)) {
    const value = filters[key]
    if (value === undefined || value === def.default || value === '' || value === false) sp.delete(def.param)
    else sp.set(def.param, def.flag ? '1' : String(value))
  }
  return sp
}
