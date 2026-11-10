// Thin wrapper around the STIGWatch REST API (all routes under /api).
//
// Authentication uses an httpOnly session cookie that the browser sends with same-origin
// requests, so no token is ever handled in JavaScript. Any 401 fires a
// "stigwatch:unauthorized" event and the app returns to the sign-in screen.

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, { credentials: 'same-origin', ...options })
  } catch {
    throw new ApiError('Cannot reach the STIGWatch API.', 0)
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body.detail) {
        detail = typeof body.detail === 'string'
          ? body.detail
          : body.detail.map?.((d) => d.msg).join('; ') || JSON.stringify(body.detail)
      }
    } catch { /* not JSON */ }
    if (res.status === 401 && !path.startsWith('/auth/')) {
      window.dispatchEvent(new Event('stigwatch:unauthorized'))
    }
    throw new ApiError(detail, res.status)
  }
  return res.json()
}

const send = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

const enc = encodeURIComponent

export const api = {
  health: () => request('/health'),
  me: () => request('/auth/me'),
  login: (username, password) => request('/auth/login', send('POST', { username, password })),
  logout: () => request('/auth/logout', { method: 'POST' }),

  fleet: () => request('/fleet'),
  alerts: () => request('/alerts'),
  hosts: () => request('/hosts'),
  host: (id) => request(`/hosts/${enc(id)}`),
  hostScans: (id) => request(`/hosts/${enc(id)}/scans`),
  scanResults: (scanId) => request(`/scans/${enc(scanId)}/results`),
  scanDrift: (scanId) => request(`/scans/${enc(scanId)}/drift`),
  rule: (hostId, stigId) => request(`/hosts/${enc(hostId)}/rules/${enc(stigId)}`),

  /** Same-origin download links; the session cookie goes with them. */
  cklUrl: (scanId) => `/api/scans/${enc(scanId)}/export.ckl`,
  cklbUrl: (scanId) => `/api/scans/${enc(scanId)}/export.cklb`,
  remediationUrl: (hostId) => `/api/hosts/${enc(hostId)}/remediation`,
  fleetCsvUrl: () => '/api/reports/fleet.csv',
  fleetHtmlUrl: () => '/api/reports/fleet.html',

  // Writer-only; the server answers 403 for guests.
  saveComment: (hostId, stigId, text) => request(`/hosts/${enc(hostId)}/rules/${enc(stigId)}/comment`, send('PUT', { text })),
}
