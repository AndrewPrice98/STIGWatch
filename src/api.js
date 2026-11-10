// Thin wrapper around the STIGWatch REST API (all routes under /api).
//
// Authentication uses an httpOnly session cookie that the browser sends with same-origin
// requests, so no token is ever handled in JavaScript. Any 401 fires a
// "stigwatch:unauthorized" event and the app returns to the sign-in screen.

export class ApiError extends Error {
  constructor(message, status, retryAfter = null) {
    super(message)
    this.status = status
    /** Seconds from a Retry-After header (503 while the demo data is being prepared), or null. */
    this.retryAfter = retryAfter
  }
}

async function send_(path, options) {
  let res
  try {
    res = await fetch(`/api${path}`, { credentials: 'same-origin', ...options })
  } catch {
    throw new ApiError('Cannot reach the STIGWatch API.', 0)
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`.trim()
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
    const retry = Number(res.headers.get('Retry-After'))
    throw new ApiError(detail, res.status, Number.isFinite(retry) && retry > 0 ? retry : null)
  }
  return res
}

/** A 2xx body that is not JSON (a proxy error page, an HTML fallback) is an ApiError, not a SyntaxError. */
export async function parseJsonBody(res) {
  try {
    return await res.json()
  } catch {
    throw new ApiError('Unexpected response from the API', res.status)
  }
}

async function request(path, options = {}) {
  return parseJsonBody(await send_(path, options))
}

async function requestText(path) {
  const res = await send_(path, {})
  return res.text()
}

const send = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

function upload(file) {
  const body = new FormData()
  body.append('file', file)
  return { method: 'POST', body } // the browser sets the multipart boundary
}

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
  benchmarks: () => request('/benchmarks'),
  coverage: (benchmarkId) => request(`/benchmarks/${enc(benchmarkId)}/coverage`),
  rule: (hostId, stigId) => request(`/hosts/${enc(hostId)}/rules/${enc(stigId)}`),

  /** Same-origin download links; the session cookie goes with them. */
  cklUrl: (scanId) => `/api/scans/${enc(scanId)}/export.ckl`,
  cklbUrl: (scanId) => `/api/scans/${enc(scanId)}/export.cklb`,
  remediationUrl: (hostId) => `/api/hosts/${enc(hostId)}/remediation`,
  fleetCsvUrl: () => '/api/reports/fleet.csv',
  fleetHtmlUrl: () => '/api/reports/fleet.html',

  /** The generated remediation file as text (shown in a <pre>; never parsed or inserted as HTML). */
  remediationText: (hostId) => requestText(`/hosts/${enc(hostId)}/remediation`),

  // Writer-only; the server answers 403 for guests.
  createHost: (body) => request('/hosts', send('POST', body)),
  /** Upload collector JSON (multipart field "file"); the host comes from the name in the file. */
  uploadScan: (file) => request('/scans', upload(file)),
  uploadHostScan: (hostId, file) => request(`/hosts/${enc(hostId)}/scans`, upload(file)),
  saveComment: (hostId, stigId, text) => request(`/hosts/${enc(hostId)}/rules/${enc(stigId)}/comment`, send('PUT', { text })),
}
