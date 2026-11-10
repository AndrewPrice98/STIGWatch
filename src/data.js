// Loaders that combine several API calls for the fleet-wide pages.
import { api } from './api.js'

/** Run `fn` over `items` with at most `limit` calls in flight; results keep the input order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  async function worker() {
    while (next < items.length) {
      const i = next
      next += 1
      out[i] = await fn(items[i], i)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

/** Hosts that have been scanned at least once. */
export const scannedHosts = (hosts) => hosts.filter((h) => h.latest_scan)

/** Every scanned host's scan list: [{ host: {id, name, os}, scans }]. */
export function loadHostScans(hosts) {
  return mapLimit(scannedHosts(hosts), 6, async (h) => ({
    host: { id: h.id, name: h.name, os: h.os },
    scans: await api.hostScans(h.id),
  }))
}
