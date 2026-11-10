// End-to-end smoke test for the built dashboard against the demo API.
//
//   STIGWATCH_URL=http://127.0.0.1:4173 node smoke.mjs      (default URL shown)
//   E2E_CHANNEL=chrome node smoke.mjs                        (use an installed Chrome; CI installs Chromium)
//
// Needs `python -m stigwatch demo --serve` and `npm run build && npx vite preview` (see README).
// Checks, as an anonymous guest: the dashboard is read-only (no upload form, writes get 403),
// and a rule that lost visibility (Open -> Not reviewed) is listed apart and never as "Fixed".
import { chromium } from 'playwright'

const BASE = process.env.STIGWATCH_URL || 'http://127.0.0.1:4173'
const failures = []
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `  [${detail}]`}`)
  if (!ok) failures.push(name)
}

async function settle(page) {
  await page.waitForLoadState('networkidle')
  await page.waitForFunction(() => !document.querySelector('.spinner'), null, { timeout: 30000 })
}

const browser = await chromium.launch(process.env.E2E_CHANNEL ? { channel: process.env.E2E_CHANNEL } : {})
try {
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage()
  const problems = []
  page.on('pageerror', (e) => problems.push(e.message))

  // --- guest is read-only -------------------------------------------------------------------
  await page.goto(`${BASE}/`)
  await settle(page)
  check('guest sees the Demo badge', (await page.locator('.badge.demo').count()) > 0)
  check('fleet page shows hosts data', (await page.locator('.kpi-grid').count()) === 1)
  for (const path of ['/hosts', '/hosts/1', '/reports']) {
    await page.goto(`${BASE}${path}`)
    await settle(page)
    check(`guest: no upload form on ${path}`, (await page.locator('input[type=file]').count()) === 0)
  }
  const health = await page.evaluate(() => fetch('/api/health').then((r) => r.json()))
  check('health reports demo, guest and an upload limit', health.demo === true && health.guest === true && health.max_upload_mb > 0, JSON.stringify(health))
  const writes = await page.evaluate(async () => {
    const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }).then((r) => r.status)
    return [
      await post('/api/hosts', '{"name":"x","os":"linux"}'),
      await post('/api/scans', '{}'),
    ]
  })
  check('guest writes are refused (403)', writes.every((s) => s === 403), writes.join(','))

  // --- lost visibility is never "fixed" -----------------------------------------------------
  await page.goto(`${BASE}/drift`)
  await settle(page)
  const lost = page.locator('.drift-group', { has: page.locator('h3', { hasText: 'Lost visibility' }) })
  const fixed = page.locator('.drift-group', { has: page.locator('h3', { hasText: /^\s*Fixed/ }) })
  check('week 6 has a "Lost visibility" group', (await lost.count()) === 1)
  const lostText = await lost.innerText()
  const lostId = lostText.match(/(UBTU|WN22)-[\w-]+/)?.[0]
  check('it says the rules are not known to be fixed', /Not known to be fixed/.test(lostText), lostText.slice(0, 120))
  check('a lost-visibility rule is not in the Fixed group', Boolean(lostId) && !(await fixed.innerText()).includes(lostId), lostId)

  check('no uncaught page errors', problems.length === 0, problems.join(' | '))
} finally {
  await browser.close()
}
if (failures.length) {
  console.error(`\n${failures.length} check(s) failed`)
  process.exit(1)
}
console.log('\nsmoke test passed')
