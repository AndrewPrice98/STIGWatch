// Regenerates docs/screenshots/*.png at 1400 px wide from a running demo (see smoke.mjs).
//   STIGWATCH_URL=http://127.0.0.1:4173 node screenshots.mjs
import { chromium } from 'playwright'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const BASE = process.env.STIGWATCH_URL || 'http://127.0.0.1:4173'
const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'screenshots')
const PAGES = [
  ['fleet', '/'],
  ['findings', '/findings'],
  ['drift', '/drift'],
  ['remediation', '/remediation'],
  ['reports', '/reports'],
  ['benchmarks', '/benchmarks'],
]

const browser = await chromium.launch(process.env.E2E_CHANNEL ? { channel: process.env.E2E_CHANNEL } : {})
try {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 }, colorScheme: 'dark' })
  const page = await ctx.newPage()
  for (const [name, url] of PAGES) {
    await page.goto(BASE + url)
    await page.waitForLoadState('networkidle')
    await page.waitForFunction(() => !document.querySelector('.spinner'), null, { timeout: 30000 })
    await page.waitForTimeout(300)
    await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: false })
    console.log('wrote', name)
  }
} finally {
  await browser.close()
}
