import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DISCLAIMER, alertFrom, asyncView, buildTimeline, catBreakdown, defaultWeek, describeDelta, environments, lostByScan,
  filterFindings, filterHosts, filterResults, formatBytes, formatDate, formatPct, groupFindings, hostsAtRisk,
  listWords, mergeDrift, niceMax, notReviewedCount, ranUnprivileged, regressionStory, sortHosts, sortHostsByRisk,
  sortResults, splitStigText, weekDelta, weekOf, weekStart, writeErrorMessage,
} from './lib.js'
import { ApiError, parseJsonBody } from './api.js'
import { highlight } from './highlight.js'
import { applyFilters, parseFilters } from './urlFilters.js'
import { mapLimit } from './data.js'

const host = (name, open, extra = {}) => ({
  name, os: 'linux', environment: 'prod', owner: 'Ops', tags: [], compliance: 99,
  open: { 'CAT I': open[0], 'CAT II': open[1], 'CAT III': open[2] }, ...extra,
})

test('disclaimer is the exact required text', () => {
  assert.equal(DISCLAIMER,
    "STIGWatch is an independent tool. It is not a DISA product and does not replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")
})

test('compliance is shown as supplied by the API, with a dash when nothing was decided', () => {
  assert.equal(formatPct(null), '—')
  assert.equal(formatPct(96.8), '96.8%')
  assert.equal(formatPct(100), '100.0%')
})

test('week delta compares the last two trend points per CAT', () => {
  const trend = [
    { week: '2026-10-19', open: { 'CAT I': 3, 'CAT II': 80, 'CAT III': 22 } },
    { week: '2026-10-26', open: { 'CAT I': 7, 'CAT II': 62, 'CAT III': 16 } },
    { week: '2026-11-02', open: { 'CAT I': 7, 'CAT II': 44, 'CAT III': 10 } },
  ]
  assert.deepEqual(weekDelta(trend, 'CAT I'), { current: 7, previous: 7, change: 0, since: '2026-10-26', lost: 0 })
  assert.equal(weekDelta(trend, 'CAT II').change, -18)
  assert.equal(weekDelta(trend.slice(0, 2), 'CAT I').change, 4)
  assert.equal(weekDelta(trend.slice(0, 1), 'CAT I'), null)
  assert.equal(weekDelta([], 'CAT I'), null)
})

test('fewer open findings reads as good, more as bad, with words not just colour', () => {
  assert.deepEqual(describeDelta(-2), { arrow: '↓', text: '2 fewer', tone: 'good', sr: 'down 2 from the previous week' })
  assert.equal(describeDelta(4).tone, 'bad')
  assert.equal(describeDelta(4).text, '4 more')
  assert.equal(describeDelta(0).text, 'no change')
  assert.equal(describeDelta(null), null)
})

test('findings that only lost visibility are not reported as fewer', () => {
  const trend = [
    { week: '2026-10-26', open: { 'CAT III': 3 }, lost_visibility: { 'CAT III': 0 } },
    { week: '2026-11-02', open: { 'CAT III': 2 }, lost_visibility: { 'CAT III': 1 } },
  ]
  const d = weekDelta(trend, 'CAT III')
  assert.equal(d.lost, 1)
  const shown = describeDelta(d.change, d.lost)
  assert.equal(shown.tone, 'neutral')
  assert.match(shown.text, /1 lost visibility/)
  assert.match(shown.sr, /not confirmed fixed/)
  assert.equal(describeDelta(-1, 0).tone, 'good', 'a real decrease is still good')
  assert.equal(describeDelta(2, 1).tone, 'bad', 'an increase is bad either way')
})

test('hosts sort by open CAT I, then CAT II, CAT III, compliance and name', () => {
  const hosts = [
    host('b', [0, 5, 0]), host('a', [0, 5, 0]), host('c', [1, 0, 0]), host('d', [0, 5, 3]),
    host('e', [0, 5, 0], { compliance: 90 }), host('f', [2, 3, 0]),
  ]
  assert.deepEqual(sortHostsByRisk(hosts).map((h) => h.name), ['f', 'c', 'd', 'e', 'a', 'b'])
  assert.deepEqual(hosts.map((h) => h.name), ['b', 'a', 'c', 'd', 'e', 'f'], 'input is not mutated')
})

test('hosts at risk keeps only hosts with open CAT I or CAT II', () => {
  const hosts = [host('clean', [0, 0, 4]), host('x', [0, 1, 0]), host('y', [1, 0, 0])]
  assert.deepEqual(hostsAtRisk(hosts).map((h) => h.name), ['y', 'x'])
  assert.equal(hostsAtRisk(hosts, 1).length, 1)
})

test('host sort options', () => {
  const hosts = [
    host('web', [0, 1, 0], { compliance: 98, latest_scan: { collected_at: '2026-11-09T02:00:00Z' } }),
    host('api', [1, 0, 0], { compliance: 99, latest_scan: { collected_at: '2026-11-09T03:00:00Z' } }),
    host('db', [0, 0, 0], { compliance: null, latest_scan: null }),
  ]
  assert.deepEqual(sortHosts(hosts, 'name').map((h) => h.name), ['api', 'db', 'web'])
  assert.deepEqual(sortHosts(hosts, 'compliance').map((h) => h.name), ['web', 'api', 'db'])
  assert.deepEqual(sortHosts(hosts, 'scanned').map((h) => h.name), ['api', 'web', 'db'])
  assert.deepEqual(sortHosts(hosts).map((h) => h.name), ['api', 'web', 'db'])
})

test('host filters: OS, environment, has CAT I, search over name/owner/tags', () => {
  const hosts = [
    host('web-01', [1, 0, 0], { tags: ['internet-facing'] }),
    host('dc-01', [0, 3, 0], { os: 'windows', environment: 'prod', owner: 'Identity' }),
    host('ci-01', [0, 1, 2], { environment: 'dev', owner: 'DevOps' }),
  ]
  assert.deepEqual(filterHosts(hosts, { os: 'windows' }).map((h) => h.name), ['dc-01'])
  assert.deepEqual(filterHosts(hosts, { environment: 'DEV' }).map((h) => h.name), ['ci-01'])
  assert.deepEqual(filterHosts(hosts, { cat1: true }).map((h) => h.name), ['web-01'])
  assert.deepEqual(filterHosts(hosts, { q: 'identity' }).map((h) => h.name), ['dc-01'])
  assert.deepEqual(filterHosts(hosts, { q: 'internet' }).map((h) => h.name), ['web-01'])
  assert.deepEqual(filterHosts(hosts, { q: 'windows server' }).map((h) => h.name), ['dc-01'])
  assert.equal(filterHosts(hosts, {}).length, 3)
  assert.deepEqual(environments([...hosts, host('x', [0, 0, 0], { environment: 'staging' })]), ['prod', 'staging', 'dev'])
})

test('results sort Open first, then Not reviewed, then by CAT and STIG ID', () => {
  const rows = [
    { stig_id: 'B', status: 'NotAFinding', cat: 'CAT I' },
    { stig_id: 'C', status: 'Open', cat: 'CAT II' },
    { stig_id: 'A', status: 'Open', cat: 'CAT II' },
    { stig_id: 'D', status: 'Open', cat: 'CAT I' },
    { stig_id: 'E', status: 'Not_Reviewed', cat: 'CAT III' },
    { stig_id: 'F', status: 'Not_Applicable', cat: 'CAT I' },
  ]
  assert.deepEqual(sortResults(rows).map((r) => r.stig_id), ['D', 'A', 'C', 'E', 'B', 'F'])
})

test('result filters by status, CAT and text', () => {
  const rows = [
    { stig_id: 'UBTU-22-255025', status: 'Open', cat: 'CAT I', title: 'SSH unattended login', reason: '' },
    { stig_id: 'UBTU-22-211015', status: 'NotAFinding', cat: 'CAT I', title: 'Ctrl-Alt-Delete', reason: '' },
    { stig_id: 'UBTU-22-654010', status: 'Not_Reviewed', cat: 'CAT II', title: 'audit', reason: 'requires root' },
  ]
  assert.equal(filterResults(rows, { status: 'Open' }).length, 1)
  assert.equal(filterResults(rows, { cat: 'CAT I' }).length, 2)
  assert.deepEqual(filterResults(rows, { q: 'ctrl' }).map((r) => r.stig_id), ['UBTU-22-211015'])
  assert.deepEqual(filterResults(rows, { q: 'requires ROOT' }).map((r) => r.stig_id), ['UBTU-22-654010'])
  assert.equal(filterResults(rows, { status: 'Open', cat: 'CAT II' }).length, 0)
})

test('CAT breakdown counts every status per CAT', () => {
  const b = catBreakdown([
    { cat: 'CAT I', status: 'Open' }, { cat: 'CAT I', status: 'NotAFinding' },
    { cat: 'CAT II', status: 'Not_Reviewed' }, { cat: 'CAT X', status: 'Open' },
  ])
  assert.deepEqual(b['CAT I'], { Open: 1, NotAFinding: 1, Not_Applicable: 0, Not_Reviewed: 0, total: 2 })
  assert.equal(b['CAT II'].Not_Reviewed, 1)
  assert.equal(b['CAT III'].total, 0)
})

test('scan privilege is tri-state: only an explicit false makes the banner claim', () => {
  assert.equal(ranUnprivileged({ privileged: false }), true)
  assert.equal(ranUnprivileged({ privileged: true }), false)
  assert.equal(ranUnprivileged({ privileged: null }), false)
  assert.equal(ranUnprivileged({}), false)
  assert.equal(ranUnprivileged(undefined), false)
  assert.equal(notReviewedCount({ status: { Not_Reviewed: 90 } }), 90)
  assert.equal(notReviewedCount({}), 0)
})

test('regression story buckets alerts by the scan collected_at, not the alert created_at', () => {
  const trend = ['2026-09-21', '2026-09-28', '2026-10-05', '2026-10-12', '2026-10-19', '2026-10-26', '2026-11-02', '2026-11-09']
    .map((week) => ({ week, open: {} }))
  const alert = (host_id, host_name, stig_id, collected_at, created_at = '2030-01-01T00:00:00Z') =>
    ({ host_id, host_name, stig_id, collected_at, created_at, cat: 'CAT I', kind: 'cat1_regression' })
  const alerts = [
    alert(11, 'file-01', 'WN22-SO-000210', '2026-10-26T03:08:56Z'),
    alert(11, 'file-01', 'WN22-AC-000090', '2026-10-26T03:08:56Z'),
    alert(1, 'web-01', 'UBTU-22-255040', '2026-10-26T02:32:44Z'),
    alert(1, 'web-01', 'UBTU-22-255025', '2026-10-26T02:32:44Z'),
    alert(2, 'web-02', 'UBTU-22-255025', '2026-11-02T02:32:44Z'),
  ]
  const story = regressionStory(alerts, trend)
  assert.equal(story.day, '2026-10-26', 'created_at (2030) is ignored')
  assert.equal(story.week, 6)
  assert.deepEqual(story.hosts.map((h) => h.name), ['file-01', 'web-01'])
  assert.deepEqual(story.rules.map((r) => r.stig_id), ['WN22-AC-000090', 'WN22-SO-000210', 'UBTU-22-255025', 'UBTU-22-255040'])
  assert.equal(story.total, 5)
  assert.equal(regressionStory([], trend), null)
  assert.equal(regressionStory([{ ...alerts[0], collected_at: undefined }], trend), null, 'an alert with no scan date is not guessed')
  assert.equal(weekOf('2026-09-20', trend.map((t) => t.week)), null)
})

test('chart scales round up to readable maxima', () => {
  assert.equal(niceMax(194), 200)
  assert.equal(niceMax(65), 100)
  assert.equal(niceMax(7), 10)
  assert.equal(niceMax(0), 1)
  assert.equal(niceMax(2.2), 2.5)
})

test('STIG text splits into prose and command blocks', () => {
  const text = 'Verify that unattended login is disabled with the following command:\n\n'
    + "     $ sudo grep -i permit /etc/ssh/sshd_config\n     PermitEmptyPasswords no\n\n"
    + 'If "PermitEmptyPasswords" is not set to "no",\nthis is a finding.'
  assert.deepEqual(splitStigText(text), [
    { type: 'p', text: 'Verify that unattended login is disabled with the following command:' },
    { type: 'code', text: '$ sudo grep -i permit /etc/ssh/sshd_config\nPermitEmptyPasswords no' },
    { type: 'p', text: 'If "PermitEmptyPasswords" is not set to "no", this is a finding.' },
  ])
  assert.deepEqual(splitStigText(''), [])
  assert.deepEqual(splitStigText('$ sudo systemctl restart ssh').map((b) => b.type), ['code'])
})

test('formatting helpers', () => {
  assert.equal(formatDate('2026-10-26T02:32:44Z'), 'Oct 26, 2026')
  assert.equal(formatDate('2026-10-26'), 'Oct 26, 2026')
  assert.equal(formatDate(null), '—')
  assert.equal(listWords(['a', 'b', 'c']), 'a, b and c')
})

// -- findings, drift and timeline helpers -------------------------------------------------------

const res = (stig_id, status, cat = 'CAT II', title = `title ${stig_id}`) => ({ stig_id, status, cat, title })
const H = (id, name, os = 'linux') => ({ id, name, os })

test('findings group by STIG ID with the hosts where each is Open; Not reviewed is kept apart', () => {
  const groups = groupFindings([
    { host: H(1, 'web-02'), results: [res('U-1', 'Open', 'CAT I'), res('U-2', 'Open'), res('U-3', 'NotAFinding')] },
    { host: H(2, 'web-01'), results: [res('U-1', 'Open', 'CAT I'), res('U-2', 'Not_Reviewed'), res('U-4', 'Not_Reviewed')] },
    { host: H(3, 'dc-01', 'windows'), results: [res('W-1', 'Open', 'CAT III')] },
  ])
  assert.deepEqual(groups.map((g) => g.stig_id), ['U-1', 'U-2', 'W-1'], 'CAT I first; rules never Open are left out')
  assert.deepEqual(groups[0].open.map((h) => h.name), ['web-01', 'web-02'])
  assert.deepEqual(groups[1].open.map((h) => h.name), ['web-02'])
  assert.deepEqual(groups[1].unchecked.map((h) => h.name), ['web-01'], 'Not reviewed is not counted as open or fixed')
  assert.equal(groups[2].os, 'windows')
  assert.deepEqual(filterFindings(groups, { cat: 'CAT I' }).map((g) => g.stig_id), ['U-1'])
  assert.deepEqual(filterFindings(groups, { os: 'windows' }).map((g) => g.stig_id), ['W-1'])
  assert.deepEqual(filterFindings(groups, { q: 'TITLE u-2' }).map((g) => g.stig_id), ['U-2'])
  assert.equal(filterFindings(groups, {}).length, 3)
})

test('weeks start on Monday (UTC)', () => {
  assert.equal(weekStart('2026-10-26T02:32:44Z'), '2026-10-26')
  assert.equal(weekStart('2026-11-01'), '2026-10-26') // a Sunday belongs to the week before
  assert.equal(weekStart('2026-11-02T00:00:00Z'), '2026-11-02')
  assert.equal(weekStart('nonsense'), '')
})

test('fleet timeline: scans per week, net change per host, alerts matched by scan', () => {
  const trend = [
    { week: '2026-10-19', hosts: 2, open: { 'CAT I': 3, 'CAT II': 10, 'CAT III': 1 } },
    { week: '2026-10-26', hosts: 2, open: { 'CAT I': 5, 'CAT II': 8, 'CAT III': 1 } },
    { week: '2026-11-02', hosts: 2, open: { 'CAT I': 4, 'CAT II': 8, 'CAT III': 1 } },
  ]
  const open = (a, b, c) => ({ 'CAT I': a, 'CAT II': b, 'CAT III': c })
  const hostScans = [
    { host: H(1, 'web-01'), scans: [
      { id: 12, collected_at: '2026-10-26T02:00:00Z', open: open(3, 5, 0) },
      { id: 11, collected_at: '2026-10-19T02:00:00Z', open: open(1, 5, 0) },
    ] },
    { host: H(2, 'db-01'), scans: [{ id: 21, collected_at: '2026-10-19T03:00:00Z', open: open(2, 5, 1) }] },
  ]
  const alerts = [{ id: 1, scan_id: 12, host_id: 1, host_name: 'web-01', stig_id: 'U-1', created_at: '2099-01-01T00:00:00Z' }]
  const weeks = buildTimeline(trend, hostScans, alerts)
  assert.deepEqual(weeks.map((w) => w.n), [1, 2, 3])
  assert.equal(weeks[0].change, null)
  assert.deepEqual(weeks[1].change, { 'CAT I': 2, 'CAT II': -2, 'CAT III': 0 })
  assert.deepEqual(weeks[0].scans.map((s) => s.host_name), ['db-01', 'web-01'])
  assert.equal(weeks[0].scans[0].first, true)
  assert.deepEqual(weeks[1].scans[0].change, { 'CAT I': 2, 'CAT II': 0, 'CAT III': 0 })
  assert.equal(weeks[1].alerts.length, 1, 'the alert lands in the week its scan was collected')
  assert.equal(weeks[0].alerts.length, 0)
  assert.equal(weeks[2].scans.length, 0)
  assert.equal(defaultWeek(weeks), '2026-10-26', 'latest week with a CAT I regression')
  assert.equal(defaultWeek(buildTimeline(trend, hostScans, [])), '2026-11-02')
  assert.equal(defaultWeek([]), null)
})

test('merged drift keeps lost visibility apart from fixed and leaves CAT I out of newly open', () => {
  const scan = (id, host_id, host_name) => ({ id, host_id, host_name })
  const item = (stig_id, cat, from, to) => ({ stig_id, cat, from, to })
  const merged = mergeDrift([
    { scan: scan(5, 1, 'web-01'), drift: {
      first_scan: false, regressed: [item('U-1', 'CAT I', 'NotAFinding', 'Open')],
      newly_open: [item('U-2', 'CAT I', 'Not_Reviewed', 'Open'), item('U-3', 'CAT II', 'Not_Reviewed', 'Open')],
      newly_visible_cat1: [item('U-2', 'CAT I', 'Not_Reviewed', 'Open')],
      lost_visibility: [item('U-4', 'CAT II', 'Open', 'Not_Reviewed')], fixed: [item('U-5', 'CAT III', 'Open', 'NotAFinding')],
    } },
    { scan: scan(6, 2, 'db-01'), drift: { first_scan: true } },
  ])
  assert.equal(merged.compared, 1)
  assert.deepEqual(merged.first.map((s) => s.host_name), ['db-01'])
  assert.deepEqual(merged.newly_open.map((r) => r.stig_id), ['U-3'])
  assert.deepEqual(merged.lost_visibility.map((r) => r.stig_id), ['U-4'])
  assert.ok(!merged.fixed.some((r) => r.stig_id === 'U-4'), 'lost visibility is never listed as fixed')
  assert.equal(merged.regressed[0].host_name, 'web-01')
  assert.equal(alertFrom({ from_status: 'NotAFinding' }), 'NotAFinding')
  assert.equal(alertFrom({ message: 'went from NotAFinding to Open' }), '', 'the message is not parsed')
})

test('async state never shows the data of a previous loader', () => {
  const hostA = () => {}
  const hostB = () => {}
  const stateA = { owner: hostA, loading: false, error: null, data: { host: 'A' } }
  assert.deepEqual(asyncView(stateA, hostA).data, { host: 'A' })
  assert.deepEqual(asyncView(stateA, hostB), { loading: true, error: null, data: null })
})

test('a 2xx response that is not JSON raises ApiError, not a SyntaxError', async () => {
  await assert.rejects(parseJsonBody(new Response('<html>proxy error</html>', { status: 200 })), (err) => {
    assert.ok(err instanceof ApiError)
    assert.equal(err.message, 'Unexpected response from the API')
    assert.equal(err.status, 200)
    return true
  })
  assert.deepEqual(await parseJsonBody(new Response('{"ok":true}', { status: 200 })), { ok: true })
})

test('URL filters read through allow-lists and keep unrelated parameters', () => {
  const spec = {
    os: { param: 'os', default: '', allow: ['linux', 'windows'] },
    q: { param: 'q', default: '', max: 5, search: true },
    cat1: { param: 'cat1', default: false, flag: true },
    sort: { param: 'sort', default: 'risk', allow: ['risk', 'name'], view: true },
  }
  const read = (qs) => parseFilters(spec, new URLSearchParams(qs))
  assert.deepEqual(read('os=windows&q=abcdefgh&cat1=1&sort=name'), { os: 'windows', q: 'abcde', cat1: true, sort: 'name' })
  assert.deepEqual(read('os=plan9&cat1=yes&sort=<script>'), { os: '', q: '', cat1: false, sort: 'risk' })
  const next = applyFilters(spec, new URLSearchParams('scan=7&os=linux&sort=name'), { os: '', q: 'x', cat1: true, sort: 'risk' })
  assert.equal(next.toString(), 'scan=7&q=x&cat1=1', 'defaults leave the URL, other parameters stay')
})

test('syntax highlighting tokenises into plain data and never changes the text', () => {
  const yaml = '# Review before applying\n- name: Set <b>x</b>\n  ansible.builtin.lineinfile:\n    line: "PermitRootLogin no"\n    hosts: "{{ stigwatch_target }}"\n    become: true\n'
  const lines = highlight(yaml, 'yaml')
  assert.equal(lines.map((l) => l.map((t) => t.text).join('')).join('\n') + '\n', yaml)
  assert.equal(lines[0][0].type, 'comment')
  assert.ok(lines[2].some((t) => t.type === 'key' && t.text === 'ansible.builtin.lineinfile'))
  assert.ok(lines[4].some((t) => t.type === 'template' && t.text === '{{ stigwatch_target }}'))
  assert.ok(lines[1].some((t) => t.text.includes('<b>')), 'markup in file text stays text')

  const ps = '<#\n.SYNOPSIS\n  hello <script>\n#>\nparam([switch]$Apply)\nif (-not $Apply) { Write-Output \'DRY RUN\' } # note\n$x = @\'\nraw </script>\n\'@\n'
  const p = highlight(ps, 'powershell')
  assert.equal(p.map((l) => l.map((t) => t.text).join('')).join('\n') + '\n', ps)
  assert.ok(p[0].every((t) => t.type === 'comment') && p[2].every((t) => t.type === 'comment'), 'block comment spans lines')
  const flat = p[5]
  assert.ok(flat.some((t) => t.type === 'keyword' && t.text === 'if'))
  assert.ok(flat.some((t) => t.type === 'param' && t.text === '-not'))
  assert.ok(flat.some((t) => t.type === 'variable' && t.text === '$Apply'))
  assert.ok(flat.some((t) => t.type === 'cmdlet' && t.text === 'Write-Output'))
  assert.ok(flat.some((t) => t.type === 'string' && t.text === "'DRY RUN'"))
  assert.ok(flat.some((t) => t.type === 'comment' && t.text === '# note'))
  assert.ok(p[7].every((t) => t.type === 'string'), 'here-string body stays a string')
  assert.deepEqual(highlight('', 'yaml'), [])
  assert.equal(highlight('a\nb', 'other').length, 2)
})

test('mapLimit keeps order and honours the concurrency limit', async () => {
  let running = 0
  let peak = 0
  const out = await mapLimit([1, 2, 3, 4, 5, 6], 2, async (n) => {
    running += 1
    peak = Math.max(peak, running)
    await new Promise((r) => setTimeout(r, 5))
    running -= 1
    return n * 2
  })
  assert.deepEqual(out, [2, 4, 6, 8, 10, 12])
  assert.equal(peak, 2)
  assert.deepEqual(await mapLimit([], 3, async (n) => n), [])
})

test('write errors are explained for the cases an admin can hit', () => {
  const e = (status, message = 'm') => new ApiError(message, status)
  assert.match(writeErrorMessage(e(403)), /read-only/)
  assert.match(writeErrorMessage(e(503)), /not ready/)
  // A platform 413 (plain text, not the API's JSON) must not leak its raw "413 ..." text.
  const platform = new ApiError('413 Request Entity Too Large', 413)
  assert.doesNotMatch(writeErrorMessage(platform), /^413|Request Entity/)
  assert.match(writeErrorMessage(platform), /larger than the server accepts/)
  assert.match(writeErrorMessage(new ApiError('File too large (max 4 MB)', 413, null, true)), /^File too large \(max 4 MB\)/)
  assert.match(writeErrorMessage(e(502)), /did not answer/)
  assert.match(writeErrorMessage(e(504)), /did not answer/)
  assert.match(writeErrorMessage(e(400, 'File is not valid JSON')), /not valid JSON/)
  assert.match(writeErrorMessage(e(0)), /Cannot reach/)
  assert.equal(formatBytes(2048), '2.0 KB')
  assert.equal(formatBytes(12), '12 B')
})

test('drift timeline: a week decrease that includes lost visibility is neutral, per week and per host', () => {
  const trend = [
    { week: '2026-10-26', hosts: 1, open: { 'CAT I': 0, 'CAT II': 5, 'CAT III': 2 }, lost_visibility: { 'CAT I': 0, 'CAT II': 0, 'CAT III': 0 } },
    { week: '2026-11-02', hosts: 1, open: { 'CAT I': 0, 'CAT II': 2, 'CAT III': 1 }, lost_visibility: { 'CAT I': 0, 'CAT II': 2, 'CAT III': 0 } },
  ]
  const weeks = buildTimeline(trend, [], [])
  assert.deepEqual(weeks[1].lost, { 'CAT I': 0, 'CAT II': 2, 'CAT III': 0 })
  const lost = weeks[1].lost['CAT II']
  const shown = describeDelta(weeks[1].change['CAT II'], lost)
  assert.equal(shown.tone, 'neutral')
  assert.match(shown.text, /2 lost visibility/)
  assert.equal(describeDelta(weeks[1].change['CAT III'], weeks[1].lost['CAT III']).tone, 'good', 'a real decrease stays good')
  // Trend rows from an older API without lost_visibility count as zero.
  assert.deepEqual(buildTimeline([{ week: '2026-11-02', open: {} }], [], [])[0].lost, { 'CAT I': 0, 'CAT II': 0, 'CAT III': 0 })
})

test('lostByScan counts lost-visibility rules per scan and CAT for the per-host net change', () => {
  const merged = { lost_visibility: [
    { scan_id: 7, cat: 'CAT II', stig_id: 'A' }, { scan_id: 7, cat: 'CAT II', stig_id: 'B' }, { scan_id: 8, cat: 'CAT I', stig_id: 'C' },
  ] }
  const m = lostByScan(merged)
  assert.deepEqual(m.get(7), { 'CAT I': 0, 'CAT II': 2, 'CAT III': 0 })
  assert.equal(m.get(8)['CAT I'], 1)
  assert.equal(m.get(9), undefined)
  assert.equal(describeDelta(-2, m.get(7)['CAT II']).tone, 'neutral')
  assert.equal(lostByScan(null).size, 0)
})
