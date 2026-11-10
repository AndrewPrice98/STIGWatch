import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DISCLAIMER, catBreakdown, compliancePct, describeDelta, environments, filterHosts, filterResults,
  formatDate, formatPct, hostsAtRisk, listWords, niceMax, privilegeGaps, regressionStory, sortHosts,
  sortHostsByRisk, sortResults, splitStigText, ticks, weekDelta, weekOf,
} from './lib.js'

const host = (name, open, extra = {}) => ({
  name, os: 'linux', environment: 'prod', owner: 'Ops', tags: [], compliance: 99,
  open: { 'CAT I': open[0], 'CAT II': open[1], 'CAT III': open[2] }, ...extra,
})

test('disclaimer is the exact required text', () => {
  assert.equal(DISCLAIMER,
    "STIGWatch is an independent tool. It is not a DISA product and does not replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")
})

test('compliance is NotAFinding / (Open + NotAFinding); Not reviewed and N/A excluded', () => {
  assert.equal(compliancePct({ Open: 46, NotAFinding: 2389, Not_Applicable: 299, Not_Reviewed: 456 }), 98.1)
  assert.equal(compliancePct({ Open: 0, NotAFinding: 10, Not_Reviewed: 500 }), 100)
  assert.equal(compliancePct({ Open: 1, NotAFinding: 0 }), 0)
  assert.equal(compliancePct({ Not_Reviewed: 3, Not_Applicable: 2 }), null)
  assert.equal(compliancePct(undefined), null)
  assert.equal(formatPct(null), '—')
  assert.equal(formatPct(96.8), '96.8%')
})

test('week delta compares the last two trend points per CAT', () => {
  const trend = [
    { week: '2026-10-19', open: { 'CAT I': 3, 'CAT II': 80, 'CAT III': 22 } },
    { week: '2026-10-26', open: { 'CAT I': 7, 'CAT II': 62, 'CAT III': 16 } },
    { week: '2026-11-02', open: { 'CAT I': 7, 'CAT II': 44, 'CAT III': 10 } },
  ]
  assert.deepEqual(weekDelta(trend, 'CAT I'), { current: 7, previous: 7, change: 0, since: '2026-10-26' })
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

test('privilege gaps: Not reviewed because the collector lacked root or Administrator', () => {
  const nr = (reason, cat = 'CAT II') => ({ status: 'Not_Reviewed', cat, reason })
  const rows = [
    nr('Not reviewed: audit_rules could not be read: requires root (run the collector with sudo)'),
    nr('Not reviewed: shadow could not be read: awk: cannot open /etc/shadow (Permission denied)', 'CAT I'),
    nr('Manual review: STIGWatch has no automated check for this rule.'),
    { status: 'Open', cat: 'CAT I', reason: 'Permission denied in the observed value' },
  ]
  assert.deepEqual(privilegeGaps(rows), { count: 2, cat1: 1, unprivileged: false })
  const many = Array.from({ length: 5 }, () => rows[0])
  assert.equal(privilegeGaps(many).unprivileged, true)
})

test('regression story picks the week with the most CAT I regressions', () => {
  const trend = ['2026-09-21', '2026-09-28', '2026-10-05', '2026-10-12', '2026-10-19', '2026-10-26', '2026-11-02', '2026-11-09']
    .map((week) => ({ week, open: {} }))
  const alert = (host_id, host_name, stig_id, created_at) => ({ host_id, host_name, stig_id, created_at, cat: 'CAT I', kind: 'cat1_regression' })
  const alerts = [
    alert(11, 'file-01', 'WN22-SO-000210', '2026-10-26T03:08:56Z'),
    alert(11, 'file-01', 'WN22-AC-000090', '2026-10-26T03:08:56Z'),
    alert(1, 'web-01', 'UBTU-22-255040', '2026-10-26T02:32:44Z'),
    alert(1, 'web-01', 'UBTU-22-255025', '2026-10-26T02:32:44Z'),
    alert(2, 'web-02', 'UBTU-22-255025', '2026-11-02T02:32:44Z'),
  ]
  const story = regressionStory(alerts, trend)
  assert.equal(story.day, '2026-10-26')
  assert.equal(story.week, 6)
  assert.deepEqual(story.hosts.map((h) => h.name), ['file-01', 'web-01'])
  assert.deepEqual(story.rules.map((r) => r.stig_id), ['WN22-AC-000090', 'WN22-SO-000210', 'UBTU-22-255025', 'UBTU-22-255040'])
  assert.equal(story.total, 5)
  assert.equal(regressionStory([], trend), null)
  assert.equal(weekOf('2026-09-20', trend.map((t) => t.week)), null)
})

test('chart scales round up to readable maxima', () => {
  assert.equal(niceMax(194), 200)
  assert.equal(niceMax(65), 100)
  assert.equal(niceMax(7), 10)
  assert.equal(niceMax(0), 1)
  assert.equal(niceMax(2.2), 2.5)
  assert.deepEqual(ticks(200, 4), [0, 50, 100, 150, 200])
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
