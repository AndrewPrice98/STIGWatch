import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Icon, PageHead, usePageTitle } from '../components/ui.jsx'

// Pages that the next dashboard release fills in. Each says what it will show and links to
// where the same information already lives, so no navigation item is a dead end.
const PAGES = {
  findings: {
    title: 'Findings',
    eyebrow: 'Across the fleet',
    about: 'Every open finding on every host in one list, filterable by CAT, rule and host.',
    now: <>Each host lists its findings today: open a host from <Link to="/hosts">Hosts</Link> and filter its results by status and CAT.</>,
  },
  drift: {
    title: 'Drift',
    eyebrow: 'Change between scans',
    about: 'What changed fleet-wide since the previous scan: regressions, fixes, rules that lost visibility and CAT I findings that became visible.',
    now: <>Every host page has a drift panel for any of its scans. The CAT I regressions of week 6 are summarised on the <Link to="/">Fleet</Link> page.</>,
  },
  remediation: {
    title: 'Remediation',
    eyebrow: 'Generated for review',
    about: 'Ansible playbooks (Ubuntu) and PowerShell scripts (Windows) for open findings. STIGWatch never connects to hosts or applies changes; review before applying and test on a non-production host.',
    now: <>Each host page offers its remediation file for download under Exports.</>,
  },
  reports: {
    title: 'Reports',
    eyebrow: 'Exports',
    about: 'Fleet reports and STIG Viewer checklists (.ckl and .cklb) for every scan.',
    now: <>The fleet report is available now; checklists are on each host page.</>,
    links: [[api.fleetHtmlUrl(), 'Fleet report (HTML)'], [api.fleetCsvUrl(), 'Fleet summary (CSV)']],
  },
  benchmarks: {
    title: 'Benchmarks',
    eyebrow: 'DISA STIG catalogs',
    about: 'The DISA STIG releases STIGWatch checks against, and which rules are automated or left for manual review.',
    now: <>Each result names its benchmark release; open a host from <Link to="/hosts">Hosts</Link> to see it.</>,
  },
}

export default function Placeholder({ page }) {
  const p = PAGES[page]
  usePageTitle(p.title)
  return (
    <div className="page">
      <PageHead eyebrow={p.eyebrow} title={p.title}>
        <p className="lede">{p.about}</p>
      </PageHead>
      <section className="card placeholder" aria-labelledby="ph-title">
        <h2 id="ph-title"><Icon name="info" size={18} /> This view arrives in the next release</h2>
        <p>{p.now}</p>
        {p.links && (
          <ul className="link-list">
            {p.links.map(([href, label]) => (
              <li key={href}><a className="btn secondary small" href={href} download><Icon name="download" size={15} />{label}</a></li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
