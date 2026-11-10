import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import { CodeView, CopyButton } from '../components/code.jsx'
import { OsTag } from '../components/hosts.jsx'
import { Empty, ErrorState, Icon, Loading, PageHead, useAsync, usePageTitle } from '../components/ui.jsx'
import { scannedHosts } from '../data.js'
import { REVIEW_HEADER, plural, remediationKind, sortHostsByRisk } from '../lib.js'

function ReviewBanner() {
  return (
    <section className="review-banner" aria-labelledby="review-title">
      <Icon name="alert" size={22} />
      <div>
        <h2 id="review-title">{REVIEW_HEADER}</h2>
        <p>
          STIGWatch never connects to a host and never applies a change. These files are generated from a host&apos;s
          open findings so that a person can read them, test them and run them. Treat them as a draft: a hardening
          setting that is right for the STIG can still break a service you depend on.
        </p>
      </div>
    </section>
  )
}

function Switches() {
  return (
    <section className="card" aria-labelledby="switches-title">
      <h2 id="switches-title">How the files are made safe to review</h2>
      <div className="switch-grid">
        <div>
          <h3>Windows PowerShell script (.ps1)</h3>
          <dl className="switch-list">
            <div>
              <dt><code>(no switch)</code></dt>
              <dd>A <strong>dry run</strong>. The script only reports what it would change and changes nothing. This is the default.</dd>
            </div>
            <div>
              <dt><code>-Apply</code></dt>
              <dd>Really makes the changes. Needs an elevated PowerShell. Run the dry run first and read the output.</dd>
            </div>
            <div>
              <dt><code>-IncludeAccessChanges</code></dt>
              <dd>
                Settings that can change <strong>who or what may connect or sign in</strong> (SMB or LDAP signing, NTLM level,
                remote UAC filtering, WinRM, user rights) are skipped unless you add this. They can lock out an administrator,
                a service or a domain trust, so review each one first.
              </dd>
            </div>
          </dl>
        </div>
        <div>
          <h3>Ubuntu Ansible playbook (.yml)</h3>
          <dl className="switch-list">
            <div>
              <dt><code>{'{{ stigwatch_target }}'}</code></dt>
              <dd>
                The playbook has no host written into it. You must pass the host or group to change with{' '}
                <code>-e stigwatch_target=&lt;host-or-group&gt;</code>; if you do not, the play fails instead of running anywhere.
              </dd>
            </div>
            <div>
              <dt><code>--check --diff</code></dt>
              <dd>Ansible&apos;s own dry run: shows what would change without changing it. Run this first.</dd>
            </div>
            <div>
              <dt><code>--tags &lt;STIG-ID&gt;</code></dt>
              <dd>Applies only the findings you pick. Rules STIGWatch cannot fix safely are listed as manual steps at the end.</dd>
            </div>
          </dl>
        </div>
      </div>
    </section>
  )
}

function Preview({ host }) {
  const kind = remediationKind(host.os)
  const { data, error, loading, reload } = useAsync(() => api.remediationText(host.id), [host.id])
  const open = host.open || {}
  const total = (open['CAT I'] || 0) + (open['CAT II'] || 0) + (open['CAT III'] || 0)
  return (
    <section className="card" aria-labelledby="preview-title">
      <div className="card-head">
        <div>
          <h2 id="preview-title" className="wrap-anywhere">{host.name}: {kind.label}</h2>
          <p className="muted small">
            Generated from {plural(total, 'open finding')} in the latest scan
            {open['CAT I'] ? ` (${open['CAT I']} CAT I)` : ''}. {host.os === 'windows' ? 'Dry run unless -Apply is given.' : 'Run it with --check --diff first.'}
          </p>
        </div>
        <div className="exports" role="group" aria-label="Remediation file">
          <a className="btn primary small" href={api.remediationUrl(host.id)} download>
            <Icon name="download" size={15} />Download {kind.ext}
          </a>
          {data && <CopyButton text={data} label="Copy file" />}
        </div>
      </div>
      {loading && !data && <Loading label="Generating the file…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <CodeView text={data} lang={kind.lang} label={`${kind.label} for ${host.name}`} />
      )}
    </section>
  )
}

export default function Remediation() {
  usePageTitle('Remediation')
  const { data, error, loading, reload } = useAsync(() => api.hosts(), [])
  const [params, setParams] = useSearchParams()
  const hosts = useMemo(() => sortHostsByRisk(scannedHosts(data || [])), [data])
  const requested = Number(params.get('host'))
  const host = hosts.find((h) => h.id === requested) || hosts[0] || null

  return (
    <div className="page">
      <PageHead eyebrow="Generated for review" title="Remediation">
        <p className="lede">
          Pick a host to preview the Ansible playbook (Ubuntu) or PowerShell script (Windows) STIGWatch generated
          from its open findings, then download it.
        </p>
      </PageHead>

      <ReviewBanner />

      {loading && !data && <Loading label="Loading hosts…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && <NoData onChanged={reload} />}
      {data && data.length > 0 && !hosts.length && <Empty>No host has been scanned yet, so there is nothing to generate. <Link to="/hosts">Hosts</Link></Empty>}
      {host && (
        <>
          <form className="filters card" aria-label="Choose a host" onSubmit={(e) => e.preventDefault()}>
            <label className="field grow">
              <span>Host</span>
              <select value={host.id}
                onChange={(e) => setParams((p) => { const sp = new URLSearchParams(p); sp.set('host', e.target.value); return sp }, { replace: true })}>
                {hosts.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.name} · {h.os === 'windows' ? 'Windows' : 'Ubuntu'} · {plural((h.open?.['CAT I'] || 0) + (h.open?.['CAT II'] || 0) + (h.open?.['CAT III'] || 0), 'open finding')}
                  </option>
                ))}
              </select>
            </label>
            <div className="field"><span>Operating system</span><OsTag os={host.os} /></div>
            <Link className="btn ghost small" to={`/hosts/${host.id}`}>Open the host <Icon name="arrow" size={15} /></Link>
          </form>
          <Preview key={host.id} host={host} />
        </>
      )}
      <Switches />
    </div>
  )
}
