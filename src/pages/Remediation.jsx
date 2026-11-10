import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { NoData } from '../components/admin.jsx'
import { CodeView, CopyButton } from '../components/code.jsx'
import { OsTag } from '../components/hosts.jsx'
import {
  About, Empty, ErrorState, Icon, Loading, Notice, PageHead, Panel, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { scannedHosts } from '../data.js'
import { REVIEW_HEADER, plural, remediationKind, sortHostsByRisk } from '../lib.js'

function ReviewNotice() {
  return (
    <Notice icon="alert" tone="warn" title={REVIEW_HEADER}>
      <p>
        STIGWatch never connects to a host and never applies a change. These files are generated from a host&apos;s
        open findings so that a person can read them, test them and run them. Treat them as a draft: a hardening
        setting that is right for the STIG can still break a service you depend on.
      </p>
    </Notice>
  )
}

function Switches() {
  return (
    <Panel id="switches" title="How the files are made safe to review">
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
    </Panel>
  )
}

function Preview({ host }) {
  const kind = remediationKind(host.os)
  const { data, error, loading, reload } = useAsync(() => api.remediationText(host.id), [host.id])
  const open = host.open || {}
  const total = (open['CAT I'] || 0) + (open['CAT II'] || 0) + (open['CAT III'] || 0)
  return (
    <Panel id="preview" flush
      title={`${host.name}: ${kind.label}`}
      desc={`Generated from ${plural(total, 'open finding')} in the latest scan${open['CAT I'] ? ` (${open['CAT I']} CAT I)` : ''}. ${host.os === 'windows' ? 'Dry run unless -Apply is given.' : 'Run it with --check --diff first.'}`}
      actions={(
        <div className="exports" role="group" aria-label="Remediation file">
          {data && <CopyButton text={data} label="Copy file" />}
          <a className="btn primary" href={api.remediationUrl(host.id)} download>
            <Icon name="download" />Download {kind.ext}
          </a>
        </div>
      )}>
      {loading && !data && <Loading label="Generating the file…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <CodeView text={data} lang={kind.lang} label={`${kind.label} for ${host.name}`} />
      )}
    </Panel>
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
      <PageHead title="Remediation" sub="Generated for review: an Ansible playbook for Ubuntu or a PowerShell script for Windows.">
        <About>
          <p>
            Pick a host to preview the file STIGWatch generated from its open findings, then download it. Nothing here
            is ever applied by STIGWatch.
          </p>
        </About>
      </PageHead>

      <ReviewNotice />

      {loading && !data && <Loading label="Loading hosts…" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && <NoData onChanged={reload} />}
      {data && data.length > 0 && !hosts.length && <Empty>No host has been scanned yet, so there is nothing to generate. <Link to="/hosts">Hosts</Link></Empty>}
      {host && (
        <>
          <form className="toolbar" aria-label="Choose a host" onSubmit={(e) => e.preventDefault()}>
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
            <span className="toolbar-text"><OsTag os={host.os} /></span>
            <Link className="btn ghost" to={`/hosts/${host.id}`}>Open the host <Icon name="arrow" /></Link>
          </form>
          <Preview key={host.id} host={host} />
        </>
      )}
      <Switches />
    </div>
  )
}
