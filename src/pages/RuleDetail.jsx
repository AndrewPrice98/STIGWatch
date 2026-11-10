import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { DemoWriteNotice } from '../components/admin.jsx'
import { formatDate, formatDateTime, formatObserved, plural, ranUnprivileged, splitStigText } from '../lib.js'
import {
  CatBadge, ErrorState, FormMessage, Icon, Loading, PageHead, Panel, StatusChip, useAsync, usePageTitle, useSession,
} from '../components/ui.jsx'

function StigText({ text }) {
  const blocks = splitStigText(text)
  if (!blocks.length) return <p className="muted">Not provided in the benchmark.</p>
  return (
    <div className="stig-text">
      {blocks.map((b, i) => (b.type === 'code'
        ? <pre key={i} className="code-block" tabIndex={0}><code>{b.text}</code></pre>
        : <p key={i}>{b.text}</p>))}
    </div>
  )
}

function Evidence({ evidence, status }) {
  if (!evidence.length) {
    return (
      <p className="muted">
        {status === 'Not_Reviewed'
          ? 'No facts were available to decide this rule; the reason above says why.'
          : 'This result records no evidence items.'}
      </p>
    )
  }
  return (
    <ul className="evidence-list">
      {evidence.map((e, i) => {
        const context = e.expected === '(context)'
        const observed = formatObserved(e.observed)
        return (
          <li key={i} className={`evidence-item${context ? ' context' : ''}`}>
            <p className="ev-path"><code>{e.path || e.fact}</code>{context && <span className="tag">supporting context</span>}</p>
            <dl className="ev-grid">
              <div>
                <dt>Observed</dt>
                <dd>{observed.includes('\n') || observed.length > 60
                  ? <pre className="code-block small" tabIndex={0}><code>{observed}</code></pre>
                  : <code className="ev-value">{observed}</code>}</dd>
              </div>
              {!context && (
                <div>
                  <dt>Expected</dt>
                  <dd><code className="ev-value expected">{formatObserved(e.expected)}</code></dd>
                </div>
              )}
              {e.command && (
                <div className="ev-cmd">
                  <dt><Icon name="terminal" size={14} /> Collector command</dt>
                  <dd><code>{e.command}</code></dd>
                </div>
              )}
            </dl>
          </li>
        )
      })}
    </ul>
  )
}

function History({ history }) {
  return (
    <ol className="history">
      {[...history].reverse().map((h, i, arr) => {
        const prev = arr[i + 1]
        const changed = prev && prev.status !== h.status
        return (
          <li key={h.scan_id} className={changed ? 'changed' : ''}>
            <span className="hist-date">{formatDate(h.collected_at)}</span>
            <span className="hist-status">
              <StatusChip status={h.status} />
              {changed && <span className="tag change">changed</span>}
              {i === 0 && <span className="tag">latest</span>}
            </span>
            <span className="hist-rel muted">{h.benchmark_release}</span>
          </li>
        )
      })}
    </ol>
  )
}

/** Keyed by host and rule by the caller, so a draft or a pending save can never reach another rule. */
function Comment({ hostId, stigId, comment, onSaved }) {
  const { guest, authConfigured, signIn } = useSession()
  const saved = comment?.text || ''
  const [text, setText] = useState(saved)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState(null)
  useEffect(() => { setText(saved) }, [saved])

  if (guest) {
    return (
      <>
        {saved
          ? <blockquote className="comment-text">{saved}</blockquote>
          : <p className="muted">No assessor comment for this rule on this host.</p>}
        {comment?.updated_at && <p className="muted">Updated {formatDateTime(comment.updated_at)}</p>}
        <p className="muted read-only-note">
          <Icon name="lock" size={13} /> Read-only.{' '}
          {authConfigured && <button type="button" className="link" onClick={signIn}>Sign in as admin to edit</button>}
        </p>
      </>
    )
  }

  const unchanged = text === saved
  const disabled = busy || unchanged
  async function save(e) {
    e.preventDefault()
    if (disabled) return
    setBusy(true)
    setMessage(null)
    try {
      const res = await api.saveComment(hostId, stigId, text)
      onSaved(res.comment)
      setMessage({ tone: 'good', text: 'Saved.' })
    } catch (err) {
      setMessage({ tone: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }
  return (
    <form onSubmit={save} className="comment-form">
      <DemoWriteNotice />
      <label className="field">
        <span>Comment <span className="muted">(kept with this host and rule across scans)</span></span>
        <textarea rows={4} maxLength={5000} value={text} onChange={(e) => { setText(e.target.value); setMessage(null) }}
          placeholder="For example: risk accepted until the change window, ticket CHG-1234." />
      </label>
      <div className="form-row">
        <button type="submit" className="btn primary" aria-disabled={disabled ? 'true' : undefined}>
          {busy ? 'Saving…' : 'Save comment'}
        </button>
        <FormMessage message={message || (unchanged ? null : { tone: '', text: 'Unsaved changes' })} />
      </div>
      {comment?.updated_at && <p className="muted">Last saved {formatDateTime(comment.updated_at)}</p>}
    </form>
  )
}

/** Keyed by host and rule: moving to another rule starts from a clean slate. */
export default function RuleDetailRoute() {
  const { hostId, stigId } = useParams()
  return <RuleDetail key={`${hostId}:${stigId}`} hostId={hostId} stigId={stigId} />
}

function RuleDetail({ hostId, stigId }) {
  const { data, error, loading, reload } = useAsync(
    () => Promise.all([api.rule(hostId, stigId), api.host(hostId)]).then(([rule, host]) => ({ rule, host })),
    [hostId, stigId],
  )
  const [comment, setComment] = useState(undefined)
  usePageTitle(data ? `${stigId} on ${data.host.name}` : stigId)

  const back = { to: `/hosts/${hostId}`, label: data?.host?.name ? `Back to ${data.host.name}` : 'Back to the host' }
  if (loading && !data) return <div className="page"><Loading label="Loading the rule…" /></div>
  if (error) {
    return (
      <div className="page">
        <PageHead back={back} title={error.status === 404 ? 'Rule not found' : stigId} />
        <ErrorState error={error} onRetry={error.status === 404 ? undefined : reload} />
      </div>
    )
  }
  const { rule: detail, host } = data
  const rule = detail.rule
  const latest = detail.history.at(-1)
  const currentComment = comment === undefined ? detail.comment : comment
  // Only when the rule's latest result is from the host's latest scan and that scan says it ran unprivileged.
  const privilege = latest && latest.status === 'Not_Reviewed' && host.latest_scan?.id === latest.scan_id
    && ranUnprivileged(host.latest_scan)

  return (
    <div className="page">
      <PageHead back={back} title={<span className="mono-title">{stigId}</span>} sub={rule?.title}>
        <div className="host-meta">
          <span>{host.name}</span>
          {rule && <CatBadge cat={rule.cat} withSeverity />}
          {latest && <StatusChip status={latest.status} />}
          {latest && <span>in the scan of {formatDate(latest.collected_at)}</span>}
        </div>
      </PageHead>

      <div className="detail-grid">
        <div className="detail-main">
          <Panel id="result" title="Latest result">
            {latest ? <p className="reason-full">{latest.reason}</p> : <p className="muted">This host has never been scanned for this rule.</p>}
            {privilege && (
              <p className="callout">
                <Icon name="lock" size={15} /> The collector ran without{' '}
                {host.os === 'windows' ? 'Administrator rights' : 'root'}, so rules that need privileged facts could not be decided; the reason above
                says what this rule was missing. Run it {host.os === 'windows' ? 'from an elevated PowerShell' : 'with sudo'} for full coverage.
                Not reviewed is never counted as compliant.
              </p>
            )}
          </Panel>

          <Panel id="evidence" title="Evidence: observed vs expected"
            desc="What the read-only collector gathered for the latest scan, and what the check required.">
            <Evidence evidence={detail.evidence} status={latest?.status} />
          </Panel>

          {rule ? (
            <>
              <Panel id="check" title="Check text">
                <StigText text={rule.check_text} />
              </Panel>
              <Panel id="fix" title="Fix text">
                <StigText text={rule.fix_text} />
                <p className="muted note">STIGWatch never applies fixes. Generated remediation is for review; test on a non-production host first.</p>
              </Panel>
              {rule.discussion && (
                <Panel id="disc" title="Discussion">
                  <StigText text={rule.discussion} />
                </Panel>
              )}
            </>
          ) : (
            <Panel><p className="muted">This rule is not in the host&apos;s current benchmark release; only its history is shown.</p></Panel>
          )}
        </div>

        <aside className="detail-side">
          <Panel id="id" title="Identifiers">
            {rule ? (
              <dl className="id-list">
                <div><dt>STIG ID</dt><dd className="mono">{rule.stig_id}</dd></div>
                <div><dt>Group ID</dt><dd className="mono">{rule.group_id}</dd></div>
                <div><dt>Rule ID</dt><dd className="mono">{rule.rule_id}</dd></div>
                <div><dt>Severity</dt><dd>{rule.cat} ({rule.severity})</dd></div>
                <div><dt>CCI</dt><dd className="mono">{rule.ccis.join(', ') || '—'}</dd></div>
                {latest && <div><dt>Benchmark</dt><dd>{host.benchmark_id} {latest.benchmark_release}</dd></div>}
              </dl>
            ) : <p className="muted">Not in the current benchmark.</p>}
          </Panel>

          <Panel id="comment" title="Assessor comment">
            <Comment key={`${host.id}:${stigId}`} hostId={host.id} stigId={stigId} comment={currentComment} onSaved={setComment} />
          </Panel>

          <Panel id="history" title="Result history" desc={`${plural(detail.history.length, 'scan')}, newest first.`}>
            <History history={detail.history} />
            <Link className="btn ghost" to={`/hosts/${host.id}#drift`}>Host drift <Icon name="arrow" /></Link>
          </Panel>
        </aside>
      </div>
    </div>
  )
}
