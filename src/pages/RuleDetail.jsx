import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { formatDate, formatDateTime, formatObserved, plural, ranUnprivileged, splitStigText } from '../lib.js'
import {
  CatBadge, ErrorState, FormMessage, Icon, Loading, PageHead, StatusChip, useAsync, usePageTitle, useSession,
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
              <StatusChip status={h.status} small />
              {changed && <span className="tag change">changed</span>}
              {i === 0 && <span className="tag">latest</span>}
            </span>
            <span className="hist-rel muted small">{h.benchmark_release}</span>
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
        {comment?.updated_at && <p className="muted small">Updated {formatDateTime(comment.updated_at)}</p>}
        <p className="muted small read-only-note">
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
      <label className="field">
        <span>Comment <span className="muted small">(kept with this host and rule across scans)</span></span>
        <textarea rows={4} maxLength={5000} value={text} onChange={(e) => { setText(e.target.value); setMessage(null) }}
          placeholder="For example: risk accepted until the change window, ticket CHG-1234." />
      </label>
      <div className="form-row">
        <button type="submit" className="btn primary small" aria-disabled={disabled ? 'true' : undefined}>
          {busy ? 'Saving…' : 'Save comment'}
        </button>
        <FormMessage message={message || (unchanged ? null : { tone: '', text: 'Unsaved changes' })} />
      </div>
      {comment?.updated_at && <p className="muted small">Last saved {formatDateTime(comment.updated_at)}</p>}
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
      <PageHead back={back} eyebrow={`${host.name} · ${rule?.group_id || 'rule'}`} title={stigId}>
        {rule && <p className="lede rule-lede">{rule.title}</p>}
        <div className="host-meta">
          {rule && <CatBadge cat={rule.cat} withSeverity />}
          {latest && <StatusChip status={latest.status} />}
          {latest && <span className="muted small">in the scan of {formatDate(latest.collected_at)}</span>}
        </div>
      </PageHead>

      <div className="detail-grid">
        <div className="detail-main">
          <section className={`card result-card st-${latest?.status || ''}`} aria-labelledby="result-title">
            <h2 id="result-title">Latest result</h2>
            {latest ? <p className="reason-full">{latest.reason}</p> : <p className="muted">This host has never been scanned for this rule.</p>}
            {privilege && (
              <p className="callout warn small">
                <Icon name="lock" size={15} /> The collector ran without{' '}
                {host.os === 'windows' ? 'Administrator rights' : 'root'}, so rules that need privileged facts could not be decided; the reason above
                says what this rule was missing. Run it {host.os === 'windows' ? 'from an elevated PowerShell' : 'with sudo'} for full coverage.
                Not reviewed is never counted as compliant.
              </p>
            )}
          </section>

          <section className="card" aria-labelledby="evidence-title">
            <h2 id="evidence-title">Evidence: observed vs expected</h2>
            <p className="muted small">What the read-only collector gathered for the latest scan, and what the check required.</p>
            <Evidence evidence={detail.evidence} status={latest?.status} />
          </section>

          {rule ? (
            <>
              <section className="card" aria-labelledby="check-title">
                <h2 id="check-title">Check text</h2>
                <StigText text={rule.check_text} />
              </section>
              <section className="card" aria-labelledby="fix-title">
                <h2 id="fix-title">Fix text</h2>
                <StigText text={rule.fix_text} />
                <p className="muted small">STIGWatch never applies fixes. Generated remediation is for review; test on a non-production host first.</p>
              </section>
              {rule.discussion && (
                <section className="card" aria-labelledby="disc-title">
                  <h2 id="disc-title">Discussion</h2>
                  <StigText text={rule.discussion} />
                </section>
              )}
            </>
          ) : (
            <section className="card"><p className="muted">This rule is not in the host&apos;s current benchmark release; only its history is shown.</p></section>
          )}
        </div>

        <aside className="detail-side">
          <section className="card" aria-labelledby="id-title">
            <h2 id="id-title">Identifiers</h2>
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
          </section>

          <section className="card" aria-labelledby="comment-title">
            <h2 id="comment-title">Assessor comment</h2>
            <Comment key={`${host.id}:${stigId}`} hostId={host.id} stigId={stigId} comment={currentComment} onSaved={setComment} />
          </section>

          <section className="card" aria-labelledby="history-title">
            <h2 id="history-title">Result history</h2>
            <p className="muted small">{plural(detail.history.length, 'scan')}, newest first.</p>
            <History history={detail.history} />
            <Link className="btn ghost small" to={`/hosts/${host.id}#drift`}>Host drift <Icon name="arrow" size={15} /></Link>
          </section>
        </aside>
      </div>
    </div>
  )
}
