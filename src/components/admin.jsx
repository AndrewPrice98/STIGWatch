import { useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { COLLECTOR_STEPS, OS_LABEL, formatBytes, formatPct, plural, writeErrorMessage } from '../lib.js'
import { Icon, useSession } from './ui.jsx'

const HOST_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/

export const DEMO_WRITE_NOTICE = 'Demo: changes you make are visible to other visitors until the demo resets.'

/** Persistent notice beside every admin control while the hosted demo is running and you are not a guest. */
export function DemoWriteNotice() {
  const { demo, guest } = useSession()
  if (!demo || guest) return null
  return <p className="notice-inline small" role="note"><Icon name="info" size={13} /> {DEMO_WRITE_NOTICE}</p>
}

/** Upload one collector JSON file. For writers only; the server enforces that with a 403. */
export function UploadScan({ hostId, onDone, heading = 'Upload a scan' }) {
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(null)
  const input = useRef(null)
  const id = useId()
  const { maxUploadMb } = useSession()

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    if (!file) { setError('Choose a collector output file (.json) first.'); return }
    if (maxUploadMb && file.size > maxUploadMb * 1024 * 1024) {
      setError(`${file.name} is ${formatBytes(file.size)}, over this server's ${maxUploadMb} MB upload limit. Collector output is normally well under a megabyte; check it is the right file.`)
      return
    }
    setBusy(true)
    setError('')
    setDone(null)
    try {
      const res = hostId ? await api.uploadHostScan(hostId, file) : await api.uploadScan(file)
      setDone(res)
      setFile(null)
      if (input.current) input.current.value = ''
      onDone?.(res)
    } catch (err) {
      setError(writeErrorMessage(err, 'The upload'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="admin-form" onSubmit={submit} aria-labelledby={`${id}-h`}>
      <h3 id={`${id}-h`}><Icon name="upload" size={16} /> {heading}</h3>
      <p className="muted small">
        Choose the JSON file a STIGWatch collector wrote. {hostId
          ? 'It must come from this host.'
          : 'The host is matched by the name inside the file, and created if it is new.'}
      </p>
      <label className="field">
        <span>Collector output (.json)</span>
        <input ref={input} type="file" accept=".json,application/json"
          onChange={(e) => { setFile(e.target.files?.[0] || null); setError(''); setDone(null) }} />
      </label>
      {file && <p className="muted small">{file.name} · {formatBytes(file.size)}</p>}
      <DemoWriteNotice />
      <div className="form-row">
        <button type="submit" className="btn primary small" aria-disabled={busy ? 'true' : undefined}>
          {busy ? 'Uploading…' : 'Upload scan'}
        </button>
      </div>
      <div aria-live="polite">
        {error && <p className="form-msg error" role="alert">{error}</p>}
        {done && (
          <p className="form-msg good">
            Stored the scan of {done.host}{done.host_created ? ' (new host)' : ''}: {formatPct(done.compliance)} compliance,{' '}
            {plural(done.open?.['CAT I'] ?? 0, 'open CAT I finding')}
            {done.alerts_raised > 0 ? `, ${plural(done.alerts_raised, 'CAT I regression alert')}` : ''}.{' '}
            <Link to={`/hosts/${done.host_id}`}>Open the host</Link>
          </p>
        )}
      </div>
    </form>
  )
}

/** Register a host before its first scan (the upload also creates hosts from the name in the file). */
export function AddHost({ onDone }) {
  const [form, setForm] = useState({ name: '', os: 'linux', environment: '', owner: '', tags: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(null)
  const id = useId()
  const set = (key) => (e) => { setForm((f) => ({ ...f, [key]: e.target.value })); setError(''); setDone(null) }

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    const name = form.name.trim()
    if (!HOST_NAME.test(name)) {
      setError('Host names are 1 to 253 characters: letters, digits, dot, dash and underscore, starting with a letter or digit.')
      return
    }
    setBusy(true)
    setError('')
    setDone(null)
    try {
      const tags = form.tags.split(',').map((t) => t.trim()).filter(Boolean)
      const host = await api.createHost({ name, os: form.os, environment: form.environment.trim(), owner: form.owner.trim(), tags })
      setDone(host)
      setForm({ name: '', os: form.os, environment: '', owner: '', tags: '' })
      onDone?.(host)
    } catch (err) {
      setError(writeErrorMessage(err, 'Adding the host'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="admin-form" onSubmit={submit} aria-labelledby={`${id}-h`}>
      <h3 id={`${id}-h`}><Icon name="plus" size={16} /> Add a host</h3>
      <DemoWriteNotice />
      <div className="form-grid">
        <label className="field">
          <span>Host name</span>
          <input type="text" value={form.name} maxLength={253} onChange={set('name')} autoComplete="off" spellCheck="false" />
        </label>
        <label className="field">
          <span>Operating system</span>
          <select value={form.os} onChange={set('os')}>
            {Object.entries(OS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Environment</span>
          <input type="text" value={form.environment} maxLength={100} onChange={set('environment')} placeholder="prod, staging, dev" />
        </label>
        <label className="field">
          <span>Owner</span>
          <input type="text" value={form.owner} maxLength={100} onChange={set('owner')} />
        </label>
        <label className="field wide">
          <span>Tags <span className="muted small">(comma separated)</span></span>
          <input type="text" value={form.tags} onChange={set('tags')} />
        </label>
      </div>
      <div className="form-row">
        <button type="submit" className="btn primary small" aria-disabled={busy ? 'true' : undefined}>
          {busy ? 'Adding…' : 'Add host'}
        </button>
      </div>
      <div aria-live="polite">
        {error && <p className="form-msg error" role="alert">{error}</p>}
        {done && <p className="form-msg good">Added {done.name}. <Link to={`/hosts/${done.id}`}>Open the host</Link></p>}
      </div>
    </form>
  )
}

/** Admin tools (writers only): add a host, upload a scan. Guests see nothing. */
export function AdminTools({ onChanged }) {
  const { guest } = useSession()
  if (guest) return null
  return (
    <section className="card" aria-labelledby="admin-title">
      <div className="card-head">
        <div>
          <h2 id="admin-title">Admin tools</h2>
          <p className="muted small">Visible only when signed in as admin. Collectors never connect to STIGWatch: you upload their output.</p>
        </div>
      </div>
      <div className="admin-grid">
        <UploadScan onDone={onChanged} />
        <AddHost onDone={onChanged} />
      </div>
    </section>
  )
}

/** Shown on every data page when no scan exists yet. */
export function NoData({ onChanged }) {
  const { guest } = useSession()
  return (
    <section className="card no-data" aria-labelledby="nodata-title">
      <h2 id="nodata-title"><Icon name="radar" size={18} /> Run a collector and upload a scan to begin</h2>
      <p>
        STIGWatch has no scans yet. A collector is a read-only script you run on a host; it writes one JSON file
        that you upload here. The <Link to="/benchmarks">Benchmarks</Link> page has the commands for Ubuntu and Windows.
      </p>
      <ol className="steps">
        <li>Run the collector on the host: {COLLECTOR_STEPS.linux.title} or {COLLECTOR_STEPS.windows.title}.</li>
        <li>Upload the JSON file it wrote{guest ? ' (only an admin can upload in this demo)' : ''}.</li>
        <li>Come back after the next weekly scan to see what changed.</li>
      </ol>
      {!guest && <div className="admin-grid"><UploadScan onDone={onChanged} /><AddHost onDone={onChanged} /></div>}
    </section>
  )
}
