import { useMemo, useRef, useState } from 'react'
import { highlight } from '../highlight.js'
import { plural } from '../lib.js'
import { Icon } from './ui.jsx'

/** Copy `text` to the clipboard and say so (politely announced). Never throws. */
export function CopyButton({ text, label = 'Copy', small = true }) {
  const [state, setState] = useState('')
  const timer = useRef(0)
  async function copy() {
    clearTimeout(timer.current)
    try {
      await navigator.clipboard.writeText(text)
      setState('Copied')
    } catch {
      setState('Could not copy; select the text and copy it')
    }
    timer.current = setTimeout(() => setState(''), 2500)
  }
  return (
    <span className="copy-wrap">
      <button type="button" className={`btn secondary${small ? ' small' : ''}`} onClick={copy}>
        <Icon name="copy" size={15} />{label}
      </button>
      <span role="status" className="form-msg good copy-msg">{state}</span>
    </span>
  )
}

/**
 * Syntax-highlighted text for the generated remediation files. Tokens are React <span>s with
 * text children (see highlight.js); the file content is never treated as HTML. Long files show
 * the first `firstLines` lines until asked for the rest. The block is focusable so it can be
 * scrolled and read with the keyboard.
 */
export function CodeView({ text, lang, label, firstLines = 300 }) {
  const lines = useMemo(() => highlight(text, lang), [text, lang])
  const [all, setAll] = useState(false)
  const shown = all ? lines : lines.slice(0, firstLines)
  return (
    <div className="code-view">
      <pre className="code-pre" tabIndex={0} aria-label={label}>
        <code>
          {shown.map((tokens, i) => (
            <span className="cl" key={i}>
              {tokens.map((t, j) => (t.type === 'plain'
                ? t.text
                : <span key={j} className={`tk-${t.type}`}>{t.text}</span>))}
              {'\n'}
            </span>
          ))}
        </code>
      </pre>
      {lines.length > shown.length && (
        <div className="more-row">
          <span className="muted small">Showing the first {shown.length} of {plural(lines.length, 'line')}. The download has the whole file.</span>
          <button type="button" className="btn secondary small" onClick={() => setAll(true)}>
            Show all {lines.length} lines
          </button>
        </div>
      )}
    </div>
  )
}

/** A short block of commands to copy (collector instructions). Plain text in a <pre>. */
export function CommandBlock({ commands, label }) {
  const text = commands.join('\n')
  return (
    <div className="command-block">
      <pre className="code-block" tabIndex={0} aria-label={label}><code>{text}</code></pre>
      <CopyButton text={commands.filter((c) => !c.startsWith('#')).join('\n')} label="Copy commands" />
    </div>
  )
}
