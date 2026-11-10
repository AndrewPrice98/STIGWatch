import { useRef, useState } from 'react'
import { CATS, COMPLIANCE_DEFINITION, formatDate, formatPct, niceMax, plural } from '../lib.js'
import { CatBadge, useWidth } from './ui.jsx'

const CAT_KEY = { 'CAT I': 'cat1', 'CAT II': 'cat2', 'CAT III': 'cat3' }

/**
 * Fleet open findings per CAT over the weekly scans, as three aligned small multiples (each CAT
 * on its own scale, so a CAT I change of 4 is as visible as a CAT II change of 40). Each panel is
 * labelled directly, the line is 1.5 px, and the annotated week is a dashed rule across all three.
 * Hover shows the week's values; the data table is the text alternative.
 */
export function TrendChart({ trend, annotation }) {
  const wrapRef = useRef(null)
  const width = useWidth(wrapRef, 720)
  const [hover, setHover] = useState(null)
  const n = trend.length
  if (!n) return null

  const narrow = width < 520
  const padL = narrow ? 30 : 36
  const padR = narrow ? 24 : 36
  const top = 36
  const panelH = narrow ? 64 : 72
  const gap = 22
  const axisH = 28
  const height = top + CATS.length * panelH + (CATS.length - 1) * gap + axisH
  const plotW = Math.max(120, width - padL - padR)
  const step = n > 1 ? plotW / (n - 1) : 0
  const x = (i) => padL + i * step
  const perLabel = n > 1 ? step : plotW
  const dateLabels = perLabel >= 58

  const panels = CATS.map((cat, p) => {
    const values = trend.map((t) => t.open?.[cat] ?? 0)
    const max = niceMax(Math.max(...values))
    const y0 = top + p * (panelH + gap)
    const y = (v) => y0 + panelH - (v / max) * (panelH - 6)
    return { cat, values, max, y0, y }
  })

  const ann = annotation && annotation.week >= 1 && annotation.week <= n ? annotation : null
  const annX = ann ? x(ann.week - 1) : 0
  const annAnchor = ann ? (annX > width - 190 ? 'end' : annX < 150 ? 'start' : 'middle') : 'middle'

  const first = trend[0].week
  const last = trend[n - 1].week
  const summary = `Fleet open findings by CAT, weekly from ${formatDate(first)} to ${formatDate(last)}. `
    + panels.map((pn) => `${pn.cat}: ${pn.values[0]} to ${pn.values[n - 1]}`).join('; ') + '.'
    + (ann ? ` Annotated: week ${ann.week}, ${ann.label}.` : '')

  const tipLeft = hover == null ? 0 : Math.min(Math.max(x(hover) - 80, 4), width - 168)

  return (
    <figure className="trend">
      <div className="trend-plot" ref={wrapRef} onMouseLeave={() => setHover(null)}>
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={summary}
          focusable="false">
          {ann && (
            <g className="ann">
              <line x1={annX} x2={annX} y1={top - 8} y2={height - axisH + 2} />
              <text x={annAnchor === 'start' ? annX - 3 : annAnchor === 'end' ? annX + 3 : annX}
                y={10} textAnchor={annAnchor}>{`Week ${ann.week}: ${ann.label}`}</text>
            </g>
          )}
          {panels.map((pn) => (
            <g key={pn.cat} className={`panel ${CAT_KEY[pn.cat]}`}>
              <text className="panel-label" x={padL} y={pn.y0 - 7}>{pn.cat}</text>
              <text className="axis-max" x={padL - 8} y={pn.y(pn.max) + 4} textAnchor="end">{pn.max}</text>
              <text className="axis-max" x={padL - 8} y={pn.y(0) + 4} textAnchor="end">0</text>
              <line className="grid" x1={padL} x2={padL + plotW} y1={pn.y(pn.max)} y2={pn.y(pn.max)} />
              <line className="baseline" x1={padL} x2={padL + plotW} y1={pn.y(0)} y2={pn.y(0)} />
              <polyline className={`series ${CAT_KEY[pn.cat]}`}
                points={pn.values.map((v, i) => `${x(i)},${pn.y(v)}`).join(' ')} />
              {pn.values.map((v, i) => {
                const marked = i === n - 1 || (ann && i === ann.week - 1)
                return marked ? <circle key={i} className={`mk ${CAT_KEY[pn.cat]}`} cx={x(i)} cy={pn.y(v)} r="3" /> : null
              })}
              {pn.values.map((v, i) => {
                const show = i === 0 || i === n - 1 || (ann && i === ann.week - 1)
                if (!show) return null
                const anchor = i === 0 || i === n - 1 ? 'start' : 'middle'
                const above = pn.y(v) - 9 > pn.y0 + 2
                const dx = i === 0 ? 2 : i === n - 1 ? 8 : 0
                return (
                  <text key={`l${i}`} className="value-label" x={x(i) + dx}
                    y={i === n - 1 ? pn.y(v) + 4 : above ? pn.y(v) - 8 : pn.y(v) + 16} textAnchor={anchor}>{v}</text>
                )
              })}
            </g>
          ))}
          <g className="x-axis">
            {trend.map((t, i) => (
              <text key={t.week} x={x(i)} y={height - 8}
                textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'}>
                {dateLabels ? formatDate(t.week, { withYear: false }) : `W${i + 1}`}
              </text>
            ))}
          </g>
          {hover != null && (
            <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={top - 4} y2={height - axisH + 2} />
          )}
          {trend.map((t, i) => (
            <rect key={`h${t.week}`} className="hit" x={x(i) - Math.max(step / 2, 10)} y={top - 6}
              width={Math.max(step, 20)} height={height - top - axisH + 10}
              onMouseEnter={() => setHover(i)} />
          ))}
        </svg>
        {hover != null && (
          <div className="tooltip" style={{ left: tipLeft }} aria-hidden="true">
            <strong>Week {hover + 1} · {formatDate(trend[hover].week)}</strong>
            {CATS.map((cat) => (
              <span key={cat} className="tt-row"><i className={`sev-dot ${CAT_KEY[cat]}`} />{cat}<b>{trend[hover].open?.[cat] ?? 0}</b></span>
            ))}
          </div>
        )}
      </div>
      {!dateLabels && <p className="axis-note">W1 = week of {formatDate(first)}; one scan per host per week.</p>}
      <details className="data-table">
        <summary>Show the data as a table</summary>
        <div className="table-wrap">
          <table className="table compact">
            <caption className="sr-only">Fleet open findings by CAT per week</caption>
            <thead>
              <tr><th scope="col">Week</th>{CATS.map((c) => <th key={c} scope="col" className="num">{c}</th>)}</tr>
            </thead>
            <tbody>
              {trend.map((t, i) => (
                <tr key={t.week} className={ann && i === ann.week - 1 ? 'hl' : ''}>
                  <th scope="row">{i + 1} · {formatDate(t.week)}</th>
                  {CATS.map((c) => <td key={c} className="num">{t.open?.[c] ?? 0}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  )
}

/** The compliance figure as a large numeral over a thin linear meter, with the definition as text. */
export function ComplianceMeter({ value, notReviewed, notApplicable }) {
  const pct = value == null ? 0 : Math.max(0, Math.min(100, value))
  return (
    <div className="meter-block">
      <p className="kpi-num">{formatPct(value)}</p>
      <div className="meter" role="img" aria-label={`Compliance ${formatPct(value)}`}>
        <span className="meter-fill" style={{ width: `${pct}%` }} />
      </div>
      <p className="kpi-sub"><strong>Compliance</strong> = {COMPLIANCE_DEFINITION}.</p>
      {(notReviewed != null || notApplicable != null) && (
        <p className="kpi-sub">
          Shown separately, not counted: {plural(notReviewed || 0, 'result')} Not reviewed
          {notApplicable != null && <>, {notApplicable} Not applicable</>}.
        </p>
      )}
    </div>
  )
}

const SEGMENTS = [
  ['Open', 'open', 'open'],
  ['NotAFinding', 'naf', 'not a finding'],
  ['Not_Reviewed', 'nr', 'not reviewed'],
  ['Not_Applicable', 'na', 'N/A'],
]

/** One flat stacked bar per CAT; each count is labelled with its own colour key. */
export function CatBars({ breakdown }) {
  return (
    <ul className="catbar-list">
      {CATS.map((cat) => {
        const row = breakdown[cat]
        const total = row.total || 1
        return (
          <li key={cat} className="catbar-row">
            <div className="catbar-head">
              <CatBadge cat={cat} />
              <span className="catbar-total">{plural(row.total, 'rule')}</span>
            </div>
            <div className="catbar" aria-hidden="true">
              {SEGMENTS.map(([key, cls]) => row[key] > 0 && (
                <span key={key} className={`seg ${cls}`} style={{ flexGrow: row[key] / total }} />
              ))}
            </div>
            <p className="catbar-text">
              {SEGMENTS.map(([key, cls, label]) => (
                <span key={key} className={`key${row[key] ? '' : ' zero'}`}>
                  <i className={`swatch ${cls}`} aria-hidden="true" /><b>{row[key]}</b> {label}
                </span>
              ))}
            </p>
          </li>
        )
      })}
    </ul>
  )
}

/** Tiny sparkline (open findings per week). Decorative: the numbers are beside it. */
export function Sparkline({ values, width = 84, height = 24, className = '' }) {
  if (!values?.length) return null
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? (width - 4) / (values.length - 1) : 0
  const pts = values.map((v, i) => `${2 + i * step},${height - 2 - (v / max) * (height - 4)}`).join(' ')
  return (
    <svg className={`spark ${className}`} width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
      <polyline points={pts} />
    </svg>
  )
}
