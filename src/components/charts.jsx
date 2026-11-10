import { useRef, useState } from 'react'
import { CATS, COMPLIANCE_DEFINITION, formatDate, formatPct, niceMax, plural } from '../lib.js'
import { CatBadge, useWidth } from './ui.jsx'

const CAT_KEY = { 'CAT I': 'cat1', 'CAT II': 'cat2', 'CAT III': 'cat3' }

/** Marker shapes differ per CAT, so the series are told apart without colour. */
function Marker({ cat, x, y, r = 4.5 }) {
  const cls = `mk ${CAT_KEY[cat]}`
  if (cat === 'CAT II') return <rect className={cls} x={x - r} y={y - r} width={r * 2} height={r * 2} rx="1" />
  if (cat === 'CAT III') {
    const h = r * 1.15
    return <path className={cls} d={`M${x} ${y - h - 0.6}L${x + h + 0.6} ${y + h - 0.2}H${x - h - 0.6}Z`} />
  }
  return <circle className={cls} cx={x} cy={y} r={r} />
}

export function LegendMarker({ cat }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" focusable="false" className="legend-mk">
      <Marker cat={cat} x={7} y={7} r={4.2} />
    </svg>
  )
}

/**
 * Fleet open findings per CAT over the weekly scans, as three aligned small multiples (each CAT
 * on its own scale, so a CAT I change of 4 is as visible as a CAT II change of 40), with an
 * annotated week. Hover shows the week's values; the data table is the text alternative.
 */
export function TrendChart({ trend, annotation }) {
  const wrapRef = useRef(null)
  const width = useWidth(wrapRef, 720)
  const [hover, setHover] = useState(null)
  const n = trend.length
  if (!n) return null

  const narrow = width < 520
  const padL = narrow ? 64 : 92
  const padR = narrow ? 14 : 24
  const top = 34
  const panelH = narrow ? 70 : 84
  const gap = 16
  const axisH = 34
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
    const y = (v) => y0 + panelH - (v / max) * (panelH - 8)
    return { cat, values, max, y0, y }
  })

  const ann = annotation && annotation.week >= 1 && annotation.week <= n ? annotation : null
  const annX = ann ? x(ann.week - 1) : 0
  const annAnchor = ann ? (annX > width - 150 ? 'end' : annX < 150 ? 'start' : 'middle') : 'middle'

  const first = trend[0].week
  const last = trend[n - 1].week
  const summary = `Fleet open findings by CAT, weekly from ${formatDate(first)} to ${formatDate(last)}. `
    + panels.map((pn) => `${pn.cat}: ${pn.values[0]} to ${pn.values[n - 1]}`).join('; ') + '.'
    + (ann ? ` Annotated: week ${ann.week}, ${ann.label}.` : '')

  const tipLeft = hover == null ? 0 : Math.min(Math.max(x(hover) - 80, 4), width - 168)

  return (
    <figure className="trend">
      <ul className="legend" aria-hidden="true">
        {CATS.map((cat) => <li key={cat}><LegendMarker cat={cat} />{cat}</li>)}
        {ann && <li><span className="legend-band" />Week {ann.week} regression</li>}
      </ul>
      <div className="trend-plot" ref={wrapRef} onMouseLeave={() => setHover(null)}>
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={summary}
          focusable="false">
          {ann && (
            <g className="ann">
              <rect x={annX - Math.min(step / 2, 26)} y={top - 6} width={Math.min(step, 52)}
                height={height - top - axisH + 10} rx="4" />
              <text x={annAnchor === 'start' ? annX - Math.min(step / 2, 26) : annAnchor === 'end' ? annX + Math.min(step / 2, 26) : annX}
                y={14} textAnchor={annAnchor}>{`▼ Week ${ann.week}: ${ann.label}`}</text>
            </g>
          )}
          {panels.map((pn) => (
            <g key={pn.cat} className={`panel ${CAT_KEY[pn.cat]}`}>
              <text className="panel-label" x={0} y={pn.y0 + 12}>{pn.cat}</text>
              <text className="axis-max" x={padL - 10} y={pn.y(pn.max) + 4} textAnchor="end">{pn.max}</text>
              <text className="axis-max" x={padL - 10} y={pn.y(0) + 4} textAnchor="end">0</text>
              <line className="grid" x1={padL} x2={padL + plotW} y1={pn.y(pn.max)} y2={pn.y(pn.max)} />
              <line className="baseline" x1={padL} x2={padL + plotW} y1={pn.y(0)} y2={pn.y(0)} />
              <polyline className={`series ${CAT_KEY[pn.cat]}`}
                points={pn.values.map((v, i) => `${x(i)},${pn.y(v)}`).join(' ')} />
              {pn.values.map((v, i) => <Marker key={i} cat={pn.cat} x={x(i)} y={pn.y(v)} />)}
              {pn.values.map((v, i) => {
                const show = i === 0 || i === n - 1 || (ann && i === ann.week - 1) || (ann && i === ann.week - 2)
                if (!show) return null
                const anchor = i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'
                const above = pn.y(v) - 9 > pn.y0 + 2
                return (
                  <text key={`l${i}`} className="value-label" x={x(i) + (i === 0 ? 6 : i === n - 1 ? -6 : 0)}
                    y={above ? pn.y(v) - 9 : pn.y(v) + 17} textAnchor={anchor}>{v}</text>
                )
              })}
            </g>
          ))}
          <g className="x-axis">
            {trend.map((t, i) => (
              <text key={t.week} x={x(i)} y={height - 12}
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
              <span key={cat} className="tt-row"><LegendMarker cat={cat} />{cat}<b>{trend[hover].open?.[cat] ?? 0}</b></span>
            ))}
          </div>
        )}
      </div>
      {!dateLabels && <p className="axis-note">W1 = week of {formatDate(first)}; one scan per host per week.</p>}
      <details className="data-table">
        <summary>Show the data as a table</summary>
        <div className="table-scroll">
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

/** Semicircle gauge for a percentage, with the number and definition as text. */
export function ComplianceGauge({ value, notReviewed, notApplicable }) {
  const r = 80
  const cx = 100
  const cy = 96
  const pct = value == null ? 0 : Math.max(0, Math.min(100, value))
  const angle = Math.PI * (1 - pct / 100)
  const ex = cx + r * Math.cos(angle)
  const ey = cy - r * Math.sin(angle)
  const track = `M${cx - r} ${cy} A${r} ${r} 0 0 1 ${cx + r} ${cy}`
  const arc = `M${cx - r} ${cy} A${r} ${r} 0 0 1 ${ex.toFixed(2)} ${ey.toFixed(2)}`
  return (
    <div className="gauge">
      <svg viewBox="0 0 200 112" width="200" height="112" role="img" focusable="false"
        aria-label={`Compliance ${formatPct(value)}`}>
        <path className="gauge-track" d={track} />
        {value != null && pct > 0 && <path className="gauge-value" d={arc} />}
        {[0, 50, 100].map((t) => {
          const a = Math.PI * (1 - t / 100)
          return (
            <line key={t} className="gauge-tick" x1={cx + (r - 13) * Math.cos(a)} y1={cy - (r - 13) * Math.sin(a)}
              x2={cx + (r + 13) * Math.cos(a)} y2={cy - (r + 13) * Math.sin(a)} />
          )
        })}
        <text className="gauge-num" x={cx} y={cy - 14} textAnchor="middle">{formatPct(value)}</text>
      </svg>
      <p className="gauge-def"><strong>Compliance</strong> = {COMPLIANCE_DEFINITION}.</p>
      {(notReviewed != null || notApplicable != null) && (
        <p className="gauge-sep muted small">
          Shown separately, not counted: {plural(notReviewed || 0, 'result')} Not reviewed
          {notApplicable != null && <>, {notApplicable} Not applicable</>}.
        </p>
      )}
    </div>
  )
}

const SEGMENTS = [
  ['Open', 'open', 'Open'],
  ['NotAFinding', 'naf', 'Not a finding'],
  ['Not_Reviewed', 'nr', 'Not reviewed'],
  ['Not_Applicable', 'na', 'Not applicable'],
]

/** One stacked bar per CAT: Open, Not a finding, Not reviewed, Not applicable, with the counts as text. */
export function CatBars({ breakdown }) {
  return (
    <div className="catbars">
      <ul className="legend small" aria-hidden="true">
        {SEGMENTS.map(([, cls, label]) => <li key={cls}><span className={`swatch ${cls}`} />{label}</li>)}
      </ul>
      <ul className="catbar-list">
        {CATS.map((cat) => {
          const row = breakdown[cat]
          const total = row.total || 1
          return (
            <li key={cat} className="catbar-row">
              <div className="catbar-head">
                <CatBadge cat={cat} />
                <span className="catbar-total muted small">{plural(row.total, 'rule')}</span>
              </div>
              <div className="catbar" aria-hidden="true">
                {SEGMENTS.map(([key, cls]) => row[key] > 0 && (
                  <span key={key} className={`seg ${cls} ${key === 'Open' ? CAT_KEY[cat] : ''}`}
                    style={{ flexGrow: row[key] / total }} />
                ))}
              </div>
              <p className="catbar-text small">
                <strong className={row.Open ? `open-num ${CAT_KEY[cat]}` : 'open-num zero'}>{row.Open} open</strong>
                {' · '}{row.NotAFinding} not a finding · {row.Not_Reviewed} not reviewed · {row.Not_Applicable} N/A
              </p>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

/** Tiny per-host sparkline (total open findings per scan). Decorative: the numbers are in the row. */
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
