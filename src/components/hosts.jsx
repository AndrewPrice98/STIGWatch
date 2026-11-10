import { Link } from 'react-router-dom'
import { CATS, OS_LABEL, formatDate, formatPct } from '../lib.js'
import { Icon, OpenCount } from './ui.jsx'

export function OsTag({ os }) {
  return (
    <span className={`os-tag ${os}`}>
      <Icon name="server" size={14} />{OS_LABEL[os] || os}
    </span>
  )
}

/**
 * Hosts with their latest-scan numbers. On narrow screens each row becomes a card
 * (the cells carry data-label for that layout).
 */
export function HostTable({ hosts, caption, showOwner = true, showScans = true }) {
  return (
    <div className="table-wrap">
      <table className="table cards host-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Host</th>
            {showOwner && <th scope="col">Environment · owner</th>}
            {CATS.map((c) => <th key={c} scope="col" className="num">{c}<span className="sr-only"> open</span></th>)}
            <th scope="col" className="num">Compliance</th>
            <th scope="col" className="num">Not reviewed</th>
            {showScans && <th scope="col">Last scan</th>}
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.id} className={h.open?.['CAT I'] ? 'has-cat1' : ''}>
              <th scope="row">
                <div className="host-cell">
                  <Link to={`/hosts/${h.id}`} className="host-link">{h.name}</Link>
                  <OsTag os={h.os} />
                </div>
              </th>
              {showOwner && (
                <td data-label="Environment">
                  <div className="env-cell">
                    <span className={`env ${String(h.environment).toLowerCase()}`}>{h.environment || '—'}</span>
                    <span className="muted small owner">{h.owner}</span>
                  </div>
                </td>
              )}
              {CATS.map((c) => (
                <td key={c} data-label={c} className="num count-cell"><OpenCount n={h.open?.[c] || 0} cat={c} /></td>
              ))}
              <td data-label="Compliance" className="num">{formatPct(h.compliance)}</td>
              <td data-label="Not reviewed" className="num muted-num">{h.status?.Not_Reviewed ?? 0}</td>
              {showScans && (
                <td data-label="Last scan" className="date-cell">
                  {formatDate(h.latest_scan?.collected_at)}
                  {h.latest_scan && <span className="muted small"> · {h.latest_scan.benchmark_release}</span>}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
