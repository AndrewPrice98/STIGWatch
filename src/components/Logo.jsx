// The STIGWatch mark: a baseline with drift. Two bars sit on the baseline; the middle one has
// shifted right and carries the accent. It is drawn inline so it follows the page colours;
// public/logo-mark.svg and public/favicon.svg hold the same geometry for use outside the app.
export default function Logo({ size = 24 }) {
  return (
    <svg className="logo-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect className="logo-base" x="4" y="5" width="17" height="6" rx="1" />
      <rect className="logo-drift" x="11" y="13" width="17" height="6" rx="1" />
      <rect className="logo-base" x="4" y="21" width="17" height="6" rx="1" />
    </svg>
  )
}
