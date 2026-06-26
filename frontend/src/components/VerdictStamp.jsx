import { severityColor } from './ui.jsx'

// The page's signature element: a rotated rubber-stamp badge, the way an
// investigator would mark a closed case file, fused with a radial gauge
// reading the composite 0–100 risk score.
export default function VerdictStamp({ score, severity, recommendation }) {
  const color = severityColor(severity)
  const circumference = 2 * Math.PI * 54
  const offset = circumference - (score / 100) * circumference

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 28, flexWrap: 'wrap' }}>
      <div style={{ position: 'relative', width: 132, height: 132, flexShrink: 0 }}>
        <svg width="132" height="132" viewBox="0 0 132 132">
          <circle cx="66" cy="66" r="54" fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle
            cx="66" cy="66" r="54" fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={circumference} strokeDashoffset={offset}
            strokeLinecap="round" transform="rotate(-90 66 66)"
            style={{ transition: 'stroke-dashoffset 0.9s ease' }}
          />
        </svg>
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
        }}>
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 34, fontWeight: 700, color: 'var(--text)' }}>
            {score}
          </span>
          <span className="mono" style={{ fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.08em' }}>/ 100</span>
        </div>
      </div>

      <div style={{ flex: 1, minWidth: 220 }}>
        <div
          style={{
            display: 'inline-block',
            fontFamily: 'var(--font-display)',
            fontWeight: 700,
            fontSize: 22,
            letterSpacing: '0.06em',
            color,
            border: `2px solid ${color}`,
            borderRadius: 6,
            padding: '6px 16px',
            transform: 'rotate(-3deg)',
            textTransform: 'uppercase',
            boxShadow: `0 0 0 1px ${color}22 inset`,
          }}
        >
          {severity}
        </div>
        <div className="mono" style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>
          recommended action → <span style={{ color }}>{recommendation?.replace(/_/g, ' ')}</span>
        </div>
      </div>
    </div>
  )
}
