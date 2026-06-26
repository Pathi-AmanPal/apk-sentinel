export const SEVERITY_COLOR = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
}

export const SEVERITY_SOFT = {
  CRITICAL: 'var(--critical-soft)',
  HIGH: 'var(--high-soft)',
  MEDIUM: 'var(--medium-soft)',
  LOW: 'var(--low-soft)',
  critical: 'var(--critical-soft)',
  high: 'var(--high-soft)',
  medium: 'var(--medium-soft)',
  low: 'var(--low-soft)',
}

export function severityColor(level) {
  return SEVERITY_COLOR[level] || 'var(--text-dim)'
}
export function severitySoft(level) {
  return SEVERITY_SOFT[level] || 'var(--panel-raised)'
}

export function Panel({ children, style, ...rest }) {
  return (
    <div
      style={{
        background: 'var(--panel)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding: 24,
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  )
}

export function SectionHeader({ index, title, subtitle }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 18 }}>
      {index != null && (
        <span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>{index}</span>
      )}
      <h3 style={{
        fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 600,
        margin: 0, letterSpacing: '0.01em',
      }}>
        {title}
      </h3>
      {subtitle && <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{subtitle}</span>}
      <div style={{ flex: 1, height: 1, background: 'var(--border-soft)' }} />
    </div>
  )
}

export function Pill({ children, color, soft }) {
  return (
    <span className="mono" style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      fontSize: 11, padding: '3px 9px', borderRadius: 999,
      color: color || 'var(--text-muted)',
      background: soft || 'var(--panel-raised)',
      border: `1px solid ${color || 'var(--border)'}33`,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {children}
    </span>
  )
}

export function Bar({ value, max, color }) {
  const pct = Math.min(100, (value / max) * 100)
  return (
    <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--border-soft)', overflow: 'hidden' }}>
      <div style={{ height: '100%', width: `${pct}%`, background: color, transition: 'width 0.6s ease' }} />
    </div>
  )
}

export function KeyValueRow({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 13 }}>
      <span style={{ color: 'var(--text-dim)' }}>{label}</span>
      <span className={mono ? 'mono' : ''} style={{ color: 'var(--text)', textAlign: 'right', maxWidth: '65%' }}>{value}</span>
    </div>
  )
}
