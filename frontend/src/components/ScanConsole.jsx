export default function ScanConsole({ filename, progress, status, logs = [] }) {
  return (
    <div style={{
      background: 'var(--panel-inset)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)',
      padding: '20px 22px',
      maxWidth: 640,
      margin: '0 auto',
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 14 }}>
        <span className="eyebrow">live sandbox console</span>
        <span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>{progress}%</span>
      </div>

      <div className="mono" style={{ fontSize: 12.5, lineHeight: 1.9, minHeight: 220, color: 'var(--text-muted)' }}>
        <div style={{ color: 'var(--text)' }}>
          <span style={{ color: 'var(--accent)' }}>$</span> sentinel analyze <span style={{ color: 'var(--text-muted)' }}>{filename}</span>
        </div>
        {logs.map((s, i) => (
          <div key={i}>
            <span style={{ color: 'var(--text-dim)' }}>[{String(s.at).padStart(3, ' ')}%]</span> {s.line}
          </div>
        ))}
        {status === 'active' && (
          <div style={{ color: 'var(--accent)' }}>
            <span className="cursor-blink">▌</span>
          </div>
        )}
        {status === 'failed' && (
          <div style={{ color: 'var(--critical)' }}>✕ pipeline halted — see error above</div>
        )}
      </div>

      <div style={{ marginTop: 16, height: 4, borderRadius: 2, background: 'var(--border-soft)', overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${progress}%`,
          background: status === 'failed' ? 'var(--critical)' : 'var(--accent)',
          transition: 'width 0.4s ease',
        }} />
      </div>

      <style>{`
        .cursor-blink { animation: blink 1s steps(2) infinite; }
        @keyframes blink { 50% { opacity: 0; } }
      `}</style>
    </div>
  )
}
