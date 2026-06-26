import { useEffect, useRef, useState } from 'react'

// Mirrors the exact progress checkpoints emitted by backend/src/core/pipeline.js
// (10 → static, 25 → static done, 45 → dynamic done, 75 → genai done, 90 → risk+vector, 100 → report)
const STAGES = [
  { at: 0,  line: 'queueing job · awaiting worker pickup' },
  { at: 10, line: 'stage 1/6 — static analysis: unpacking manifest, scanning permissions' },
  { at: 25, line: 'stage 1/6 — static analysis complete: certificate + smali strings extracted' },
  { at: 25, line: 'stage 2/6 — dynamic analysis: launching sandbox, attaching frida hooks' },
  { at: 45, line: 'stage 2/6 — dynamic analysis complete: behavioral timeline captured' },
  { at: 45, line: 'stage 3/6 — genai engine: dispatching 5-pillar threat assessment' },
  { at: 75, line: 'stage 3/6 — genai engine: pillars 1–5 received' },
  { at: 75, line: 'stage 4/6 — cross-referencing intent vectors against known malware families' },
  { at: 90, line: 'stage 5/6 — composite risk score computed' },
  { at: 90, line: 'stage 6/6 — compiling JSON + PDF dossier' },
  { at: 100, line: 'pipeline complete — dossier ready' },
]

export default function ScanConsole({ filename, progress, status }) {
  const [shown, setShown] = useState([])
  const lastAt = useRef(-1)

  useEffect(() => {
    const next = STAGES.filter((s) => s.at <= progress && s.at > lastAt.current)
    if (next.length) {
      setShown((prev) => [...prev, ...next])
      lastAt.current = Math.max(...next.map((s) => s.at))
    }
  }, [progress])

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
        {shown.map((s, i) => (
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
