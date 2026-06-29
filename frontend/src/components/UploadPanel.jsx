import { useCallback, useRef, useState } from 'react'

export default function UploadPanel({ onSubmit, disabled, error }) {
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  const accept = useCallback((f) => {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.apk')) return
    setFile(f)
  }, [])

  return (
    <div style={{ maxWidth: 640, margin: '0 auto' }}>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); accept(e.dataTransfer.files?.[0]) }}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `1px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
          borderRadius: 'var(--radius-lg)',
          background: dragging ? 'var(--accent-soft)' : 'var(--panel)',
          padding: '56px 32px',
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'border-color 0.2s, background 0.2s',
          position: 'relative',
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk"
          hidden
          onChange={(e) => accept(e.target.files?.[0])}
        />

        {/* corner ticks — evidence-bag seal motif */}
        {['0,0', '1,0', '0,1', '1,1'].map((pos) => {
          const [x, y] = pos.split(',').map(Number)
          return (
            <div key={pos} style={{
              position: 'absolute',
              width: 14, height: 14,
              top: y ? undefined : 10, bottom: y ? 10 : undefined,
              left: x ? undefined : 10, right: x ? 10 : undefined,
              borderTop: !y ? '2px solid var(--border)' : 'none',
              borderBottom: y ? '2px solid var(--border)' : 'none',
              borderLeft: !x ? '2px solid var(--border)' : 'none',
              borderRight: x ? '2px solid var(--border)' : 'none',
            }} />
          )
        })}

        <div className="eyebrow" style={{ marginBottom: 14 }}>evidence intake</div>

        <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 600, marginBottom: 8 }}>
          {file ? file.name : 'Drop an .apk file, or click to browse'}
        </div>

        <div className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          {file ? `${(file.size / 1024 / 1024).toFixed(2)} MB · queued for analysis` : 'accepted format: .apk · max 100MB'}
        </div>
      </div>

      {error && (
        <div className="mono" style={{
          marginTop: 14, padding: '10px 14px', fontSize: 12.5,
          background: 'var(--critical-soft)', color: 'var(--critical)',
          border: '1px solid var(--critical)', borderRadius: 'var(--radius-sm)',
        }}>
          ✕ {error}
        </div>
      )}

      <button
        disabled={!file || disabled}
        onClick={() => onSubmit(file)}
        style={{
          marginTop: 18,
          width: '100%',
          padding: '14px 0',
          borderRadius: 'var(--radius-md)',
          border: 'none',
          fontFamily: 'var(--font-display)',
          fontWeight: 600,
          fontSize: 14,
          letterSpacing: '0.02em',
          cursor: (!file || disabled) ? 'not-allowed' : 'pointer',
          background: (!file || disabled) ? 'var(--panel-raised)' : 'var(--accent)',
          color: (!file || disabled) ? 'var(--text-dim)' : '#1a1206',
          transition: 'background 0.2s',
        }}
      >
        {disabled ? 'Submitting…' : 'Open case — begin analysis'}
      </button>

      <div style={{ marginTop: 22, textAlign: 'center' }}>
        <span className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          Need a test file?{' '}
          <a
            href="/demo.apk"
            download="demo.apk"
            onClick={(e) => e.stopPropagation()}
            style={{
              color: 'var(--accent)',
              textDecoration: 'underline',
              cursor: 'pointer',
              fontWeight: 500
            }}
          >
            Download Demo APK (10 KB)
          </a>
        </span>
      </div>
    </div>
  )
}
