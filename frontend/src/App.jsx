import { useState } from 'react'
import UploadPanel from './components/UploadPanel.jsx'
import ScanConsole from './components/ScanConsole.jsx'
import ReportView from './components/ReportView.jsx'
import { uploadApk, pollStatus, getReport } from './api.js'

// Phases: idle -> submitting -> scanning -> report | failed
export default function App() {
  const [phase, setPhase] = useState('idle')
  const [filename, setFilename] = useState('')
  const [progress, setProgress] = useState(0)
  const [jobId, setJobId] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [consoleLogs, setConsoleLogs] = useState([])

  async function handleSubmit(file) {
    setError(null)
    setFilename(file.name)
    setProgress(0)

    const isLarge = file.size > 4 * 1024 * 1024
    const initMsg = isLarge
      ? 'APK size exceeds Vercel limit. Initializing metadata-only analysis...'
      : 'Uploading APK package and establishing secure connection...'

    setConsoleLogs([{ at: 0, line: initMsg }])
    setPhase('scanning')

    try {
      const response = await uploadApk(file, {
        onProgress: (p) => {
          setProgress(p.progress)
          setConsoleLogs((prev) => {
            // Avoid duplicate log lines
            if (prev.length > 0 && prev[prev.length - 1].line === p.message) {
              return prev
            }
            return [...prev, { at: p.progress, line: p.message }]
          })
        }
      })

      setJobId(response.jobId)
      if (response.status === 'completed' && response.result) {
        setReport(response.result)
        setPhase('report')
      } else {
        throw new Error('Analysis completed but did not return report results.')
      }
    } catch (err) {
      setError(err.message)
      setPhase('failed')
    }
  }

  function reset() {
    setPhase('idle')
    setError(null)
    setJobId(null)
    setReport(null)
    setProgress(0)
    setConsoleLogs([])
  }

  return (
    <div style={{ minHeight: '100%', padding: '48px 24px' }}>
      <div className="scanlines" />

      {phase !== 'report' && (
        <header style={{ textAlign: 'center', marginBottom: 48 }}>
          <div className="eyebrow" style={{ marginBottom: 10 }}>genai-powered threat assessment platform</div>
          <h1 style={{
            fontFamily: 'var(--font-display)', fontSize: 38, fontWeight: 700,
            margin: 0, letterSpacing: '-0.01em',
          }}>
            🛡️ APK <span style={{ color: 'var(--accent)' }}>Sentinel</span>
          </h1>
          <p style={{ color: 'var(--text-dim)', fontSize: 14, marginTop: 10 }}>
            Static decompilation · dynamic sandbox tracing · 5-pillar GenAI threat verdict
          </p>
        </header>
      )}

      {phase === 'idle' && (
        <UploadPanel onSubmit={handleSubmit} disabled={false} />
      )}

      {(phase === 'scanning' || phase === 'failed') && (
        <>
          <ScanConsole filename={filename} progress={progress} status={phase === 'failed' ? 'failed' : 'active'} logs={consoleLogs} />
          {phase === 'failed' && (
            <div style={{ maxWidth: 640, margin: '20px auto 0', textAlign: 'center' }}>
              <p className="mono" style={{ color: 'var(--critical)', fontSize: 13 }}>{error}</p>
              <button onClick={reset} style={resetBtn}>↺ try another file</button>
            </div>
          )}
        </>
      )}

      {phase === 'report' && report && (
        <ReportView jobId={jobId} report={report} onReset={reset} />
      )}
    </div>
  )
}

const resetBtn = {
  marginTop: 12, fontFamily: 'var(--font-mono)', fontSize: 12, padding: '9px 16px',
  borderRadius: 6, background: 'transparent', color: 'var(--text-muted)',
  border: '1px solid var(--border)', cursor: 'pointer',
}
