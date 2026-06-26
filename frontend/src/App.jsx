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

  async function handleSubmit(file) {
    setError(null)
    setPhase('submitting')
    setFilename(file.name)
    try {
      const { jobId } = await uploadApk(file)
      setJobId(jobId)
      setPhase('scanning')
      setProgress(0)

      const finalStatus = await pollStatus(jobId, {
        onTick: (s) => setProgress(s.progress ?? 0),
      })

      if (finalStatus.status === 'failed') {
        setError(finalStatus.error || 'Analysis pipeline failed.')
        setPhase('failed')
        return
      }

      const { report } = await getReport(jobId)
      setReport(report)
      setPhase('report')
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

      {phase === 'submitting' && (
        <UploadPanel onSubmit={() => {}} disabled={true} />
      )}

      {(phase === 'scanning' || phase === 'failed') && (
        <>
          <ScanConsole filename={filename} progress={progress} status={phase === 'failed' ? 'failed' : 'active'} />
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
