// =============================================
// api.js — thin client for the APK Sentinel backend
// Matches backend/src/routes/analysis.js exactly:
//   POST /api/analyze        -> { jobId, pollUrl }
//   GET  /api/status/:jobId  -> { status, progress, result? }
//   GET  /api/report/:jobId  -> { report } | PDF download
// =============================================

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api'

async function asJson(res) {
  const data = await res.json().catch(() => null)
  if (!res.ok || (data && data.success === false)) {
    const message = data?.error || `Request failed (${res.status})`
    throw new Error(message)
  }
  return data
}

export async function uploadApk(file) {
  const form = new FormData()
  form.append('apk', file)
  const res = await fetch(`${API_URL}/analyze`, { method: 'POST', body: form })
  return asJson(res)
}

export async function getStatus(jobId) {
  const res = await fetch(`${API_URL}/status/${jobId}`)
  return asJson(res)
}

export async function getReport(jobId) {
  const res = await fetch(`${API_URL}/report/${jobId}?format=json`)
  return asJson(res)
}

export function pdfReportUrl(jobId) {
  return `${API_URL}/report/${jobId}?format=pdf`
}

// Polls /api/status/:jobId until status is completed or failed.
// onTick receives the raw status payload on every poll, including progress.
export async function pollStatus(jobId, { intervalMs = 1800, onTick } = {}) {
  while (true) {
    const status = await getStatus(jobId)
    onTick?.(status)
    if (status.status === 'completed' || status.status === 'failed') {
      return status
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
