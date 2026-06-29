// =============================================
// api.js — thin client for the APK Sentinel backend
// Matches backend/src/routes/analysis.js exactly:
//   POST /api/analyze        -> { jobId, pollUrl }
//   GET  /api/status/:jobId  -> { status, progress, result? }
//   GET  /api/report/:jobId  -> { report } | PDF download
// =============================================

const API_URL = import.meta.env.VITE_API_URL || '/api'

async function asJson(res) {
  const data = await res.json().catch(() => null)
  if (!res.ok || (data && data.success === false)) {
    const message = data?.error || `Request failed (${res.status})`
    throw new Error(message)
  }
  return data
}

export async function uploadApk(file, { onProgress } = {}) {
  let res
  // If file size exceeds 4MB, send metadata instead of the whole file
  // to bypass Vercel's 4.5MB payload limit
  if (file.size > 4 * 1024 * 1024) {
    res = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        filename: file.name,
        fileSize: file.size
      })
    })
  } else {
    const form = new FormData()
    form.append('apk', file)
    res = await fetch(`${API_URL}/analyze`, { method: 'POST', body: form })
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let errMessage = `Request failed (${res.status})`
    try {
      const parsed = JSON.parse(text)
      if (parsed && parsed.error) errMessage = parsed.error
    } catch (_) {}
    throw new Error(errMessage)
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalResult = null

  while (true) {
    const { value, done } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop()

    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('data: ')) {
        let payload
        try {
          payload = JSON.parse(trimmed.slice(6))
        } catch (e) {
          console.warn('Could not parse SSE chunk:', trimmed, e)
          continue
        }

        // Trigger progress updates only for non-empty messages
        if (payload.progress !== undefined && payload.message) {
          onProgress?.({
            progress: payload.progress,
            message: payload.message
          })
        }

        if (payload.status === 'completed' && payload.result) {
          finalResult = payload
        } else if (payload.status === 'failed') {
          throw new Error(payload.error || 'Pipeline execution failed.')
        }
      }
    }
  }

  if (!finalResult) {
    throw new Error('Analysis completed but did not return report results.')
  }

  return finalResult
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
