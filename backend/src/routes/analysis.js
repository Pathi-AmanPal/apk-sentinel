// =============================================
// routes/analysis.js — API Routes (with in-memory fallback)
// =============================================
// Same as before, but with an in-memory job store as fallback
// when Redis (BullMQ) is not available.
// This lets us test the full pipeline without Docker running.
// =============================================

import express from 'express'
import multer from 'multer'
import path from 'path'
import { v4 as uuidv4 } from 'uuid'
import { readFile } from 'fs/promises'
import { existsSync, writeFileSync, readFileSync, mkdirSync, readdirSync } from 'fs'

import logger from '../utils/logger.js'
import { runPipeline } from '../core/pipeline.js'

const router = express.Router()

// ── Vercel/Serverless Directory Resolution ────────────────────────
const isVercel = !!process.env.VERCEL
const uploadDir = isVercel ? '/tmp' : (process.env.UPLOAD_DIR || './uploads')
const outputDir = isVercel ? '/tmp' : (process.env.OUTPUT_DIR || './output')
const storageDir = isVercel ? '/tmp/jobs' : path.join(outputDir, 'jobs')

try {
  mkdirSync(uploadDir, { recursive: true })
  mkdirSync(outputDir, { recursive: true })
  mkdirSync(storageDir, { recursive: true })
} catch (e) {}

// ── File-Persisted Job Store for Serverless Resilience ────────────
class JobStore {
  constructor() {
    this.memoryStore = new Map()
  }

  get(jobId) {
    if (this.memoryStore.has(jobId)) {
      return this.memoryStore.get(jobId)
    }
    const filePath = path.join(storageDir, `${jobId}.json`)
    if (existsSync(filePath)) {
      try {
        const content = readFileSync(filePath, 'utf-8')
        const job = JSON.parse(content)
        this.memoryStore.set(jobId, job)
        return job
      } catch (e) {
        logger.warn('Failed to parse persistent job file', { jobId, error: e.message })
      }
    }
    return null
  }

  set(jobId, jobData) {
    this.memoryStore.set(jobId, jobData)
    const filePath = path.join(storageDir, `${jobId}.json`)
    try {
      writeFileSync(filePath, JSON.stringify(jobData, null, 2), 'utf-8')
    } catch (e) {
      logger.warn('Failed to persist job file', { jobId, error: e.message })
    }
  }

  entries() {
    const jobs = new Map(this.memoryStore)
    try {
      const files = readdirSync(storageDir)
      for (const file of files) {
        if (!file.endsWith('.json')) continue
        const id = path.basename(file, '.json')
        if (!jobs.has(id)) {
          const content = readFileSync(path.join(storageDir, file), 'utf-8')
          jobs.set(id, JSON.parse(content))
        }
      }
    } catch (e) {}
    return jobs.entries()
  }
}

const jobStore = new JobStore()

// ── Multer Configuration ───────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const uniquePrefix = uuidv4().slice(0, 8)
    cb(null, `${uniquePrefix}-${file.originalname}`)
  }
})

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase()
  if (ext !== '.apk') {
    return cb(new Error('Only .apk files are allowed'), false)
  }
  cb(null, true)
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 }   // 100MB
})

// ── Route 1: POST /api/analyze ─────────────────────────────────────
router.post('/analyze', upload.single('apk'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No APK file uploaded. Send a file in the "apk" field.'
      })
    }

    const jobId = uuidv4()

    logger.info('APK uploaded, starting analysis job', {
      jobId,
      filename: req.file.originalname,
      size: `${(req.file.size / 1024 / 1024).toFixed(2)} MB`
    })

    // Store job in memory
    jobStore.set(jobId, {
      status: 'active',
      progress: 0,
      filename: req.file.originalname,
      filePath: req.file.path,
      createdAt: new Date().toISOString(),
      result: null,
      error: null
    })

    // Run pipeline in background (don't await — return immediately)
    // setImmediate pushes this to the next iteration of the event loop
    // so the HTTP response is sent BEFORE the pipeline starts
    setImmediate(async () => {
      try {
        const updateProgress = (pct) => {
          const job = jobStore.get(jobId)
          if (job) job.progress = pct
        }

        const result = await runPipeline(jobId, req.file.path, req.file.originalname, updateProgress)

        const job = jobStore.get(jobId)
        job.status = 'completed'
        job.progress = 100
        job.result = result

        logger.info('Job completed', { jobId, riskScore: result.riskScore })

      } catch (err) {
        const job = jobStore.get(jobId)
        if (job) {
          job.status = 'failed'
          job.error = err.message
        }
        logger.error('Job failed', { jobId, error: err.message })
      }
    })

    res.status(202).json({
      success: true,
      jobId,
      status: 'active',
      message: 'APK analysis started. Poll /api/status/:jobId for updates.',
      pollUrl: `/api/status/${jobId}`
    })

  } catch (error) {
    logger.error('Upload failed', { error: error.message })
    res.status(500).json({ success: false, error: error.message })
  }
})

// ── Route 2: GET /api/status/:jobId ───────────────────────────────
router.get('/status/:jobId', async (req, res) => {
  const { jobId } = req.params
  const job = jobStore.get(jobId)

  if (!job) {
    return res.status(404).json({
      success: false,
      error: `No job found with ID: ${jobId}`
    })
  }

  const response = {
    success: true,
    jobId,
    status: job.status,
    filename: job.filename,
    progress: job.progress,
    createdAt: job.createdAt
  }

  if (job.status === 'completed') {
    response.result = job.result
    response.reportUrl = `/api/report/${jobId}`
  }

  if (job.status === 'failed') {
    response.error = job.error
  }

  res.json(response)
})

// ── Route 3: GET /api/report/:jobId ───────────────────────────────
router.get('/report/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params
    const format = req.query.format || 'json'

    const outDir = outputDir
    const reportPath = path.join(outDir, `${jobId}.json`)

    if (!existsSync(reportPath)) {
      return res.status(404).json({
        success: false,
        error: 'Report not ready yet. Check /api/status/:jobId first.'
      })
    }

    if (format === 'json') {
      const report = JSON.parse(await readFile(reportPath, 'utf-8'))
      res.json({ success: true, report })
    } else {
      const pdfPath = path.join(outDir, `${jobId}.pdf`)
      if (!existsSync(pdfPath)) {
        return res.status(404).json({ success: false, error: 'PDF not generated yet.' })
      }
      res.download(pdfPath, `apk-sentinel-report-${jobId}.pdf`)
    }

  } catch (error) {
    logger.error('Report fetch failed', { error: error.message })
    res.status(500).json({ success: false, error: error.message })
  }
})

// ── Route 4: GET /api/jobs ─────────────────────────────────────────
// List all jobs (handy for testing)
router.get('/jobs', (req, res) => {
  const jobs = []
  for (const [id, job] of jobStore.entries()) {
    jobs.push({ jobId: id, status: job.status, filename: job.filename, progress: job.progress })
  }
  res.json({ success: true, count: jobs.length, jobs })
})

export default router
