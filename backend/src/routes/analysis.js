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
import { generatePDFStream } from '../core/reportGenerator.js'

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
    const jobId = uuidv4()
    let filename
    let filePath
    let fileSizeStr

    if (req.file) {
      filename = req.file.originalname
      filePath = req.file.path
      fileSizeStr = `${(req.file.size / 1024 / 1024).toFixed(2)} MB`
    } else if (req.body && req.body.filename) {
      filename = req.body.filename
      filePath = path.join(uploadDir, `stub-${jobId}-${filename}`)
      const sizeBytes = req.body.fileSize || 0
      fileSizeStr = `${(sizeBytes / 1024 / 1024).toFixed(2)} MB`
    } else {
      return res.status(400).json({
        success: false,
        error: 'No APK file uploaded and no filename metadata provided.'
      })
    }

    logger.info('APK target identified, starting analysis job', {
      jobId,
      filename,
      size: fileSizeStr
    })

    // Store active state in memory initially
    jobStore.set(jobId, {
      status: 'active',
      progress: 0,
      filename,
      filePath,
      createdAt: new Date().toISOString(),
      result: null,
      error: null
    })

    // Run pipeline synchronously on the request
    let result
    try {
      result = await runPipeline(jobId, filePath, filename, () => {})
      jobStore.set(jobId, {
        status: 'completed',
        progress: 100,
        filename,
        filePath,
        createdAt: new Date().toISOString(),
        result,
        error: null
      })
      logger.info('Job completed synchronously', { jobId, riskScore: result.riskScore })
    } catch (err) {
      jobStore.set(jobId, {
        status: 'failed',
        progress: 0,
        filename,
        filePath,
        createdAt: new Date().toISOString(),
        result: null,
        error: err.message
      })
      logger.error('Job failed synchronously', { jobId, error: err.message })
      throw err
    }

    res.status(200).json({
      success: true,
      jobId,
      status: 'completed',
      message: 'APK analysis completed successfully.',
      result
    })

  } catch (error) {
    logger.error('Upload/analysis failed', { error: error.message })
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

// ── Route 5: POST /api/report/pdf ──────────────────────────────────
router.post('/report/pdf', async (req, res) => {
  try {
    const { jobId, report } = req.body
    if (!report) {
      return res.status(400).json({ success: false, error: 'No report data provided.' })
    }

    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Disposition', `attachment; filename=apk-sentinel-report-${jobId}.pdf`)

    generatePDFStream(report, res)
  } catch (error) {
    logger.error('PDF generation failed', { error: error.message })
    res.status(500).json({ success: false, error: error.message })
  }
})

export default router
