// =============================================
// workers/analysisWorker.js — BullMQ Pipeline Worker
// =============================================
//
// THIS IS THE CORE ORCHESTRATOR.
// This file runs the entire analysis pipeline for every APK job.
//
// HOW THE WORKER PATTERN WORKS:
//   1. routes/analysis.js → adds a job to the Redis queue (via BullMQ)
//   2. This worker is ALWAYS RUNNING in the background, watching the queue
//   3. When a job appears, the worker picks it up and runs processJob()
//   4. processJob() calls all 5 pillars in order and saves the result
//   5. The job is marked "completed" in BullMQ/Redis
//   6. The /api/status route can now return "completed" + the result
//
// RUN THIS SEPARATELY:
//   npm run worker   (in a second terminal)
//
// WHY SEPARATE PROCESS?
// The worker is CPU/time-intensive (runs 30-60 seconds per APK).
// Running it in the same process as the web server would block all requests.
// Separate process = server stays fast, worker can take its time.
//
// JOB PROGRESS:
// We update job.updateProgress(N) throughout so the frontend can show
// a progress bar via /api/status/:jobId
// =============================================

import 'dotenv/config'
import { Worker } from 'bullmq'
import logger from '../utils/logger.js'
import { analyzeApkStatic } from '../core/staticAnalyzer.js'
import { analyzeApkDynamic } from '../core/dynamicAnalyzer.js'
import {
  pillar1_identityGapAnalysis,
  pillar2_codeDeobfuscation,
  pillar3_attackGraphClassify,
  pillar4_narrativeReport,
  pillar5_spoofingAnalysis
} from '../core/genaiEngine.js'
import { computeRiskScore } from '../core/riskScorer.js'
import { generateReport } from '../core/reportGenerator.js'
import { searchSimilarMalware } from '../db/vectorDb.js'

// =============================================
// CREATE THE WORKER
// Worker watches the 'apk-analysis' queue in Redis
// When a job arrives, it calls the processJob function
// =============================================
const worker = new Worker(
  'apk-analysis',    // queue name — must match what routes/analysis.js uses
  processJob,        // the function to call for each job
  {
    connection: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379
    },
    concurrency: 2   // process up to 2 APKs simultaneously
  }
)

// =============================================
// MAIN PIPELINE: processJob()
// This runs for every APK analysis job.
// Each step = one stage in our 5-pillar pipeline.
// =============================================
async function processJob(job) {
  const { jobId, filePath, filename } = job.data

  logger.info('═══ Starting APK Analysis Pipeline ═══', { jobId, filename })
  const startTime = Date.now()

  try {

    // ── STAGE 1: Static Analysis (10% → 25%) ────────────────────
    // Decompile APK, extract manifest, permissions, suspicious strings
    await job.updateProgress(10)
    logger.info('Stage 1/6: Static analysis', { jobId })

    const staticResults = await analyzeApkStatic(filePath, jobId)
    await job.updateProgress(25)


    // ── STAGE 2: Dynamic Analysis (25% → 45%) ───────────────────
    // Run in sandbox, hook APIs with Frida, capture network traffic
    await job.updateProgress(25)
    logger.info('Stage 2/6: Dynamic analysis', { jobId })

    const dynamicResults = await analyzeApkDynamic(filePath, jobId, staticResults)
    await job.updateProgress(45)


    // ── STAGE 3: GenAI Pillars 1 & 2 (45% → 65%) ────────────────
    // Run identity gap analysis and code deobfuscation in parallel
    // Promise.all() runs both at the same time (parallel API calls)
    logger.info('Stage 3/6: GenAI Pillars 1 & 2 (identity + deobfuscation)', { jobId })

    const [pillar1, pillar2] = await Promise.all([
      pillar1_identityGapAnalysis(staticResults, jobId),
      pillar2_codeDeobfuscation(staticResults, jobId)
    ])
    await job.updateProgress(60)


    // ── STAGE 4: GenAI Pillars 3 & 5 (65% → 75%) ────────────────
    // Attack graph classification + spoofing analysis
    logger.info('Stage 4/6: GenAI Pillars 3 & 5 (attack graph + spoofing)', { jobId })

    const [pillar3, pillar5] = await Promise.all([
      pillar3_attackGraphClassify(dynamicResults, jobId),
      pillar5_spoofingAnalysis(dynamicResults, jobId)
    ])
    await job.updateProgress(75)


    // ── STAGE 5: Risk Scoring + Vector DB (75% → 85%) ────────────
    // Score the risk and check against known malware database
    logger.info('Stage 5/6: Risk scoring + vector DB search', { jobId })

    // Semantic search: does this APK's intent match known malware?
    const intentText = pillar2.actualPurpose || pillar2.attackChainSummary || filename
    const vectorMatch = await searchSimilarMalware(intentText, jobId)

    const pillarResults = { pillar1, pillar2, pillar3, pillar5 }
    const riskScore = computeRiskScore(staticResults, dynamicResults, pillarResults, vectorMatch)
    await job.updateProgress(80)


    // ── STAGE 6: GenAI Pillar 4 — Narrative Report (85% → 95%) ──
    // Generate human-readable narrative AFTER we have the risk score
    // (So Claude knows the score when writing the narrative)
    logger.info('Stage 6/6: GenAI Pillar 4 (narrative report)', { jobId })

    const pillar4 = await pillar4_narrativeReport(pillarResults, riskScore, jobId)
    pillarResults.pillar4 = pillar4
    await job.updateProgress(90)


    // ── FINAL: Save Reports (95% → 100%) ─────────────────────────
    logger.info('Saving JSON + PDF reports', { jobId })

    const { report } = await generateReport(
      jobId,
      staticResults,
      dynamicResults,
      pillarResults,
      riskScore
    )
    await job.updateProgress(100)

    const durationSeconds = ((Date.now() - startTime) / 1000).toFixed(1)

    logger.info('═══ Analysis Pipeline Complete ═══', {
      jobId,
      filename,
      riskScore: riskScore.score,
      severity: riskScore.severity,
      recommendation: riskScore.recommendation,
      durationSeconds
    })

    // Return value is stored in BullMQ and accessible via /api/status/:jobId
    return {
      jobId,
      filename,
      riskScore: riskScore.score,
      severity: riskScore.severity,
      recommendation: riskScore.recommendation,
      vectorMatch: vectorMatch.matched ? vectorMatch.matchedFamily : null,
      durationSeconds: parseFloat(durationSeconds),
      reportUrl: `/api/report/${jobId}`
    }

  } catch (error) {
    logger.error('Pipeline failed', { jobId, error: error.message, stack: error.stack })
    throw error  // BullMQ will mark the job as failed and retry if configured
  }
}

// ── Worker Event Handlers ──────────────────────────────────────────
// These log what's happening with the queue

worker.on('completed', (job, result) => {
  logger.info('Job completed ✅', {
    jobId: job.id,
    riskScore: result?.riskScore,
    severity: result?.severity
  })
})

worker.on('failed', (job, error) => {
  logger.error('Job failed ❌', {
    jobId: job?.id,
    error: error.message,
    attempts: job?.attemptsMade
  })
})

worker.on('progress', (job, progress) => {
  logger.debug('Job progress', { jobId: job.id, progress: `${progress}%` })
})

worker.on('error', (error) => {
  logger.error('Worker error', { error: error.message })
})

logger.info('🔧 APK Analysis Worker started — waiting for jobs...')
logger.info(`Connected to Redis at ${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`)
