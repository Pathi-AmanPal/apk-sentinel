// =============================================
// core/pipeline.js — Analysis Pipeline Orchestrator
// =============================================
// Runs the 6-stage pipeline, utilizing the combined GenAI engine
// call to optimize speed and bypass rate limits on free-tier keys.
// =============================================

import logger from '../utils/logger.js'
import { analyzeApkStatic } from './staticAnalyzer.js'
import { analyzeApkDynamic } from './dynamicAnalyzer.js'
import { runCombinedGenAiAnalysis } from './genaiEngine.js'
import { computeRiskScore } from './riskScorer.js'
import { generateReport } from './reportGenerator.js'
import { searchSimilarMalware } from '../db/vectorDb.js'

export async function runPipeline(jobId, filePath, filename, updateProgress) {
  logger.info('═══ Pipeline Start ═══', { jobId, filename })
  const t0 = Date.now()

  // Stage 1 – Static analysis
  updateProgress(10, 'Decompiling APK and parsing AndroidManifest.xml...')
  const staticResults = await analyzeApkStatic(filePath, jobId)
  updateProgress(25, 'Analyzing package signature, permissions and strings...')

  // Stage 2 – Dynamic analysis
  updateProgress(35, 'Initializing temporal sandbox environments...')
  const dynamicResults = await analyzeApkDynamic(filePath, jobId, staticResults)
  updateProgress(55, 'Running dynamic evasion and intent-spoofing tests...')

  // Stage 3 – Combined GenAI Analysis (all 5 pillars in 1 call to avoid 429 rate limits)
  updateProgress(65, 'Consulting Gemini GenAI engine for 5-pillar verdict...')
  logger.info('Invoking Combined Gemini Analysis...', { jobId })
  const genAiResults = await runCombinedGenAiAnalysis(staticResults, dynamicResults, jobId)
  updateProgress(80, 'Analyzing threat vectors and computing risk matrix...')

  // Stage 4 – Extract pillars
  const { pillar1, pillar2, pillar3, pillar4, pillar5 } = genAiResults
  const pillarResults = { pillar1, pillar2, pillar3, pillar4, pillar5 }

  // Stage 5 – Risk score + vector DB
  const intentText = pillar2.actualPurpose || pillar2.attackChainSummary || filename
  const vectorMatch = await searchSimilarMalware(intentText, jobId)
  const riskScore = computeRiskScore(staticResults, dynamicResults, pillarResults, vectorMatch)
  updateProgress(90, 'Generating audit-ready PDF and JSON reports...')

  // Stage 6 – Save JSON + PDF
  await generateReport(jobId, staticResults, dynamicResults, pillarResults, riskScore)
  updateProgress(100, 'Analysis completed successfully.')

  const duration = ((Date.now() - t0) / 1000).toFixed(1)
  logger.info('═══ Pipeline Complete ═══', { jobId, riskScore: riskScore.score, duration })

  return {
    jobId, filename,
    riskScore: riskScore.score,
    severity: riskScore.severity,
    recommendation: riskScore.recommendation,
    vectorMatch: vectorMatch?.matched ? vectorMatch.matchedFamily : null,
    durationSeconds: parseFloat(duration),
    reportUrl: `/api/report/${jobId}`
  }
}
