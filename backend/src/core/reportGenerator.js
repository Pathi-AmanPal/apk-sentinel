// =============================================
// core/reportGenerator.js — JSON + PDF Reports
// =============================================
//
// WHAT THIS FILE DOES:
// Takes all analysis results and:
//   1. Saves a structured JSON report to output/{jobId}.json
//   2. Generates a PDF using PDFKit for download
//
// WHY JSON AND PDF?
//   - JSON → for the frontend dashboard to consume via API
//   - PDF  → for investigators to download, print, file as evidence
//
// PDFKIT:
//   PDFKit is a JavaScript library for creating PDF files from code.
//   You programmatically say: "add a title", "add a paragraph", "add a table".
//   It's like drawing on paper — you position everything manually.
// =============================================

import PDFDocument from 'pdfkit'
import { writeFile, createWriteStream } from 'fs'
import { promisify } from 'util'
import path from 'path'
import logger from '../utils/logger.js'

const writeFileAsync = promisify(writeFile)

// =============================================
// MAIN EXPORT: generateReport()
// Saves both JSON and PDF reports
// =============================================
export async function generateReport(jobId, staticResults, dynamicResults, pillarResults, riskScore) {
  logger.info('Generating reports', { jobId })

  const isVercel = !!process.env.VERCEL
  const outputDir = isVercel ? '/tmp' : (process.env.OUTPUT_DIR || './output')

  // Assemble the full report object
  const report = {
    meta: {
      jobId,
      generatedAt: new Date().toISOString(),
      analysisVersion: '1.0.0',
      filename: staticResults.filename
    },

    // The final verdict — what the investigator needs first
    verdict: {
      riskScore: riskScore.score,
      severity: riskScore.severity,
      recommendation: riskScore.recommendation,
      interpretation: riskScore.interpretation
    },

    // The human-readable narrative (from Pillar 4)
    narrative: pillarResults.pillar4 || null,

    // Raw data from each analysis stage
    staticAnalysis: staticResults,
    dynamicAnalysis: dynamicResults,

    // GenAI pillar outputs
    genaiAnalysis: {
      identityGapAnalysis: pillarResults.pillar1,
      codeDeobfuscation:   pillarResults.pillar2,
      attackClassification: pillarResults.pillar3,
      spoofingAnalysis:    pillarResults.pillar5
    },

    // Risk breakdown for transparency
    riskBreakdown: riskScore.breakdown
  }

  // ── Save JSON ───────────────────────────────────────────────────
  const jsonPath = path.join(outputDir, `${jobId}.json`)
  await writeFileAsync(jsonPath, JSON.stringify(report, null, 2))
  logger.info('JSON report saved', { path: jsonPath })

  // ── Generate PDF ────────────────────────────────────────────────
  const pdfPath = path.join(outputDir, `${jobId}.pdf`)
  await generatePDF(report, pdfPath)
  logger.info('PDF report saved', { path: pdfPath })

  return { jsonPath, pdfPath, report }
}

// =============================================
// PDF GENERATOR using PDFKit
// =============================================
function generatePDF(report, outputPath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 })
    const stream = doc.pipe(createWriteStream(outputPath))

    // Colors
    const RED    = '#E53E3E'
    const ORANGE = '#DD6B20'
    const BLUE   = '#2B6CB0'
    const DARK   = '#1A202C'
    const GRAY   = '#718096'

    // ── PAGE 1: Cover ───────────────────────────────────────────
    // Logo / Title area
    doc.rect(0, 0, 612, 120).fill('#1A202C')
    doc.fillColor('white')
      .fontSize(28).font('Helvetica-Bold')
      .text('APK SENTINEL', 50, 30)
    doc.fontSize(12).font('Helvetica')
      .text('Threat Analysis Report', 50, 65)
    doc.fontSize(10)
      .text(`Generated: ${new Date(report.meta.generatedAt).toLocaleString()}`, 50, 85)

    // Risk Score Badge
    const scoreColor = report.verdict.severity === 'CRITICAL' ? RED :
                       report.verdict.severity === 'HIGH' ? ORANGE : BLUE
    doc.roundedRect(430, 25, 130, 75, 8).fill(scoreColor)
    doc.fillColor('white')
      .fontSize(40).font('Helvetica-Bold')
      .text(report.verdict.riskScore, 445, 35, { align: 'center', width: 100 })
    doc.fontSize(10).font('Helvetica')
      .text(report.verdict.severity, 445, 78, { align: 'center', width: 100 })

    // ── Executive Summary Section ────────────────────────────────
    doc.moveDown(4).fillColor(DARK)
    doc.fontSize(16).font('Helvetica-Bold').text('Executive Summary')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    doc.fontSize(11).font('Helvetica')
      .fillColor(DARK)
      .text(report.narrative?.executiveSummary || 'Analysis complete. See details below.', {
        paragraphGap: 5, lineGap: 3
      })

    // ── Threat Narrative ─────────────────────────────────────────
    doc.moveDown(1.5)
    doc.fontSize(14).font('Helvetica-Bold').fillColor(DARK).text('Threat Narrative')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    doc.fontSize(11).font('Helvetica').fillColor(DARK)
      .text(report.narrative?.threatNarrative || 'See full JSON report for details.', {
        paragraphGap: 5, lineGap: 3
      })

    // ── Recommendation Box ───────────────────────────────────────
    doc.moveDown(1.5)
    doc.rect(50, doc.y, 512, 60).fill(scoreColor)
    doc.fillColor('white')
      .fontSize(14).font('Helvetica-Bold')
      .text(`RECOMMENDATION: ${report.verdict.recommendation}`, 65, doc.y - 50, { width: 480 })
    doc.fontSize(10).font('Helvetica')
      .text(report.narrative?.recommendationReasoning || '', 65, doc.y - 30, { width: 480 })

    // ── Risk Breakdown ────────────────────────────────────────────
    doc.moveDown(4.5).fillColor(DARK)
    doc.fontSize(14).font('Helvetica-Bold').text('Risk Score Breakdown')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    const breakdown = report.riskBreakdown || {}
    const entries = [
      ['Static Analysis (permissions, certificate)', breakdown.staticScore, 30],
      ['Dynamic Analysis (C2, exfiltration)', breakdown.dynamicScore, 25],
      ['Identity Gap Score', breakdown.identityGapScore, 25],
      ['Stealth Rating', breakdown.stealthScore, 10],
      ['Known Malware Match', breakdown.vectorMatchScore, 10]
    ]

    for (const [label, score, maxScore] of entries) {
      doc.fontSize(10).font('Helvetica').fillColor(DARK)
        .text(`${label}:`, 50, doc.y + 8)
      doc.fontSize(10).font('Helvetica-Bold')
        .text(`${score || 0} / ${maxScore}`, 400, doc.y - 14, { align: 'right', width: 162 })

      // Progress bar
      const barWidth = 250
      const filled = Math.round(((score || 0) / maxScore) * barWidth)
      doc.rect(50, doc.y + 2, barWidth, 8).fill('#EDF2F7')
      doc.rect(50, doc.y + 2, filled, 8).fill(scoreColor)
      doc.moveDown(0.8)
    }

    // ── Evidence Highlights ───────────────────────────────────────
    doc.addPage()
    doc.fontSize(16).font('Helvetica-Bold').fillColor(DARK).text('Evidence Highlights')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    const evidence = report.narrative?.evidenceHighlights || []
    for (const item of evidence) {
      doc.fontSize(10).font('Helvetica').fillColor(DARK)
        .text(`• ${item}`, { indent: 10, paragraphGap: 4 })
    }

    // ── Temporal Attack Timeline ──────────────────────────────────
    doc.moveDown(1.5)
    doc.fontSize(14).font('Helvetica-Bold').fillColor(DARK).text('Temporal Attack Timeline')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    const timeline = report.dynamicAnalysis?.temporalAttackGraph || []
    for (const event of timeline) {
      const eventColor = event.risk === 'critical' ? RED :
                         event.risk === 'high' ? ORANGE : GRAY
      doc.fontSize(9).font('Helvetica-Bold').fillColor(eventColor)
        .text(`T+${event.T}s [${event.risk?.toUpperCase()}] ${event.event}`)
      doc.fontSize(9).font('Helvetica').fillColor(DARK)
        .text(`   ${event.description}`, { indent: 10 })
      doc.moveDown(0.3)
    }

    // ── Investigator Checklist ────────────────────────────────────
    doc.moveDown(1.5)
    doc.fontSize(14).font('Helvetica-Bold').fillColor(DARK).text('Investigator Checklist')
    doc.moveTo(50, doc.y + 3).lineTo(562, doc.y + 3).stroke(GRAY)
    doc.moveDown(0.5)

    const checklist = report.narrative?.investigatorChecklist || []
    checklist.forEach((item, i) => {
      doc.fontSize(10).font('Helvetica').fillColor(DARK)
        .text(`${i + 1}. ${item}`, { indent: 10, paragraphGap: 4 })
    })

    // ── Footer ────────────────────────────────────────────────────
    doc.fontSize(8).fillColor(GRAY)
      .text(`APK Sentinel v1.0 | Job ID: ${report.meta.jobId} | CONFIDENTIAL`,
        50, 780, { align: 'center', width: 512 })

    // Finalize
    doc.end()
    stream.on('finish', resolve)
    stream.on('error', reject)
  })
}
