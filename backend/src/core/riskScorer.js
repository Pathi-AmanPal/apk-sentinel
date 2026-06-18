// =============================================
// core/riskScorer.js — Composite Risk Scoring
// =============================================
//
// WHAT IS RISK SCORING?
// We take all findings from the 5 pillars and combine them into
// a single 0-100 score that tells the bank how dangerous this APK is.
//
// WHY NOT JUST USE THE AI SCORE?
// AI scores alone are subjective. A composite score that weights
// multiple data sources is more reliable and auditable.
//
// SCORING BREAKDOWN:
//   30 pts → Static analysis (permissions, certificate, strings)
//   25 pts → Dynamic analysis (C2 connections, data exfiltration)
//   25 pts → Pillar 1 identity gap score (scaled to 25)
//   10 pts → Pillar 5 stealth rating (hard to detect = more dangerous)
//   10 pts → Vector DB match (known malware family = auto high score)
//
// SEVERITY THRESHOLDS:
//   0-25:   Low       (likely safe)
//   26-50:  Medium    (suspicious, review manually)
//   51-75:  High      (likely malicious)
//   76-100: Critical  (confirmed malicious — block immediately)
// =============================================

import logger from '../utils/logger.js'

// =============================================
// MAIN EXPORT: computeRiskScore()
// Input:  all analysis results from all pillars
// Output: { score, severity, breakdown, recommendation }
// =============================================
export function computeRiskScore(staticResults, dynamicResults, pillarResults, vectorMatch) {
  const breakdown = {}

  // ── 1. Static Score (0-30 points) ─────────────────────────────
  let staticScore = 0
  const { summary: staticSummary, certificate } = staticResults

  // Critical permissions: +5 each, max 15
  staticScore += Math.min(staticSummary.criticalPermissions * 5, 15)

  // High risk permissions: +2 each, max 6
  staticScore += Math.min(staticSummary.highRiskPermissions * 2, 6)

  // Suspicious strings: +1 each, max 5
  staticScore += Math.min(staticSummary.suspiciousStringsCount, 5)

  // Debug certificate = +4 (not from Play Store)
  if (certificate.isDebugCert) staticScore += 4

  breakdown.staticScore = Math.min(staticScore, 30)

  // ── 2. Dynamic Score (0-25 points) ────────────────────────────
  let dynamicScore = 0
  const { summary: dynSummary } = dynamicResults

  if (dynSummary.credentialsExfiltrated) dynamicScore += 10
  if (dynSummary.otpIntercepted)         dynamicScore += 8
  if (dynSummary.overlayAttack)          dynamicScore += 3
  if (dynSummary.persistenceMechanism)   dynamicScore += 2
  if (dynSummary.dynamicCodeLoading)     dynamicScore += 2

  breakdown.dynamicScore = Math.min(dynamicScore, 25)

  // ── 3. Identity Gap Score (0-25 points) ───────────────────────
  // Claude returned a 0-100 score — scale it to 0-25
  const identityGap = pillarResults.pillar1?.identityGapScore || 0
  breakdown.identityGapScore = Math.round((identityGap / 100) * 25)

  // ── 4. Stealth Rating (0-10 points) ───────────────────────────
  const stealthMap = { LOW: 0, MEDIUM: 3, HIGH: 7, VERY_HIGH: 10 }
  const stealth = pillarResults.pillar5?.stealthRating || 'LOW'
  breakdown.stealthScore = stealthMap[stealth] || 0

  // ── 5. Vector DB Match (0-10 points) ──────────────────────────
  // If this APK matches known malware in our database — big bonus score
  breakdown.vectorMatchScore = vectorMatch?.similarity > 0.85 ? 10 :
                               vectorMatch?.similarity > 0.7  ? 6  :
                               vectorMatch?.similarity > 0.5  ? 3  : 0

  // ── Final Score ────────────────────────────────────────────────
  const totalScore = Object.values(breakdown).reduce((sum, v) => sum + v, 0)
  const score = Math.min(Math.round(totalScore), 100)

  // ── Severity Label ─────────────────────────────────────────────
  const severity = score >= 76 ? 'CRITICAL' :
                   score >= 51 ? 'HIGH'     :
                   score >= 26 ? 'MEDIUM'   : 'LOW'

  // ── Recommendation ─────────────────────────────────────────────
  const recommendation = score >= 76 ? 'BLOCK_IMMEDIATELY' :
                         score >= 51 ? 'QUARANTINE'        :
                         score >= 26 ? 'MONITOR'           : 'WHITELIST'

  const result = {
    score,
    severity,
    recommendation,
    breakdown,
    interpretation: getInterpretation(score, severity),
    vectorMatch: vectorMatch || null
  }

  logger.info('Risk score computed', { score, severity, recommendation })

  return result
}

function getInterpretation(score, severity) {
  const interpretations = {
    CRITICAL: `Risk score ${score}/100. This APK is almost certainly malicious. Multiple critical indicators found including credential theft, OTP interception, and C2 communication. Immediate action required.`,
    HIGH: `Risk score ${score}/100. This APK shows strong indicators of malicious behavior. Quarantine and manual review recommended before allowing any transactions.`,
    MEDIUM: `Risk score ${score}/100. This APK has suspicious characteristics that warrant investigation. May be legitimate but has unusual permission requests.`,
    LOW: `Risk score ${score}/100. No significant red flags detected. APK appears consistent with its claimed identity.`
  }
  return interpretations[severity]
}
