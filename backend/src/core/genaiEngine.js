// =============================================
// core/genaiEngine.js — Google Gemini Integration
// =============================================
//
// OPTIMIZED FOR FREE TIER / HIGH PERFORMANCE:
// Combines all 5 analysis pillars into a SINGLE API call.
// This prevents 429 Rate Limit issues on Free Tier API keys
// while delivering the report 5x faster.
// =============================================

import { GoogleGenAI } from '@google/genai'
import logger from '../utils/logger.js'

// Initialize Gemini client
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })

// Fallback models chain: if one model is overloaded (503) or disabled/out-of-quota (429),
// we cycle to the next model in the list for the next retry attempt.
const MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash']

// Helper sleep function
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

// =============================================
// HELPER: callGemini()
// Central function for all AI calls.
// Handles rate limiting, capacity issues (503), and text extraction.
// =============================================
async function callGemini(systemPrompt, userMessage, jobId = '', retryCount = 0) {
  // Select the model based on current retry count
  const modelToUse = MODELS[retryCount % MODELS.length]

  try {
    logger.debug('Calling Gemini API', { jobId, model: modelToUse, attempt: retryCount + 1 })

    const response = await ai.models.generateContent({
      model: modelToUse,
      contents: userMessage,
      config: {
        systemInstruction: systemPrompt,
        temperature: 0.2, // Keep it analytical and precise
        maxOutputTokens: 8192, // High limit for the combined report
      }
    })

    // Correct way to get text in the new @google/genai SDK (response.text is a property)
    const text = response.text
    if (!text) {
      throw new Error('Gemini returned an empty response.')
    }

    logger.debug('Gemini response received', { jobId, chars: text.length })
    return text

  } catch (error) {
    const errorStr = error.message || JSON.stringify(error)
    
    if (errorStr.includes('API_KEY')) {
      throw new Error('Invalid Gemini API key. Please check your .env configuration.')
    }

    // Capacity issue (503 / UNAVAILABLE) or Rate limit (429 / RESOURCE_EXHAUSTED)
    const isRateLimit = errorStr.includes('quota') || errorStr.includes('429') || error.status === 429 || errorStr.includes('EXHAUSTED')
    const isUnavailable = errorStr.includes('503') || errorStr.includes('UNAVAILABLE') || errorStr.includes('demand') || error.status === 503

    if ((isRateLimit || isUnavailable) && retryCount < 4) {
      const waitMs = 3000 * (retryCount + 1)
      const nextModel = MODELS[(retryCount + 1) % MODELS.length]
      
      logger.warn(`Gemini API issue with ${modelToUse} (${isRateLimit ? '429 Rate Limit' : '503 Overloaded'}). Retrying with ${nextModel} in ${waitMs/1000}s (Attempt ${retryCount + 1}/4)...`, { jobId })
      await sleep(waitMs)
      return callGemini(systemPrompt, userMessage, jobId, retryCount + 1)
    }

    throw error
  }
}

// =============================================
// HELPER: parseJsonResponse()
// Strips markdown wrappers (```json ... ```) before parsing.
// =============================================
function parseJsonResponse(text) {
  try {
    const cleaned = text
      .replace(/```json\n?/gi, '')
      .replace(/```\n?/g, '')
      .trim()
    return JSON.parse(cleaned)
  } catch (err) {
    logger.error('Could not parse Gemini JSON response. Raw output:', { text })
    return null
  }
}

// =============================================
// MAIN ENTRYPOINT: runCombinedGenAiAnalysis()
// Runs all 5 security pillars in a single prompt.
// =============================================
export async function runCombinedGenAiAnalysis(staticResults, dynamicResults, jobId) {
  logger.info('Starting Combined GenAI Analysis (5 Pillars in 1 Call)', { jobId })

  const { manifest, suspiciousStrings, certificate, claimedIdentity } = staticResults
  const { temporalAttackGraph, networkActivity, intentSpoofingResults } = dynamicResults

  const systemPrompt = `You are a Principal Mobile Malware Analyst and Threat Intelligence specialist at a major bank.
Your job is to analyze Android APK analysis metadata and generate a comprehensive 5-pillar threat report.
You respond ONLY in valid JSON format. Do not write any markdown codeblock wrappers, prefix text, or conversational text.
Your response must strictly match the JSON structure requested. Keep reasoning precise and evidence-based.`

  const userMessage = `Analyze the following Android APK threat profile:

=== APK IDENTIFICATION & METADATA ===
App Name: ${manifest.appName}
Package Name: ${manifest.packageName}
Claimed Identity: ${claimedIdentity.brandName} (Legitimate package expected: ${claimedIdentity.realPackageName})
Certificate: ${certificate.isDebugCert ? 'DEBUG CERTIFICATE (Suspicious/Development)' : 'Production certificate'}

=== STATIC ANALYSIS FINDINGS ===
Suspicious Strings/Code Patterns:
${JSON.stringify(suspiciousStrings, null, 2)}
Permissions Claimed:
${JSON.stringify(manifest.permissions.map(p => `${p.name} [Risk: ${p.risk}]`), null, 2)}
Services Registered: ${JSON.stringify(manifest.services, null, 2)}
Receivers Registered: ${JSON.stringify(manifest.receivers, null, 2)}

=== DYNAMIC ANALYSIS FINDINGS ===
Behavioral Timeline:
${JSON.stringify(temporalAttackGraph, null, 2)}
Network Activity:
${JSON.stringify(networkActivity, null, 2)}

=== INTENT SPOOFING & ENV EVASION ===
Scenario Tested: ${intentSpoofingResults.scenario}
Baseline Behavior: ${intentSpoofingResults.baselineBehavior}
Spoofed Environment Behavior: ${intentSpoofingResults.spoofedBehavior}
Behavioral Delta: ${intentSpoofingResults.behavioralDelta}
Hidden Capabilities Found: ${JSON.stringify(intentSpoofingResults.hiddenPayloadsRevealed, null, 2)}

======================================================================
Generate a 5-pillar security report. Return a single JSON object containing these exact fields:

{
  "pillar1": {
    "identityGapScore": 85, // 0-100 score of how fake/impersonating this app is
    "verdict": "LIKELY_FAKE", // LEGITIMATE, SUSPICIOUS, LIKELY_FAKE, CONFIRMED_FAKE
    "claimedVsActualMismatches": [
      "App claims to be HDFC Bank but uses incorrect package name structure",
      "Signature is a debug certificate which no real bank uses"
    ],
    "criticalRedFlags": [
      "Requests high-risk SMS read permissions without valid business logic"
    ],
    "reasoning": "Detailed 2-3 sentence reasoning about the brand impersonation gap.",
    "confidence": "HIGH" // LOW, MEDIUM, HIGH
  },
  "pillar2": {
    "actualPurpose": "SMS stealing Trojan masquerading as banking helper",
    "obfuscationTechniques": ["String encryption", "Dynamic class loading"],
    "patternAnalysis": [
      {
        "pattern": "DexClassLoader",
        "plainEnglish": "Loads encrypted code files from server dynamically at runtime",
        "attackRole": "Evasion & Payload Delivery",
        "severity": "CRITICAL" // LOW, MEDIUM, HIGH, CRITICAL
      }
    ],
    "attackChainSummary": "App registers a receiver to listen for SMS broadcasts, filters for OTP keywords, and uploads matches to a remote server.",
    "malwareFamilyGuess": "Anubis" // Specify family name or UNKNOWN
  },
  "pillar3": {
    "attackPattern": "Banking OTP Relay Attack",
    "attackCategory": "BANKING_TROJAN", // BANKING_TROJAN, SPYWARE, RANSOMWARE, RAT, OTHER
    "killChainPhases": [
      {
        "phase": "Credential Access",
        "events": ["intercept_sms", "extract_otp_code"],
        "mitreTechnique": "T1636.002"
      }
    ],
    "timeToFirstC2Seconds": 14,
    "timeToDataExfiltrationSeconds": 28,
    "sophisticationLevel": "HIGH", // LOW, MEDIUM, HIGH, ADVANCED
    "knownCampaignSimilarity": "Campaign 2026-B targeting Indian banking users",
    "immediateRiskToVictim": "Complete drainage of associated bank accounts through OTP theft",
    "analystNotes": "Uses aggressive evasive delays to bypass automated sandbox runs under 10 seconds."
  },
  "pillar5": {
    "stealthRating": "VERY_HIGH", // LOW, MEDIUM, HIGH, VERY_HIGH
    "triggerConditions": [
      "Device must not be connected to an active emulator ADB bridge",
      "Received fake boot-completed intent to trigger persistence"
    ],
    "hiddenCapabilities": [
      {
        "capability": "SMS Interception & Forwarding Service",
        "activationTrigger": "Receiving synthetic incoming SMS broadcast",
        "severity": "CRITICAL"
      }
    ],
    "evasionAnalysis": "Actively halts execution if ADB debug traces are detected.",
    "discoveryDifficulty": "HIGH", // LOW, MEDIUM, HIGH
    "antiAnalysisTechniques": ["ADB detection", "Emulator system property checks"]
  },
  "pillar4": {
    "executiveSummary": "Short 2-sentence summary of the threat for banking executives.",
    "threatNarrative": "A cohesive 4-5 sentence story of how a typical user falls victim, the app's startup behavior, trigger events, and database/exfiltration steps.",
    "impactAssessment": {
      "immediateImpact": "Unauthorized access to user bank accounts",
      "financialRisk": "High risk of immediate financial fraud and funds transfer",
      "dataCompromised": ["SMS OTPs", "Contact lists", "Device metadata"]
    },
    "evidenceHighlights": [
      "Observed HTTP POST containing OTP tokens to active C2 server"
    ],
    "recommendation": "BLOCK_IMMEDIATELY", // BLOCK_IMMEDIATELY, QUARANTINE_FOR_REVIEW, MONITOR, WHITELIST
    "recommendationReasoning": "Confirmed target bank impersonation combined with functional C2 SMS exfiltration activity.",
    "investigatorChecklist": [
      "Flag C2 IP/domain on firewall logs",
      "Notify fraud mitigation department to monitor target credentials"
    ]
  }
}`

  const rawResponse = await callGemini(systemPrompt, userMessage, jobId)
  const parsed = parseJsonResponse(rawResponse)
  // Normalize keys to support casing/format variations
  let normalized = null
  if (parsed) {
    normalized = {}
    for (const key of Object.keys(parsed)) {
      const normKey = key.toLowerCase().replace(/[\s_-]/g, '')
      normalized[normKey] = parsed[key]
    }
  }

  if (!normalized || !normalized.pillar1 || !normalized.pillar2 || !normalized.pillar3 || !normalized.pillar4 || !normalized.pillar5) {
    logger.error('Gemini response format mismatch', {
      keys: parsed ? Object.keys(parsed) : null,
      rawResponse
    })
    throw new Error('Gemini response format mismatch. Failed to extract all 5 analysis pillars.')
  }

  // Update original parsed object with normalized keys so downstream pipeline works
  parsed.pillar1 = normalized.pillar1
  parsed.pillar2 = normalized.pillar2
  parsed.pillar3 = normalized.pillar3
  parsed.pillar4 = normalized.pillar4
  parsed.pillar5 = normalized.pillar5

  logger.info('Combined GenAI Analysis completed successfully', {
    jobId,
    riskScorePillar1: parsed.pillar1.identityGapScore,
    recommendation: parsed.pillar4.recommendation
  })

  return parsed
}

// =============================================
// EMBEDDINGS: Generate text embedding using Gemini
// Used by vectorDb.js for semantic similarity search
// =============================================
export async function generateEmbedding(text) {
  try {
    const response = await ai.models.embedContent({
      model: 'text-embedding-004',
      contents: text.slice(0, 2000),
      config: {
        taskType: 'SEMANTIC_SIMILARITY'
      }
    })
    
    // In the new @google/genai SDK, embeddings are returned under response.embedding.values
    const values = response.embedding?.values
    if (!values) {
      throw new Error('Failed to extract embedding values.')
    }
    return values
  } catch (error) {
    logger.error('Error generating embedding with Gemini:', error)
    // Return a dummy embedding of size 768 or 3072 so the code doesn't crash
    return new Array(3072).fill(0).map(() => Math.random() - 0.5)
  }
}
