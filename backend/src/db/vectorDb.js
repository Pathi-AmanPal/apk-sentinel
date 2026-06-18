// =============================================
// db/vectorDb.js — Qdrant Vector Database Client
// =============================================
//
// WHAT IS A VECTOR DATABASE?
// Normal databases search by EXACT match: "WHERE name = 'HDFC'"
// Vector databases search by MEANING SIMILARITY.
//
// HOW IT WORKS:
//   1. You take a piece of text (e.g., a code intent description)
//   2. Run it through an "embedding model" — converts text to a list of 1024 numbers
//      This list of numbers = "vector" = captures the MEANING of the text
//   3. Store the vector in Qdrant
//   4. To search: convert query text to vector, find vectors that are "close" (similar)
//
// WHY DO WE NEED THIS?
// Two different APKs might steal OTPs in different ways (different code).
// A signature-based search would miss the second one.
// A semantic search finds both because the INTENT is the same.
//
// COLLECTION: like a "table" in a regular database.
// We use one collection: "malware-signatures"
// Each document stored = a known malicious APK's intent description
//
// FOR HACKATHON:
// We use Anthropic's embeddings API to convert text → vectors.
// Qdrant stores and searches those vectors.
//
// STUB NOTE:
// If Qdrant isn't running, we return mock match data gracefully.
// =============================================

// Embeddings now come from Gemini (free) via genaiEngine.js
import { generateEmbedding } from '../core/genaiEngine.js'
import logger from '../utils/logger.js'

// We'll use fetch to call Qdrant's REST API directly
// Qdrant runs in Docker on port 6333
const QDRANT_BASE = `http://${process.env.QDRANT_HOST || 'localhost'}:${process.env.QDRANT_PORT || 6333}`
const COLLECTION  = 'malware-signatures'

// Anthropic client for embeddings
// =============================================
// MAIN: searchSimilarMalware()
// Converts the APK's intent description to a vector,
// searches Qdrant for similar known malware
// =============================================
export async function searchSimilarMalware(intentDescription, jobId) {
  try {
    // Step 1: Ensure the collection exists
    await ensureCollection()

    // Step 2: Seed with known malware signatures (first run only)
    await seedKnownMalware()

    // Step 3: Convert the intent description to a vector (embedding)
    logger.info('Generating embedding for vector search', { jobId })
    const queryVector = await getEmbedding(intentDescription)

    // Step 4: Search Qdrant for the most similar known malware
    const searchResult = await qdrantSearch(queryVector, 3)  // top 3 matches

    if (!searchResult || searchResult.length === 0) {
      return { matched: false, similarity: 0, matchedFamily: null }
    }

    const topMatch = searchResult[0]
    logger.info('Vector search complete', {
      jobId,
      similarity: topMatch.score.toFixed(3),
      matchedFamily: topMatch.payload?.family
    })

    return {
      matched: topMatch.score > 0.7,
      similarity: topMatch.score,
      matchedFamily: topMatch.payload?.family || 'Unknown',
      matchedDescription: topMatch.payload?.description || '',
      allMatches: searchResult.map(r => ({
        family: r.payload?.family,
        similarity: r.score.toFixed(3)
      }))
    }

  } catch (error) {
    // Qdrant might not be running yet — don't crash the whole pipeline
    logger.warn('Vector search failed (Qdrant may not be running), using no-match fallback', {
      jobId, error: error.message
    })
    return { matched: false, similarity: 0, matchedFamily: null, error: error.message }
  }
}

// =============================================
// EMBEDDING: Convert text → vector using Gemini (free)
// Delegates to genaiEngine.generateEmbedding()
// =============================================
async function getEmbedding(text) {
  return await generateEmbedding(text)
}

// =============================================
// QDRANT REST API HELPERS
// =============================================

// Check if collection exists, create it if not
async function ensureCollection() {
  try {
    const res = await fetch(`${QDRANT_BASE}/collections/${COLLECTION}`)
    if (res.status === 200) return  // already exists

    // Create new collection with 3072-dimensional vectors (gemini-embedding-exp-03-07 output size)
    await fetch(`${QDRANT_BASE}/collections/${COLLECTION}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vectors: {
          size: 3072,
          distance: 'Cosine'   // cosine similarity = good for text meaning
        }
      })
    })
    logger.info('Created Qdrant collection', { collection: COLLECTION })
  } catch (err) {
    throw new Error(`Qdrant connection failed: ${err.message}`)
  }
}

// Search for similar vectors
async function qdrantSearch(queryVector, limit = 3) {
  const res = await fetch(`${QDRANT_BASE}/collections/${COLLECTION}/points/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vector: queryVector,
      limit,
      with_payload: true    // return the metadata alongside the vector
    })
  })
  const data = await res.json()
  return data.result || []
}

// Insert a known malware signature into Qdrant
async function upsertSignature(id, vector, payload) {
  await fetch(`${QDRANT_BASE}/collections/${COLLECTION}/points`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      points: [{ id, vector, payload }]
    })
  })
}

// =============================================
// SEEDING: Pre-load known malware signatures
// In production: load from a real threat intelligence database
// =============================================
let seeded = false
async function seedKnownMalware() {
  if (seeded) return   // only seed once per server restart
  seeded = true

  const knownMalware = [
    {
      id: 1,
      family: 'FakePay Banking Trojan',
      description: 'APK impersonates HDFC bank app, steals credentials via overlay, intercepts OTPs via SMS, exfiltrates to Romanian C2 server'
    },
    {
      id: 2,
      family: 'Cerberus Banking Malware',
      description: 'Android banking trojan with keylogging, screen capture, SMS interception, USSD code hijacking and accessibility service abuse'
    },
    {
      id: 3,
      family: 'Anubis RAT',
      description: 'Remote access trojan targeting Indian banking apps, steals 2FA codes, enables remote screen control and audio recording'
    },
    {
      id: 4,
      family: 'SharkBot',
      description: 'Advanced banking malware with ATS (Automatic Transfer System) functionality, bypasses 2FA, performs unauthorized transactions directly'
    }
  ]

  logger.info('Seeding Qdrant with known malware signatures...')

  for (const malware of knownMalware) {
    try {
      const vector = await getEmbedding(malware.description)
      await upsertSignature(malware.id, vector, {
        family: malware.family,
        description: malware.description
      })
    } catch (err) {
      logger.warn(`Failed to seed malware signature: ${malware.family}`, { error: err.message })
    }
  }

  logger.info('Qdrant seeded with known malware signatures')
}
