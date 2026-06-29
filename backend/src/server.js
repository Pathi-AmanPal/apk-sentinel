// =============================================
// server.js — Express App Entry Point
// =============================================
//
// WHAT IS EXPRESS?
// Express is a framework that makes Node.js handle HTTP requests easily.
// Without Express: raw Node.js http module is verbose and painful.
// With Express: you write clean route handlers in 3 lines.
//
// HOW THIS FILE WORKS:
// 1. Load environment variables from .env
// 2. Create an Express app
// 3. Add "middleware" (pre-processing for every request)
// 4. Register routes (what to do for each URL)
// 5. Start listening on a port
//
// MIDDLEWARE = functions that run BEFORE your route handler.
// Think of it like security checkpoints at an airport:
//   Request → [cors check] → [parse JSON] → [log request] → [your route handler]
// =============================================

import 'dotenv/config'               // Load .env file into process.env
import express from 'express'
import cors from 'cors'
import { mkdirSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import logger from './utils/logger.js'
import analysisRoutes from './routes/analysis.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// ── 1. Create the app ──────────────────────────────────────────────
const app = express()
const PORT = process.env.PORT || 3000

// ── 2. Ensure required directories exist ──────────────────────────
// If the uploads/ or output/ folders don't exist, create them
mkdirSync(process.env.UPLOAD_DIR || './uploads', { recursive: true })
mkdirSync(process.env.OUTPUT_DIR || './output', { recursive: true })

// ── 3. Register Middleware ─────────────────────────────────────────

// CORS: Allow requests from the frontend (Next.js will run on port 5173 or 3001)
// Without this, the browser blocks cross-origin requests (security policy)
app.use(cors({
  origin: ['http://localhost:3001', 'http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

// Parse JSON request bodies — so req.body works for JSON requests
app.use(express.json({ limit: '10mb' }))

// Request logger middleware — logs every incoming request
// req = the incoming request, res = the response we'll send back
// next() = "continue to the next middleware or route handler"
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')?.slice(0, 50)
  })
  next()
})

// ── 4. Register Routes ─────────────────────────────────────────────
// All analysis routes are prefixed with /api
// So: POST /api/analyze, GET /api/status/:id, GET /api/report/:id
app.use('/api', analysisRoutes)

// Serve frontend static assets
app.use(express.static(path.join(__dirname, '../public')))

// Send index.html for all other routes to support React SPA client-side routing
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next()
  }
  res.sendFile(path.join(__dirname, '../public/index.html'))
})

// ── 5. Global Error Handler ────────────────────────────────────────
// If any route throws an error and doesn't handle it,
// this catches it and sends a clean JSON error response
// The 4-parameter signature (err, req, res, next) is Express's special syntax for error handlers
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack })
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error'
  })
})

// ── 6. Start Listening ─────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`🚀 APK Sentinel server running on http://localhost:${PORT}`)
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`)
})

export default app
