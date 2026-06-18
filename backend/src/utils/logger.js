// =============================================
// utils/logger.js — Structured Logging with Winston
// =============================================
//
// WHY DO WE NEED A LOGGER?
// console.log() works but it's messy in production.
// Winston gives us:
//   - Timestamps on every message
//   - Log levels: error > warn > info > debug
//   - Color-coded output in terminal
//   - Easy to add file logging later
//
// USAGE in other files:
//   import logger from '../utils/logger.js'
//   logger.info('APK uploaded', { filename: 'suspicious.apk' })
//   logger.error('Analysis failed', { error: err.message })
// =============================================

import winston from 'winston'

// Destructure the formatting helpers we need
const { combine, timestamp, colorize, printf, errors } = winston.format

// Define how each log line looks:
// [2026-06-18 13:00:00] INFO: APK uploaded { filename: 'test.apk' }
const logFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
  // If there's extra data (like { filename: 'test.apk' }), show it
  const metaStr = Object.keys(meta).length ? `\n  ${JSON.stringify(meta, null, 2)}` : ''
  // If it's an error with a stack trace, show that too
  const stackStr = stack ? `\n${stack}` : ''
  return `[${timestamp}] ${level}: ${message}${metaStr}${stackStr}`
})

const logger = winston.createLogger({
  // Only show logs at this level and above
  // debug < info < warn < error
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',

  format: combine(
    errors({ stack: true }),   // capture stack traces on errors
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    colorize({ all: true }),   // color: green=info, yellow=warn, red=error
    logFormat
  ),

  transports: [
    // Print to terminal
    new winston.transports.Console()
  ]
})

export default logger
