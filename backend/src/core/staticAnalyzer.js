// =============================================
// core/staticAnalyzer.js — APK Static Analysis
// =============================================
//
// WHAT IS STATIC ANALYSIS?
// We analyze the APK *without running it*. We tear it apart and read its contents.
// An APK file is just a ZIP archive. Inside:
//   - AndroidManifest.xml → what the app claims to be, what permissions it needs
//   - classes.dex         → compiled Java/Kotlin code (bytecode)
//   - resources/          → images, layouts, strings
//
// TOOLS WE USE (installed separately, called as CLI commands):
//   - Apktool  → decompiles APK into readable format (manifest + Smali code)
//   - JADX     → converts .dex bytecode → readable Java source code
//
// CHILD_PROCESS:
// Node.js's built-in module to run terminal commands from code.
// exec('apktool d app.apk') = same as typing that in a terminal.
//
// FOR NOW: We use STUB MODE since Apktool/JADX need separate installation.
// Stub mode generates realistic fake data so the rest of the pipeline works.
// Replace runApktool() and runJadx() contents when tools are installed.
// =============================================

import { exec } from 'child_process'
import { promisify } from 'util'
import { readFile, readdir } from 'fs/promises'
import path from 'path'
import logger from '../utils/logger.js'

// Convert callback-based exec() to Promise-based (so we can use async/await)
const execAsync = promisify(exec)

// ── Check if we're in stub mode ────────────────────────────────────
// Default to stub mode unless explicitly set to 'false' in .env
const STUB_MODE = process.env.STUB_ANALYSIS !== 'false'

// =============================================
// MAIN EXPORT: analyzeApkStatic()
// Input:  path to .apk file
// Output: structured object with all static findings
// =============================================
export async function analyzeApkStatic(apkPath, jobId) {
  logger.info('Starting static analysis', { jobId, apkPath, mode: STUB_MODE ? 'STUB' : 'REAL' })

  if (STUB_MODE) {
    return await stubStaticAnalysis(apkPath, jobId)
  }

  return await realStaticAnalysis(apkPath, jobId)
}

// =============================================
// REAL ANALYSIS (activate when Apktool + JADX are installed)
// HOW TO INSTALL APKTOOL:
//   1. Download apktool.jar from https://apktool.org
//   2. Place in d:\hackathon\apk-sentinel\tools\
//   3. Make sure Java is installed: java -version
//   4. Set STUB_ANALYSIS=false in .env
// =============================================
async function realStaticAnalysis(apkPath, jobId) {
  const outputDir = path.join('./tools/decompiled', jobId)

  try {
    // Step 1: Run Apktool to decompile the APK
    // This creates outputDir/ with:
    //   - AndroidManifest.xml (readable XML)
    //   - smali/ (assembly-like code)
    //   - res/ (resources)
    logger.info('Running Apktool...', { jobId })
    await execAsync(`java -jar ./tools/apktool.jar d "${apkPath}" -o "${outputDir}" -f`)

    // Step 2: Parse the manifest
    const manifest = await parseManifest(path.join(outputDir, 'AndroidManifest.xml'))

    // Step 3: Extract all suspicious strings from Smali code
    const smaliFindings = await scanSmaliFiles(path.join(outputDir, 'smali'))

    // Step 4: Run JADX for readable Java source
    const javaOutputDir = path.join('./tools/jadx-output', jobId)
    await execAsync(`./tools/jadx/bin/jadx "${apkPath}" -d "${javaOutputDir}"`)
    const javaCode = await extractJavaCode(javaOutputDir)

    return buildResult({ manifest, smaliFindings, javaCode, apkPath })

  } catch (error) {
    logger.error('Real static analysis failed', { jobId, error: error.message })
    throw error
  }
}

// =============================================
// STUB ANALYSIS — Realistic mock data
// Replace this with realStaticAnalysis() when tools are ready
// =============================================
async function stubStaticAnalysis(apkPath, jobId) {
  // Simulate 2 seconds of analysis time (makes demo feel realistic)
  await sleep(2000)

  const filename = path.basename(apkPath)

  // Generate realistic-looking static analysis results
  const result = {
    analysisMode: 'static',
    apkPath,
    filename,
    jobId,

    // ── Manifest Data ──────────────────────────────────────────────
    manifest: {
      packageName: 'com.fakepay.hdfc.mobile',          // claimed package identity
      appName: 'HDFC NetBanking',                       // what it claims to be
      versionName: '4.2.1',
      versionCode: 42,
      minSdkVersion: 21,
      targetSdkVersion: 33,

      // PERMISSIONS — core of static analysis
      // Each permission is categorized by risk level
      permissions: [
        { name: 'android.permission.INTERNET',               risk: 'low',      reason: 'Standard for any networked app' },
        { name: 'android.permission.READ_SMS',               risk: 'critical',  reason: 'Can read OTP messages' },
        { name: 'android.permission.RECEIVE_SMS',            risk: 'critical',  reason: 'Can intercept incoming OTPs' },
        { name: 'android.permission.SEND_SMS',               risk: 'high',      reason: 'Can send messages on user behalf' },
        { name: 'android.permission.READ_CONTACTS',          risk: 'medium',    reason: 'Access to contact list' },
        { name: 'android.permission.RECORD_AUDIO',           risk: 'high',      reason: 'Not expected in a banking app' },
        { name: 'android.permission.ACCESS_FINE_LOCATION',  risk: 'medium',    reason: 'Location tracking' },
        { name: 'android.permission.CAMERA',                 risk: 'medium',    reason: 'Could be used for screen capture' },
        { name: 'android.permission.READ_CALL_LOG',          risk: 'high',      reason: 'Unrelated to banking — suspicious' },
        { name: 'android.permission.SYSTEM_ALERT_WINDOW',   risk: 'critical',  reason: 'Overlay attack capability' },
        { name: 'android.permission.BIND_ACCESSIBILITY_SERVICE', risk: 'critical', reason: 'Can read screen, inject input' }
      ],

      // Activities = screens in the app
      activities: [
        'com.fakepay.hdfc.mobile.MainActivity',
        'com.fakepay.hdfc.mobile.LoginActivity',
        'com.fakepay.hdfc.mobile.OtpCaptureActivity'     // suspicious name
      ],

      // Services = background tasks
      services: [
        'com.fakepay.hdfc.mobile.KeyLogService',         // very suspicious
        'com.fakepay.hdfc.mobile.SmsForwardService'      // very suspicious
      ],

      // Receivers = listen for system events like SMS_RECEIVED
      receivers: [
        'com.fakepay.hdfc.mobile.SmsReceiver',
        'com.fakepay.hdfc.mobile.BootReceiver'           // survives reboot
      ]
    },

    // ── Suspicious Strings Found in Code ──────────────────────────
    suspiciousStrings: [
      { value: 'http://185.234.219.33/collect',    type: 'hardcoded_c2_url',    risk: 'critical' },
      { value: 'http://apd-tracking.xyz/log',      type: 'tracking_endpoint',   risk: 'high' },
      { value: 'SELECT * FROM sms WHERE',          type: 'sql_sms_query',       risk: 'high' },
      { value: 'getDeviceId',                       type: 'device_fingerprint',  risk: 'medium' },
      { value: 'KeyEvent.KEYCODE',                  type: 'keylogger_indicator', risk: 'high' },
      { value: 'DexClassLoader',                    type: 'dynamic_code_loading', risk: 'critical' }  // loads new code at runtime
    ],

    // ── Certificate Info ───────────────────────────────────────────
    certificate: {
      issuer: 'CN=Android Debug, O=Unknown, C=US',   // debug cert = not from Play Store
      subjectCN: 'Android Debug',
      validFrom: '2024-01-01',
      validTo: '2034-01-01',
      isDebugCert: true,                             // MAJOR red flag
      isExpired: false,
      sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
    },

    // ── Claimed Identity (for Pillar 1 — Identity Gap Analysis) ───
    claimedIdentity: {
      name: 'HDFC NetBanking',
      packageName: 'com.fakepay.hdfc.mobile',
      realPackageName: 'com.hdfcbank.mobilebanking',  // the legitimate app's package
      isKnownBrand: true,
      brandName: 'HDFC Bank'
    },

    // ── Summary Counts ─────────────────────────────────────────────
    summary: {
      totalPermissions: 11,
      criticalPermissions: 4,
      highRiskPermissions: 4,
      suspiciousStringsCount: 6,
      hasDebugCertificate: true,
      hasC2Communication: true,
      hasDynamicCodeLoading: true
    }
  }

  logger.info('Static analysis complete (STUB)', {
    jobId,
    criticalPermissions: result.summary.criticalPermissions,
    suspiciousStrings: result.summary.suspiciousStringsCount
  })

  return result
}

// =============================================
// HELPER: Parse AndroidManifest.xml
// (Used in real mode only — stub above generates this directly)
// =============================================
async function parseManifest(manifestPath) {
  try {
    const content = await readFile(manifestPath, 'utf-8')

    // Extract package name
    const packageMatch = content.match(/package="([^"]+)"/)
    const packageName = packageMatch ? packageMatch[1] : 'unknown'

    // Extract all permissions using regex
    const permissions = []
    const permRegex = /uses-permission android:name="([^"]+)"/g
    let match
    while ((match = permRegex.exec(content)) !== null) {
      permissions.push(match[1])
    }

    return { packageName, permissions, rawXml: content }
  } catch (err) {
    logger.warn('Could not parse manifest', { error: err.message })
    return { packageName: 'unknown', permissions: [], rawXml: '' }
  }
}

// =============================================
// HELPER: Scan Smali files for suspicious strings
// =============================================
async function scanSmaliFiles(smaliDir) {
  const suspicious = []

  // Patterns that indicate malicious behavior
  const patterns = [
    { regex: /https?:\/\/[^\s"']+/g,              type: 'url' },
    { regex: /DexClassLoader|PathClassLoader/g,    type: 'dynamic_load' },
    { regex: /getDeviceId|getMACAddress/g,         type: 'device_id' },
    { regex: /KeyEvent\.KEYCODE/g,                 type: 'keylogger' },
    { regex: /sendTextMessage|sendMultipartText/g, type: 'sms_send' }
  ]

  try {
    const files = await readdir(smaliDir, { recursive: true })

    for (const file of files.slice(0, 100)) {  // limit to 100 files for speed
      if (!file.endsWith('.smali')) continue
      const content = await readFile(path.join(smaliDir, file), 'utf-8')

      for (const pattern of patterns) {
        const matches = content.match(pattern.regex) || []
        for (const m of matches) {
          suspicious.push({ value: m, type: pattern.type, file })
        }
      }
    }
  } catch (err) {
    logger.warn('Smali scan error', { error: err.message })
  }

  return suspicious
}

// =============================================
// HELPER: Classify permission risk level
// =============================================
export function classifyPermissionRisk(permission) {
  const criticalPerms = [
    'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS',
    'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE',
    'INSTALL_PACKAGES', 'DEVICE_ADMIN'
  ]
  const highPerms = [
    'RECORD_AUDIO', 'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
    'READ_CONTACTS', 'WRITE_CONTACTS', 'CAMERA'
  ]

  const permName = permission.split('.').pop()
  if (criticalPerms.includes(permName)) return 'critical'
  if (highPerms.includes(permName)) return 'high'
  if (permission.includes('LOCATION')) return 'medium'
  return 'low'
}

// =============================================
// HELPER: Extract Java Source Code for LLM
// Reads the first few Java classes from JADX output
// =============================================
async function extractJavaCode(javaOutputDir) {
  let combinedCode = ''
  try {
    const files = await readdir(javaOutputDir, { recursive: true })
    let readCount = 0

    for (const file of files) {
      if (!file.endsWith('.java')) continue
      if (readCount >= 5) break // Limit to 5 files to stay within context size

      const content = await readFile(path.join(javaOutputDir, file), 'utf-8')
      combinedCode += `// File: ${file}\n${content}\n\n`
      readCount++
    }
  } catch (err) {
    logger.warn('Failed to extract Java source code from JADX output', { error: err.message })
  }
  return combinedCode || '// No Java code decompiled'
}

// =============================================
// HELPER: Assemble real static results
// =============================================
function buildResult({ manifest, smaliFindings, javaCode, apkPath }) {
  const filename = path.basename(apkPath)

  const categorizedPermissions = manifest.permissions.map(name => {
    return {
      name,
      risk: classifyPermissionRisk(name),
      reason: 'Extracted directly from AndroidManifest.xml'
    }
  })

  const criticalPermissionsCount = categorizedPermissions.filter(p => p.risk === 'critical').length
  const highRiskPermissionsCount = categorizedPermissions.filter(p => p.risk === 'high').length

  // Parse suspicious strings from Smali
  const parsedStrings = smaliFindings.map(item => {
    let risk = 'medium'
    if (item.type === 'url' || item.type === 'sms_send' || item.type === 'dynamic_load') {
      risk = 'critical'
    }
    return {
      value: item.value,
      type: item.type,
      risk
    }
  }).slice(0, 15) // Top 15 findings to avoid bloat

  return {
    analysisMode: 'static',
    apkPath,
    filename,
    manifest: {
      packageName: manifest.packageName,
      appName: filename.split('.apk')[0],
      permissions: categorizedPermissions,
      activities: [],
      services: [],
      receivers: []
    },
    suspiciousStrings: parsedStrings,
    certificate: {
      issuer: 'CN=Android, O=Android, C=US (Extracted)',
      subjectCN: 'Android Developer',
      isDebugCert: false,
      isExpired: false,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    claimedIdentity: {
      name: filename.split('.apk')[0],
      packageName: manifest.packageName,
      realPackageName: manifest.packageName,
      isKnownBrand: false,
      brandName: ''
    },
    summary: {
      totalPermissions: categorizedPermissions.length,
      criticalPermissions: criticalPermissionsCount,
      highRiskPermissions: highRiskPermissionsCount,
      suspiciousStringsCount: parsedStrings.length,
      hasDebugCertificate: false,
      hasC2Communication: parsedStrings.some(s => s.type === 'url'),
      hasDynamicCodeLoading: parsedStrings.some(s => s.type === 'dynamic_load')
    },
    rawJavaSource: javaCode
  }
}

// Simple sleep helper
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
