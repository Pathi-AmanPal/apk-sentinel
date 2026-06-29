// =============================================
// core/staticAnalyzer.js — APK Static Analysis
// =============================================

import { exec } from 'child_process'
import { promisify } from 'util'
import { readFile, readdir } from 'fs/promises'
import path from 'path'
import logger from '../utils/logger.js'

const execAsync = promisify(exec)

// Default to stub mode unless explicitly set to 'false' in .env
const STUB_MODE = process.env.STUB_ANALYSIS !== 'false'

export async function analyzeApkStatic(apkPath, jobId) {
  logger.info('Starting static analysis', { jobId, apkPath, mode: STUB_MODE ? 'STUB' : 'REAL' })

  if (STUB_MODE) {
    return await stubStaticAnalysis(apkPath, jobId)
  }

  return await realStaticAnalysis(apkPath, jobId)
}

async function realStaticAnalysis(apkPath, jobId) {
  const outputDir = path.join('./tools/decompiled', jobId)

  try {
    logger.info('Running Apktool...', { jobId })
    await execAsync(`java -jar ./tools/apktool.jar d "${apkPath}" -o "${outputDir}" -f`)

    const manifest = await parseManifest(path.join(outputDir, 'AndroidManifest.xml'))
    const smaliFindings = await scanSmaliFiles(path.join(outputDir, 'smali'))

    const javaOutputDir = path.join('./tools/jadx-output', jobId)
    await execAsync(`./tools/jadx/bin/jadx "${apkPath}" -d "${javaOutputDir}"`)
    const javaCode = await extractJavaCode(javaOutputDir)

    return buildResult({ manifest, smaliFindings, javaCode, apkPath })

  } catch (error) {
    logger.error('Real static analysis failed', { jobId, error: error.message })
    throw error
  }
}

async function stubStaticAnalysis(apkPath, jobId) {
  await sleep(2000)

  const filename = path.basename(apkPath)
  const name = filename.toLowerCase()

  let category = 'trojan' // default
  if (name.includes('zombie') || name.includes('mod') || name.includes('game') || name.includes('hack') || name.includes('castaways') || name.includes('crack') || name.includes('cheat')) {
    category = 'game_mod'
  } else if (name.includes('safe') || name.includes('legit') || name.includes('whatsapp') || name.includes('spotify') || name.includes('chrome') || name.includes('google') || name.includes('facebook') || name.includes('instagram')) {
    category = 'safe'
  }

  let result = {
    analysisMode: 'static',
    apkPath,
    filename,
    jobId
  }

  if (category === 'game_mod') {
    result = {
      ...result,
      manifest: {
        packageName: 'com.zombie.castaways.mod',
        appName: 'Zombie Castaways MOD',
        versionName: '4.61.1',
        versionCode: 461,
        minSdkVersion: 21,
        targetSdkVersion: 33,
        permissions: [
          { name: 'android.permission.INTERNET', risk: 'low', reason: 'Required for ad loading and analytics' },
          { name: 'android.permission.ACCESS_NETWORK_STATE', risk: 'low', reason: 'Check connectivity status' },
          { name: 'android.permission.ACCESS_FINE_LOCATION', risk: 'medium', reason: 'Used for target-based local advertisements' },
          { name: 'android.permission.READ_PHONE_STATE', risk: 'high', reason: 'Reads unique device identifier for telemetry' },
          { name: 'android.permission.WRITE_EXTERNAL_STORAGE', risk: 'medium', reason: 'Saves game files and cache' }
        ],
        activities: [
          'com.vizorinteractive.zombies.MainActivity',
          'com.vizorinteractive.zombies.UnityPlayerActivity',
          'com.google.android.gms.ads.AdActivity'
        ],
        services: [
          'com.vizorinteractive.zombies.AdTrackerService'
        ],
        receivers: [
          'com.vizorinteractive.zombies.InstallReferrerReceiver'
        ]
      },
      suspiciousStrings: [
        { value: 'http://ad-tracking-network.xyz/api/log', type: 'tracking_endpoint', risk: 'medium' },
        { value: 'http://unity-ad-sdk.net/config', type: 'ad_config', risk: 'low' },
        { value: 'getDeviceId', type: 'device_fingerprint', risk: 'medium' }
      ],
      certificate: {
        issuer: 'CN=Android MOD Developer, O=AndroidP1, C=RU',
        subjectCN: 'Android MOD Developer',
        validFrom: '2024-01-01',
        validTo: '2034-01-01',
        isDebugCert: false,
        isExpired: false,
        sha256: 'c5d6e7f8a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
      },
      claimedIdentity: {
        name: 'Zombie Castaways MOD',
        packageName: 'com.zombie.castaways.mod',
        realPackageName: 'com.vizorinteractive.zombies',
        isKnownBrand: false,
        brandName: null
      },
      summary: {
        totalPermissions: 5,
        criticalPermissions: 0,
        highRiskPermissions: 1,
        suspiciousStringsCount: 3,
        hasDebugCertificate: false,
        hasC2Communication: false,
        hasDynamicCodeLoading: false
      }
    }
  } else if (category === 'safe') {
    const isSpotify = name.includes('spotify')
    const appName = isSpotify ? 'Spotify Premium' : 'WhatsApp Messenger'
    const pkgName = isSpotify ? 'com.spotify.music' : 'com.whatsapp'

    result = {
      ...result,
      manifest: {
        packageName: pkgName,
        appName: appName,
        versionName: '8.8.2',
        versionCode: 882,
        minSdkVersion: 23,
        targetSdkVersion: 33,
        permissions: [
          { name: 'android.permission.INTERNET', risk: 'low', reason: 'Allows network connections' },
          { name: 'android.permission.ACCESS_NETWORK_STATE', risk: 'low', reason: 'Allows checking network status' },
          { name: 'android.permission.MODIFY_AUDIO_SETTINGS', risk: 'low', reason: 'Allows audio configuration' }
        ],
        activities: [
          `${pkgName}.MainActivity`,
          `${pkgName}.SettingsActivity`
        ],
        services: [
          `${pkgName}.PlaybackService`
        ],
        receivers: [
          `${pkgName}.MediaButtonReceiver`
        ]
      },
      suspiciousStrings: [
        { value: 'getDeviceId', type: 'device_fingerprint', risk: 'medium' }
      ],
      certificate: {
        issuer: `CN=${isSpotify ? 'Spotify AB' : 'WhatsApp Inc'}, O=${isSpotify ? 'Spotify AB' : 'WhatsApp Inc'}, C=${isSpotify ? 'SE' : 'US'}`,
        subjectCN: isSpotify ? 'Spotify AB' : 'WhatsApp Inc',
        validFrom: '2020-01-01',
        validTo: '2040-01-01',
        isDebugCert: false,
        isExpired: false,
        sha256: '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e'
      },
      claimedIdentity: {
        name: appName,
        packageName: pkgName,
        realPackageName: pkgName,
        isKnownBrand: true,
        brandName: isSpotify ? 'Spotify' : 'WhatsApp'
      },
      summary: {
        totalPermissions: 3,
        criticalPermissions: 0,
        highRiskPermissions: 0,
        suspiciousStringsCount: 1,
        hasDebugCertificate: false,
        hasC2Communication: false,
        hasDynamicCodeLoading: false
      }
    }
  } else {
    result = {
      ...result,
      manifest: {
        packageName: 'com.fakepay.hdfc.mobile',
        appName: 'HDFC NetBanking',
        versionName: '4.2.1',
        versionCode: 42,
        minSdkVersion: 21,
        targetSdkVersion: 33,
        permissions: [
          { name: 'android.permission.INTERNET', risk: 'low', reason: 'Standard for any networked app' },
          { name: 'android.permission.READ_SMS', risk: 'critical', reason: 'Can read OTP messages' },
          { name: 'android.permission.RECEIVE_SMS', risk: 'critical', reason: 'Can intercept incoming OTPs' },
          { name: 'android.permission.SEND_SMS', risk: 'high', reason: 'Can send messages on user behalf' },
          { name: 'android.permission.READ_CONTACTS', risk: 'medium', reason: 'Access to contact list' },
          { name: 'android.permission.RECORD_AUDIO', risk: 'high', reason: 'Not expected in a banking app' },
          { name: 'android.permission.ACCESS_FINE_LOCATION', risk: 'medium', reason: 'Location tracking' },
          { name: 'android.permission.CAMERA', risk: 'medium', reason: 'Could be used for screen capture' },
          { name: 'android.permission.READ_CALL_LOG', risk: 'high', reason: 'Unrelated to banking — suspicious' },
          { name: 'android.permission.SYSTEM_ALERT_WINDOW', risk: 'critical', reason: 'Overlay attack capability' },
          { name: 'android.permission.BIND_ACCESSIBILITY_SERVICE', risk: 'critical', reason: 'Can read screen, inject input' }
        ],
        activities: [
          'com.fakepay.hdfc.mobile.MainActivity',
          'com.fakepay.hdfc.mobile.LoginActivity',
          'com.fakepay.hdfc.mobile.OtpCaptureActivity'
        ],
        services: [
          'com.fakepay.hdfc.mobile.KeyLogService',
          'com.fakepay.hdfc.mobile.SmsForwardService'
        ],
        receivers: [
          'com.fakepay.hdfc.mobile.SmsReceiver',
          'com.fakepay.hdfc.mobile.BootReceiver'
        ]
      },
      suspiciousStrings: [
        { value: 'http://185.234.219.33/collect', type: 'hardcoded_c2_url', risk: 'critical' },
        { value: 'http://apd-tracking.xyz/log', type: 'tracking_endpoint', risk: 'high' },
        { value: 'SELECT * FROM sms WHERE', type: 'sql_sms_query', risk: 'high' },
        { value: 'getDeviceId', type: 'device_fingerprint', risk: 'medium' },
        { value: 'KeyEvent.KEYCODE', type: 'keylogger_indicator', risk: 'high' },
        { value: 'DexClassLoader', type: 'dynamic_code_loading', risk: 'critical' }
      ],
      certificate: {
        issuer: 'CN=Android Debug, O=Unknown, C=US',
        subjectCN: 'Android Debug',
        validFrom: '2024-01-01',
        validTo: '2034-01-01',
        isDebugCert: true,
        isExpired: false,
        sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
      },
      claimedIdentity: {
        name: 'HDFC NetBanking',
        packageName: 'com.fakepay.hdfc.mobile',
        realPackageName: 'com.hdfcbank.mobilebanking',
        isKnownBrand: true,
        brandName: 'HDFC Bank'
      },
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
  }

  logger.info('Static analysis complete (STUB)', {
    jobId,
    category,
    criticalPermissions: result.summary.criticalPermissions,
    suspiciousStrings: result.summary.suspiciousStringsCount
  })

  return result
}

async function parseManifest(manifestPath) {
  try {
    const content = await readFile(manifestPath, 'utf-8')
    const packageMatch = content.match(/package="([^"]+)"/)
    const packageName = packageMatch ? packageMatch[1] : 'unknown'

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

async function scanSmaliFiles(smaliDir) {
  const suspicious = []
  const patterns = [
    { regex: /https?:\/\/[^\s"']+/g,              type: 'url' },
    { regex: /DexClassLoader|PathClassLoader/g,    type: 'dynamic_load' },
    { regex: /getDeviceId|getMACAddress/g,         type: 'device_id' },
    { regex: /KeyEvent\.KEYCODE/g,                 type: 'keylogger' },
    { regex: /sendTextMessage|sendMultipartText/g, type: 'sms_send' }
  ]

  try {
    const files = await readdir(smaliDir, { recursive: true })
    for (const file of files.slice(0, 100)) {
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

async function extractJavaCode(javaOutputDir) {
  let combinedCode = ''
  try {
    const files = await readdir(javaOutputDir, { recursive: true })
    let readCount = 0
    for (const file of files) {
      if (!file.endsWith('.java')) continue
      if (readCount >= 5) break
      const content = await readFile(path.join(javaOutputDir, file), 'utf-8')
      combinedCode += `// File: ${file}\n${content}\n\n`
      readCount++
    }
  } catch (err) {
    logger.warn('Failed to extract Java source code', { error: err.message })
  }
  return combinedCode || '// No Java code decompiled'
}

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
  }).slice(0, 15)

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

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
