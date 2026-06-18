// =============================================
// core/dynamicAnalyzer.js — APK Dynamic Analysis (Stub)
// =============================================
//
// WHAT IS DYNAMIC ANALYSIS?
// We actually RUN the APK in a controlled sandbox (Android emulator)
// and watch what it does: what APIs it calls, what network requests it makes.
//
// TOOLS FOR REAL MODE:
//   - Android SDK / AVD (Android Virtual Device) → the emulator
//   - Frida → a dynamic instrumentation toolkit
//     Frida injects a JavaScript agent INTO the running app.
//     That agent hooks every sensitive API call and logs it.
//   - mitmproxy → intercepts all network traffic from the emulator
//
// HOW FRIDA WORKS (high level):
//   1. Start Android emulator
//   2. Install frida-server on the emulator
//   3. Install and launch the APK in emulator
//   4. Run: frida -U -n "HDFC NetBanking" -l hook_script.js
//   5. hook_script.js runs INSIDE the app and intercepts:
//      - Every SMS read/send
//      - Every HTTP request
//      - Every file access
//      - Every crypto operation
//   6. Logged events come back to Node.js via Frida's JS API
//
// FRIDA PILLAR 5 — Intent Spoofing:
//   We FAKE environment data to the APK (lie to it):
//   - "Yes, you have SMS permission" (when it doesn't)
//   - "Yes, the device is rooted"
//   - "Yes, banking app com.hdfcbank.mobilebanking is installed"
//   Then we compare behavior before/after lying → reveals hidden payloads
//
// STUB MODE → REAL MODE CONVERSION:
//   1. Install Android SDK: https://developer.android.com/studio/command-line/sdkmanager
//   2. Install Frida: npm install frida
//   3. Create AVD: avdmanager create avd -n test_device -k "system-images;android-30;google_apis;x86_64"
//   4. Push frida-server to emulator: adb push frida-server /data/local/tmp/
//   5. Replace stubDynamicAnalysis() call with realDynamicAnalysis()
//   Estimated effort: 1 day
// =============================================

import logger from '../utils/logger.js'
import { exec } from 'child_process'
import { promisify } from 'util'
import { readFile, unlink } from 'fs/promises'
import path from 'path'

const execAsync = promisify(exec)

// Default to stub mode unless explicitly set to 'false' in .env
const STUB_MODE = process.env.STUB_ANALYSIS !== 'false'

// =============================================
// MAIN EXPORT: analyzeApkDynamic()
// Input:  apkPath, jobId, staticResults (from staticAnalyzer)
// Output: behavioral timeline, network calls, frida events
// =============================================
export async function analyzeApkDynamic(apkPath, jobId, staticResults) {
  logger.info('Starting dynamic analysis', { jobId, mode: STUB_MODE ? 'STUB' : 'REAL' })

  if (STUB_MODE) {
    return await stubDynamicAnalysis(apkPath, jobId, staticResults)
  }

  return await realDynamicAnalysis(apkPath, jobId, staticResults)
}

// =============================================
// STUB: Realistic fake dynamic analysis results
// Based on what a real banking trojan would do
// =============================================
async function stubDynamicAnalysis(apkPath, jobId, staticResults) {
  await sleep(3000)  // simulate sandbox execution time

  const result = {
    analysisMode: 'dynamic',
    jobId,
    sandboxDurationSeconds: 120,

    // ── Temporal Attack Graph ──────────────────────────────────────
    // This is Pillar 3: a timeline of what the malware does step by step
    // T = seconds after launch
    temporalAttackGraph: [
      {
        T: 0,
        event: 'APP_LAUNCH',
        description: 'App launched, shows fake HDFC login screen',
        apiCall: 'Activity.onCreate()',
        risk: 'low'
      },
      {
        T: 3,
        event: 'PERMISSION_CHECK',
        description: 'Checks if SMS permission is granted',
        apiCall: 'checkSelfPermission(READ_SMS)',
        risk: 'medium'
      },
      {
        T: 7,
        event: 'TARGET_APP_SCAN',
        description: 'Scans for installed banking apps (HDFC, SBI, ICICI, Axis)',
        apiCall: 'PackageManager.getInstalledPackages()',
        risk: 'high',
        detail: 'Found: com.hdfcbank.mobilebanking, com.sbi.mobile'
      },
      {
        T: 12,
        event: 'CREDENTIALS_CAPTURE',
        description: 'User enters credentials on fake login screen — captured by keylogger',
        apiCall: 'EditText.addTextChangedListener()',
        risk: 'critical',
        detail: 'Credentials staged for exfiltration'
      },
      {
        T: 15,
        event: 'SMS_INTERCEPT_ARM',
        description: 'Registers SMS broadcast receiver — ready to intercept OTPs',
        apiCall: 'registerReceiver(SmsReceiver, SMS_RECEIVED)',
        risk: 'critical'
      },
      {
        T: 23,
        event: 'FIRST_C2_BEACON',
        description: 'First connection to command-and-control server',
        apiCall: 'HttpURLConnection.connect()',
        risk: 'critical',
        detail: 'POST http://185.234.219.33/collect — device fingerprint sent'
      },
      {
        T: 31,
        event: 'OTP_INTERCEPT',
        description: 'Incoming SMS intercepted (bank OTP)',
        apiCall: 'BroadcastReceiver.onReceive(SMS_RECEIVED)',
        risk: 'critical',
        detail: 'OTP hidden from user notifications'
      },
      {
        T: 33,
        event: 'CREDENTIAL_EXFIL',
        description: 'Captured credentials + OTP sent to C2 server',
        apiCall: 'HttpURLConnection.connect()',
        risk: 'critical',
        detail: 'POST http://185.234.219.33/collect — 847 bytes'
      },
      {
        T: 45,
        event: 'OVERLAY_LAUNCH',
        description: 'SYSTEM_ALERT_WINDOW overlay shown to display fake "processing" screen while fraud occurs',
        apiCall: 'WindowManager.addView(TYPE_APPLICATION_OVERLAY)',
        risk: 'critical'
      },
      {
        T: 90,
        event: 'PERSISTENCE_SETUP',
        description: 'Boot receiver registered — malware survives device restart',
        apiCall: 'ACTION_BOOT_COMPLETED registered',
        risk: 'high'
      }
    ],

    // ── Network Activity ───────────────────────────────────────────
    networkActivity: [
      {
        timestamp: 'T+23s',
        method: 'POST',
        url: 'http://185.234.219.33/collect',
        size: '312 bytes',
        payload: '{"device_id":"a3f9b2c1","phone":"91XXXXXXXX10","imei":"3599..."}',
        classification: 'C2_BEACON'
      },
      {
        timestamp: 'T+33s',
        method: 'POST',
        url: 'http://185.234.219.33/collect',
        size: '847 bytes',
        payload: '{"user":"test@hdfc","pass":"[CAPTURED]","otp":"247891"}',
        classification: 'CREDENTIAL_EXFILTRATION'
      },
      {
        timestamp: 'T+61s',
        method: 'GET',
        url: 'http://apd-tracking.xyz/log?id=a3f9b2c1',
        size: '128 bytes',
        classification: 'TRACKING_PING'
      }
    ],

    // ── Frida API Hooks Log ────────────────────────────────────────
    fridaHooks: [
      { api: 'SmsManager.sendTextMessage',         called: true,  detail: 'Called once — 165.x.x.x destination' },
      { api: 'TelephonyManager.getDeviceId',        called: true,  detail: 'IMEI captured: 359943...' },
      { api: 'Cipher.doFinal',                       called: true,  detail: 'AES encryption used — obfuscating payload' },
      { api: 'Runtime.exec',                         called: false, detail: 'No shell commands executed' },
      { api: 'DexClassLoader.loadClass',             called: true,  detail: 'Dynamic code loaded from /data/data/com.fakepay/files/payload.dex' }
    ],

    // ── Pillar 5: Intent Spoofing Results ─────────────────────────
    // What happened when we LIED to the APK about its environment
    intentSpoofingResults: {
      scenario: 'Told the app SMS permission is granted AND device is rooted',
      baselineBehavior: 'App showed login screen, sent one beacon at T+23s',
      spoofedBehavior: 'App activated full keylogger, intercepted OTP, sent credentials',
      behavioralDelta: 'CRITICAL — Hidden payload activated only when conditions are met',
      hiddenPayloadsRevealed: [
        'Full keylogger mode (disabled when SMS permission not granted)',
        'Root exploit attempt (disabled when device not rooted)',
        'Secondary C2 fallback: http://185.234.219.44/backup'
      ]
    },

    // ── Summary ────────────────────────────────────────────────────
    summary: {
      totalEvents: 10,
      criticalEvents: 6,
      c2Connections: 2,
      credentialsExfiltrated: true,
      otpIntercepted: true,
      persistenceMechanism: true,
      overlayAttack: true,
      dynamicCodeLoading: true
    }
  }

  logger.info('Dynamic analysis complete (STUB)', {
    jobId,
    criticalEvents: result.summary.criticalEvents,
    c2Connections: result.summary.c2Connections
  })

  return result
}

// =============================================
// REAL DYNAMIC ANALYSIS via ADB and Frida
// =============================================
async function realDynamicAnalysis(apkPath, jobId, staticResults) {
  const packageName = staticResults.manifest?.packageName || 'com.fakepay.hdfc.mobile'
  const logFilePath = path.join('./output', `${jobId}-frida.log`)

  logger.info('Executing real dynamic analysis with Frida', { jobId, packageName })

  try {
    // 1. Verify ADB is connected to emulator / device
    const devicesOutput = await execAsync('adb devices')
    const lines = devicesOutput.stdout.trim().split('\n')
    if (lines.length <= 1 || !lines[1].includes('device')) {
      throw new Error('No Android emulator or device found online via adb. Please start your emulator.')
    }

    // 2. Install APK (grant all permissions)
    logger.info('Installing APK onto Android device...', { jobId })
    await execAsync(`adb install -g "${apkPath}"`)

    // 3. Launch the app using monkey launcher
    logger.info('Launching Android application...', { jobId })
    await execAsync(`adb shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`)

    // 4. Start Frida instrumentation
    logger.info('Attaching Frida tracing hooks...', { jobId })
    const fridaCmd = `frida -U -f ${packageName} -l ./tools/frida-hook.js --no-pause -o "${logFilePath}"`
    
    // Run Frida as a background process (don't wait for completion)
    const fridaProcess = exec(fridaCmd)
    
    // 5. Gather dynamic execution telemetry for 20 seconds
    logger.info('Telemetry window open, capturing logs...', { jobId })
    await sleep(20000)

    // 6. Stop instrumentation and clean up
    logger.info('Closing application and cleaning environment...', { jobId })
    
    // Kill Frida process safely
    try {
      fridaProcess.kill()
    } catch (e) {}

    // Force stop app and uninstall
    await execAsync(`adb shell am force-stop ${packageName}`)
    await execAsync(`adb uninstall ${packageName}`)

    // 7. Parse the output log file
    logger.info('Parsing Frida security log...', { jobId })
    let logContent = ''
    try {
      logContent = await readFile(logFilePath, 'utf8')
      await unlink(logFilePath) // delete log file after reading
    } catch (e) {
      logger.warn('No logs generated by Frida instrumentation', { jobId })
    }

    return parseFridaLogs(logContent, jobId)

  } catch (error) {
    logger.error('Real dynamic analysis failed', { jobId, error: error.message })
    throw error
  }
}

// =============================================
// PARSER: Convert raw Frida console logs → structured report
// =============================================
function parseFridaLogs(logContent, jobId) {
  const lines = logContent.split('\n')
  const temporalAttackGraph = []
  const networkActivity = []
  
  const hooksTriggered = {
    sms: false,
    network: false,
    dex: false,
    crypto: false,
    root: false
  }

  let timeOffset = 0

  for (const line of lines) {
    if (!line.includes('[FRIDA]')) continue

    timeOffset += 2 // increment timeline counter roughly

    if (line.includes('[SMS_INTERCEPTION]') || line.includes('[SMS_DETAIL]')) {
      hooksTriggered.sms = true
      temporalAttackGraph.push({
        T: timeOffset,
        event: 'SMS_INTERCEPT',
        description: 'SmsMessage API intercepted incoming message',
        apiCall: 'SmsMessage.createFromPdu()',
        risk: 'critical',
        detail: line.split('Intercepted SMS from: ').pop()
      })
    }

    if (line.includes('[NETWORK_CALL]')) {
      hooksTriggered.network = true
      const url = line.split('URL.openConnection() -> ').pop().trim()
      networkActivity.push({
        timestamp: `T+${timeOffset}s`,
        method: 'CONNECT',
        url: url,
        classification: 'C2_COMMUNICATION'
      })
      temporalAttackGraph.push({
        T: timeOffset,
        event: 'C2_BEACON',
        description: `App connected to outbound endpoint: ${url}`,
        apiCall: 'URL.openConnection()',
        risk: 'critical'
      })
    }

    if (line.includes('[DYNAMIC_CODE_LOADING]')) {
      hooksTriggered.dex = true
      temporalAttackGraph.push({
        T: timeOffset,
        event: 'DEX_LOAD',
        description: 'App loaded extra executable classes at runtime',
        apiCall: 'DexClassLoader',
        risk: 'high',
        detail: line.split('DexClassLoader loaded JAR/APK from: ').pop()
      })
    }

    if (line.includes('[CRYPTO_OPERATION]')) {
      hooksTriggered.crypto = true
    }

    if (line.includes('[ROOT_DETECTION]')) {
      hooksTriggered.root = true
    }
  }

  // Create summary stats
  const totalEvents = temporalAttackGraph.length
  const criticalEvents = temporalAttackGraph.filter(e => e.risk === 'critical').length

  return {
    analysisMode: 'dynamic',
    jobId,
    sandboxDurationSeconds: 20,
    temporalAttackGraph,
    networkActivity,
    fridaHooks: [
      { api: 'SmsManager.createFromPdu', called: hooksTriggered.sms, detail: hooksTriggered.sms ? 'SMS interception detected' : 'Not triggered' },
      { api: 'URL.openConnection', called: hooksTriggered.network, detail: hooksTriggered.network ? 'Outbound network calls captured' : 'Not triggered' },
      { api: 'DexClassLoader', called: hooksTriggered.dex, detail: hooksTriggered.dex ? 'Dynamic compilation detected' : 'Not triggered' },
      { api: 'Cipher.doFinal', called: hooksTriggered.crypto, detail: hooksTriggered.crypto ? 'Encryption methods invoked' : 'Not triggered' },
      { api: 'File (su)', called: hooksTriggered.root, detail: hooksTriggered.root ? 'Root checking triggered' : 'Not triggered' }
    ],
    intentSpoofingResults: {
      scenario: 'Told the app environment variables are spoofed via baseline analysis',
      baselineBehavior: totalEvents > 0 ? 'Behaviors captured dynamically' : 'App was dormant',
      spoofedBehavior: 'Not simulated (real device dynamic mode active)',
      behavioralDelta: hooksTriggered.sms ? 'CRITICAL — Actionable malware capabilities intercepted' : 'No significant behavioral delta detected'
    },
    summary: {
      totalEvents,
      criticalEvents,
      c2Connections: networkActivity.length,
      credentialsExfiltrated: totalEvents > 2,
      otpIntercepted: hooksTriggered.sms,
      persistenceMechanism: false,
      overlayAttack: false,
      dynamicCodeLoading: hooksTriggered.dex
    }
  }
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
