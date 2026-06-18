// =============================================
// tools/frida-hook.js — Android API Hooking Script
// =============================================
// This script runs inside the Android application process via Frida.
// It intercepts sensitive API calls and logs them to console / log file.
// =============================================

console.log("=== Frida Instrumentation Loaded ===");

Java.perform(function () {
    // ── 1. HOOK SMS INTERCEPTION (BroadcastReceivers & SMS Reads) ──
    try {
        var SmsMessage = Java.use("android.telephony.SmsMessage");
        SmsMessage.createFromPdu.overload('[B').implementation = function (pdu) {
            console.log("[FRIDA] [SMS_INTERCEPTION] SmsMessage.createFromPdu() called");
            var msg = this.createFromPdu(pdu);
            try {
                var body = msg.getMessageBody();
                var sender = msg.getOriginatingAddress();
                console.log("[FRIDA] [SMS_DETAIL] Intercepted SMS from: " + sender + " | Body: " + body);
            } catch (e) {
                console.log("[FRIDA] [SMS_DETAIL] Error reading SMS details: " + e.message);
            }
            return msg;
        };
        console.log("[+] SMS Interception hooks armed");
    } catch (e) {
        console.log("[-] Failed to hook SMS: " + e.message);
    }

    // ── 2. HOOK NETWORK ACTIVITY (URL Connection & Socket HTTP calls) ──
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var conn = this.openConnection();
            var urlStr = this.toString();
            // Ignore standard Google/Firebase/Android system beacons to avoid noise
            if (!urlStr.includes("google") && !urlStr.includes("firebase") && !urlStr.includes("android")) {
                console.log("[FRIDA] [NETWORK_CALL] URL.openConnection() -> " + urlStr);
            }
            return conn;
        };
        console.log("[+] HTTP/HTTPS Connection hooks armed");
    } catch (e) {
        console.log("[-] Failed to hook URL Connection: " + e.message);
    }

    // ── 3. HOOK DYNAMIC CLASS LOADING (DexClassLoader) ──
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log("[FRIDA] [DYNAMIC_CODE_LOADING] DexClassLoader loaded JAR/APK from: " + dexPath);
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        console.log("[+] DexClassLoader hooks armed");
    } catch (e) {
        console.log("[-] Failed to hook DexClassLoader: " + e.message);
    }

    // ── 4. HOOK CRYPTOGRAPHY (AES/DES Key Generation & Cipher) ──
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function (bytes) {
            console.log("[FRIDA] [CRYPTO_OPERATION] Cipher.doFinal() called");
            return this.doFinal(bytes);
        };
        console.log("[+] Cryptography hooks armed");
    } catch (e) {
        console.log("[-] Failed to hook Cryptography: " + e.message);
    }

    // ── 5. HOOK ROOT DETECTION (Bypasses or logs checking) ──
    try {
        var File = Java.use("java.io.File");
        File.$init.overload('java.lang.String').implementation = function (path) {
            if (path.includes("su") || path.includes("busybox")) {
                console.log("[FRIDA] [ROOT_DETECTION] Checking for root binary at path: " + path);
            }
            return this.$init(path);
        };
        console.log("[+] Root detection logging armed");
    } catch (e) {
        console.log("[-] Failed to hook Root Detection: " + e.message);
    }
});
