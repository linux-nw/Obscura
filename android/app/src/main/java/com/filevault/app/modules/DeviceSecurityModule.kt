package com.filevault.app.modules

import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.facebook.react.bridge.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.Socket

/**
 * DeviceSecurityModule — Root-Detection, Frida-Detection, Debugger-Detection.
 * Modul-Name: "DeviceSecurity"
 *
 * Gibt keine false-positives in Standard-Google-Play-Umgebungen.
 */
class DeviceSecurityModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "DeviceSecurity"

    // ─── Su-Binary Check ──────────────────────────────────────────────────────

    @ReactMethod
    fun checkSuBinary(promise: Promise) {
        try {
            val suPaths = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/system/xbin/daemonsu",
                "/sbin/su",
                "/vendor/bin/su",
                "/system/su",
                "/system/bin/.ext/su",
                "/data/local/bin/su",
                "/data/local/xbin/su",
                "/system/app/Superuser.apk",
                "/system/app/SuperSU.apk",
                "/system/app/KingUser.apk",
            )
            val found = suPaths.any { File(it).exists() }
            promise.resolve(found)
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    // ─── Debuggable-Flag Check ────────────────────────────────────────────────

    @ReactMethod
    fun checkDebuggable(promise: Promise) {
        try {
            val appInfo = reactApplicationContext.applicationInfo
            val isDebuggable = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            promise.resolve(isDebuggable)
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    // ─── Root-Package Check ───────────────────────────────────────────────────

    @ReactMethod
    fun checkRootKeysInPackage(promise: Promise) {
        try {
            val pm = reactApplicationContext.packageManager
            val rootPackages = listOf(
                "com.topjohnwu.magisk",
                "com.noshufou.android.su",
                "com.thirdparty.superuser",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.zachspong.temprootremovejb",
                "com.ramdroid.appquarantine",
                "com.kingroot.kinguser",
                "com.kingo.root",
                "com.smedialink.oneclickroot",
                "com.zhiqupk.root.global",
                "com.alephzain.framaroot",
            )
            val found = rootPackages.any {
                try { pm.getPackageInfo(it, 0); true } catch (_: PackageManager.NameNotFoundException) { false }
            }
            promise.resolve(found)
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    // ─── Frida-Detection ──────────────────────────────────────────────────────

    @ReactMethod
    fun checkFridaModules(promise: Promise) {
        val detected = mutableListOf<String>()
        try {
            // 1. Check Frida default port 27042
            if (isFridaPortOpen()) {
                detected.add("frida_port_27042")
            }

            // 2. Check for frida-server binary
            val fridaPaths = listOf(
                "/data/local/tmp/frida-server",
                "/data/local/frida-server",
                "/system/bin/frida-server",
            )
            if (fridaPaths.any { File(it).exists() }) {
                detected.add("frida_server_binary")
            }

            // 3. Check /proc/self/maps for Frida agent
            try {
                val maps = File("/proc/self/maps").readText()
                if (maps.contains("frida-agent") || maps.contains("frida_agent")) {
                    detected.add("frida_agent_in_maps")
                }
            } catch (_: Exception) {}

            // 4. Check /proc/self/status for injected libraries
            try {
                File("/proc/self/fd").listFiles()?.forEach { fd ->
                    try {
                        val link = fd.canonicalPath
                        if (link.contains("frida") || link.contains("gum-js-loop")) {
                            detected.add("frida_fd")
                        }
                    } catch (_: Exception) {}
                }
            } catch (_: Exception) {}

        } catch (e: Exception) {
            // Detection failed — don't throw, just return empty
        }

        val result = Arguments.createArray()
        detected.forEach { result.pushString(it) }
        promise.resolve(result)
    }

    private fun isFridaPortOpen(): Boolean {
        return try {
            Socket().use { s ->
                s.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 300)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    // ─── TracerPid (Debugger-Attach-Detection) ────────────────────────────────

    @ReactMethod
    fun getTracerPid(promise: Promise) {
        try {
            val statusFile = File("/proc/self/status")
            val tracerPid = statusFile.bufferedReader().useLines { lines ->
                lines.firstOrNull { it.startsWith("TracerPid:") }
                    ?.removePrefix("TracerPid:")
                    ?.trim()
                    ?.toIntOrNull() ?: 0
            }
            promise.resolve(tracerPid)
        } catch (e: Exception) {
            promise.resolve(0)
        }
    }

    // ─── Active IME (Layer 2: untrusted-keyboard signal) ──────────────────────
    // A third-party (non-system) IME can keylog the passphrase. This reports the
    // active keyboard so JS can warn the user. Best-effort SIGNAL, not a guarantee:
    // a system-app IME could still be malicious on a compromised device, and the
    // user may legitimately use a trusted third-party keyboard.

    @ReactMethod
    fun getActiveInputMethod(promise: Promise) {
        try {
            val id = Settings.Secure.getString(
                reactApplicationContext.contentResolver,
                Settings.Secure.DEFAULT_INPUT_METHOD
            )
            val pkg = id?.substringBefore('/') ?: ""
            val isSystem = try {
                val ai = reactApplicationContext.packageManager.getApplicationInfo(pkg, 0)
                val sysFlags = android.content.pm.ApplicationInfo.FLAG_SYSTEM or
                    android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                (ai.flags and sysFlags) != 0
            } catch (_: Exception) {
                false
            }
            val result = Arguments.createMap()
            result.putString("packageName", pkg)
            result.putBoolean("isSystem", isSystem)
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("IME_ERROR", e.message, e)
        }
    }
}
