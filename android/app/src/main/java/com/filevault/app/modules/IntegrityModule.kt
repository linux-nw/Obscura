package com.filevault.app.modules

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.filevault.app.BuildConfig
import com.facebook.react.bridge.*
import java.io.File
import java.security.MessageDigest

/**
 * IntegrityModule — APK-Signaturprüfung, Debugger-Detection und System-Integrity.
 * Modul-Name: "IntegrityNative"
 */
class IntegrityModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "IntegrityNative"

    // ─── Package Info ─────────────────────────────────────────────────────────

    @ReactMethod
    fun getPackageInfo(promise: Promise) {
        try {
            val pm = reactApplicationContext.packageManager
            val packageName = reactApplicationContext.packageName

            val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }

            val signatures: List<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.apkContentsSigners?.map { sig ->
                    MessageDigest.getInstance("SHA-256")
                        .digest(sig.toByteArray())
                        .joinToString(":") { "%02X".format(it) }
                } ?: emptyList()
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures?.map { sig ->
                    MessageDigest.getInstance("SHA-256")
                        .digest(sig.toByteArray())
                        .joinToString(":") { "%02X".format(it) }
                } ?: emptyList()
            }

            val installerPackageName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }

            val installSource = when (installerPackageName) {
                "com.android.vending", "com.google.android.feedback" -> 1
                null -> 2
                else -> 0
            }

            val sigsArray = Arguments.createArray()
            signatures.forEach { sigsArray.pushString(it) }

            val result = Arguments.createMap()
            result.putString("packageName", packageName)
            result.putArray("signatures", sigsArray)
            result.putInt("installSource", installSource)
            result.putDouble("firstInstallTime", pkgInfo.firstInstallTime.toDouble())
            result.putDouble("lastUpdateTime", pkgInfo.lastUpdateTime.toDouble())
            if (installerPackageName != null) result.putString("installerPackageName", installerPackageName)
            else result.putNull("installerPackageName")
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("INTEGRITY_ERROR", e.message, e)
        }
    }

    // ─── Debugger Detection ───────────────────────────────────────────────────

    @ReactMethod
    fun checkDebugger(promise: Promise) {
        try {
            val isDebuggerConnected = android.os.Debug.isDebuggerConnected()

            val tracerPid = try {
                File("/proc/self/status").useLines { lines ->
                    lines.find { it.startsWith("TracerPid:") }
                        ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
                }
            } catch (ignored: Exception) { 0 }

            promise.resolve(isDebuggerConnected || tracerPid != 0)
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    // ─── Debuggable Flag ──────────────────────────────────────────────────────

    @ReactMethod
    fun checkDebuggable(promise: Promise) {
        try {
            val flags = reactApplicationContext.applicationInfo.flags
            promise.resolve((flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    // ─── Native Library Hashes ────────────────────────────────────────────────

    @ReactMethod
    fun getNativeLibHashes(promise: Promise) {
        try {
            val nativeLibDir = reactApplicationContext.applicationInfo.nativeLibraryDir
            val md = MessageDigest.getInstance("SHA-256")

            val soFiles = File(nativeLibDir)
                .listFiles { f -> f.name.endsWith(".so") }
                ?.sortedBy { it.name } ?: emptyList()

            val libsArray = Arguments.createArray()
            soFiles.forEach { soFile ->
                libsArray.pushString(soFile.name)
                md.update(soFile.readBytes())
            }

            val result = Arguments.createMap()
            result.putArray("libs", libsArray)
            result.putString("hash", md.digest().joinToString("") { "%02x".format(it) })
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putArray("libs", Arguments.createArray())
            result.putString("hash", "")
            promise.resolve(result)
        }
    }

    // ─── File Path Hashes ─────────────────────────────────────────────────────

    @ReactMethod
    fun getFilePathHashes(paths: ReadableArray, promise: Promise) {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val pathsArray = Arguments.createArray()

            for (i in 0 until paths.size()) {
                val path = paths.getString(i) ?: continue
                pathsArray.pushString(path)
                try {
                    val f = File(path)
                    if (f.exists() && f.isFile) md.update(f.readBytes())
                } catch (ignored: Exception) {}
            }

            val result = Arguments.createMap()
            result.putArray("paths", pathsArray)
            result.putString("hashes", md.digest().joinToString("") { "%02x".format(it) })
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("INTEGRITY_ERROR", e.message, e)
        }
    }

    // ─── Hardware Info ────────────────────────────────────────────────────────

    @ReactMethod
    fun getHardwareInfo(promise: Promise) {
        try {
            val androidId = try {
                Settings.Secure.getString(
                    reactApplicationContext.contentResolver,
                    Settings.Secure.ANDROID_ID
                )
            } catch (ignored: Exception) { null }

            val result = Arguments.createMap()
            result.putString("device", Build.DEVICE)
            result.putString("model", Build.MODEL)
            result.putString("brand", Build.BRAND)
            result.putString("manufacturer", Build.MANUFACTURER)
            if (androidId != null) result.putString("androidId", androidId) else result.putNull("androidId")
            result.putNull("iosDeviceId")
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("INTEGRITY_ERROR", e.message, e)
        }
    }

    // ─── Pinned Signature Verification (L7) ───────────────────────────────────
    //
    // Compares the running APK's signing-cert SHA-256 against BuildConfig.SIGNING_CERT_SHA256
    // (compiled in at build time from the FILEVAULT_SIGNING_CERT_SHA256 gradle property), not
    // against a value the JS layer hands in (which a repackager controls) nor a TOFU SecureStore
    // value (which a repackager seeds on first run). Fail-closed:
    //   - mismatch              -> { configured: true,  isValid: false }
    //   - match                 -> { configured: true,  isValid: true  }
    //   - no hash pinned (debug) -> { configured: false, isValid: false }  // JS: "unverifiable"
    // Note: like any on-device self-check this is defeatable by an attacker who patches out the
    // call before resigning; it raises the bar against naive repackaging, it is not attestation.
    @ReactMethod
    fun verifyPinnedSignature(promise: Promise) {
        val result = Arguments.createMap()
        try {
            val expected = BuildConfig.SIGNING_CERT_SHA256
            if (expected.isEmpty()) {
                result.putBoolean("configured", false)
                result.putBoolean("isValid", false)
                result.putString("actualHash", getApkSignatureFingerprint())
                promise.resolve(result)
                return
            }
            val actual = getApkSignatureFingerprint()
            result.putBoolean("configured", true)
            result.putBoolean("isValid", constantTimeStringEquals(actual, expected))
            result.putString("actualHash", actual)
            promise.resolve(result)
        } catch (e: Exception) {
            // Could not read the cert at all -> cannot prove validity -> fail-closed, but flag
            // whether a hash was even pinned so JS can tell "tampered" from "unverifiable".
            result.putBoolean("configured", BuildConfig.SIGNING_CERT_SHA256.isNotEmpty())
            result.putBoolean("isValid", false)
            result.putString("actualHash", "")
            promise.resolve(result)
        }
    }

    // ─── Code Signature Check ─────────────────────────────────────────────────

    @ReactMethod
    fun checkCodeSignature(expectedHash: String, promise: Promise) {
        try {
            val actualHash = getApkSignatureFingerprint()
            // Fail-closed: an empty expected hash means "not configured", NOT "valid".
            val configured = expectedHash.isNotEmpty()
            val isValid = configured && constantTimeStringEquals(actualHash, expectedHash)

            val errors = Arguments.createArray()
            if (!configured) errors.pushString("No expected signature configured")
            else if (!isValid) errors.pushString("Signature mismatch: expected $expectedHash, got $actualHash")

            val result = Arguments.createMap()
            result.putBoolean("isValid", isValid)
            result.putBoolean("configured", configured)
            result.putNull("codeSignaturePath")
            result.putBoolean("signed", actualHash.isNotEmpty())
            result.putString("actualHash", actualHash)
            result.putArray("errors", errors)
            promise.resolve(result)
        } catch (e: Exception) {
            val errors = Arguments.createArray()
            errors.pushString(e.message ?: "Unknown error")
            val result = Arguments.createMap()
            result.putBoolean("isValid", false)
            result.putNull("codeSignaturePath")
            result.putBoolean("signed", false)
            result.putString("actualHash", "")
            result.putArray("errors", errors)
            promise.resolve(result)
        }
    }

    // ─── Legacy methods (kept for backward compatibility) ─────────────────────

    @ReactMethod
    fun getSignatureFingerprint(promise: Promise) {
        try {
            promise.resolve(getApkSignatureFingerprint())
        } catch (e: Exception) {
            promise.reject("INTEGRITY_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun verifySignature(expectedFingerprint: String, promise: Promise) {
        try {
            promise.resolve(constantTimeStringEquals(getApkSignatureFingerprint(), expectedFingerprint))
        } catch (e: Exception) {
            promise.resolve(false)
        }
    }

    @ReactMethod
    fun checkInstallerIntegrity(promise: Promise) {
        try {
            val pm = reactApplicationContext.packageManager
            val packageName = reactApplicationContext.packageName

            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }

            val trustedInstallers = setOf("com.android.vending", "com.google.android.feedback")
            val result = Arguments.createMap()
            result.putString("installer", installer ?: "unknown")
            result.putBoolean("fromTrustedSource", installer in trustedInstallers)
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putString("installer", "unknown")
            result.putBoolean("fromTrustedSource", false)
            promise.resolve(result)
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    @Suppress("DEPRECATION")
    private fun getApkSignatureFingerprint(): String {
        val pm = reactApplicationContext.packageManager
        val packageName = reactApplicationContext.packageName

        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners
        } else {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
        }

        val firstSig = signatures?.firstOrNull()
            ?: throw IllegalStateException("No APK signatures found")

        return MessageDigest.getInstance("SHA-256")
            .digest(firstSig.toByteArray())
            .joinToString(":") { "%02X".format(it) }
    }

    private fun constantTimeStringEquals(a: String, b: String): Boolean {
        val aBytes = a.toByteArray(Charsets.UTF_8)
        val bBytes = b.toByteArray(Charsets.UTF_8)
        if (aBytes.size != bBytes.size) return false
        var diff = 0
        for (i in aBytes.indices) diff = diff or (aBytes[i].toInt() xor bBytes[i].toInt())
        return diff == 0
    }
}
