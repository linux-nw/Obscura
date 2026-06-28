package com.filevault.app.modules

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import com.facebook.react.bridge.*
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * HardwareKeystoreModule — Android Keystore mit StrongBox-Unterstützung.
 * Modul-Name: "HardwareKeystore"
 *
 * Jeder Datensatz wird mit einem dedizierten AES-256-GCM Key aus dem Keystore verschlüsselt.
 * Key verlässt nie den Hardware-Sicherheitschip (StrongBox/TEE).
 */
class HardwareKeystoreModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
    }

    override fun getName() = "HardwareKeystore"

    // ─── Key-Generierung ──────────────────────────────────────────────────────

    @ReactMethod
    fun generateKey(keyId: String, options: ReadableMap, promise: Promise) {
        try {
            val useStrongBox = options.hasKey("useStrongBox") && options.getBoolean("useStrongBox")

            generateAesKey(keyId, useStrongBox)

            // L4 (self-audit fix): report the REAL security level of the key just generated,
            // read from KeyInfo — NOT a hardcoded isHardwareBacked=true. On a device that fell
            // back to the software keystore, generateAesKey still succeeds but the key is
            // SOFTWARE; the previous hardcoded `true` (and the "device has StrongBox feature"
            // guess for isStrongBoxEnabled) would have falsely claimed hardware backing.
            val keystoreAlias = "filevault_$keyId"
            val key = keyStore.getKey(keystoreAlias, null) as SecretKey
            val keyInfo = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            val (levelName, hardware) = securityLevelOf(keyInfo)

            val result = Arguments.createMap()
            result.putBoolean("success", true)
            result.putBoolean("keyExists", true)
            val attestation = Arguments.createMap()
            attestation.putString("algorithm", "AES")
            attestation.putBoolean("isHardwareBacked", hardware)
            attestation.putString("securityLevel", levelName)
            attestation.putBoolean("isStrongBoxEnabled", levelName == "STRONGBOX")
            attestation.putInt("keySize", 256)
            attestation.putDouble("creationDate", System.currentTimeMillis().toDouble())
            result.putMap("attestation", attestation)
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putBoolean("success", false)
            result.putString("error", e.message)
            promise.resolve(result)
        }
    }

    private fun generateAesKey(keyId: String, preferStrongBox: Boolean) {
        val keystoreAlias = "filevault_$keyId"

        val useStrongBox = preferStrongBox && isStrongBoxAvailableInternal()
        // Only require unlocked-device if a secure lock screen exists, else keygen would
        // throw on devices with no PIN/pattern/password (would break key creation).
        val deviceSecure = (reactApplicationContext
            .getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

        val specBuilder = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // biometric enforced by expo-secure-store at app layer

        // Layer 4: key is only usable while the device is unlocked (P+), but only when a
        // secure lock screen exists (else keygen would fail).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && deviceSecure) {
            specBuilder.setUnlockedDeviceRequired(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        try {
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Retry without StrongBox (TEE-backed key still hardware-backed).
            val fallbackBuilder = KeyGenParameterSpec.Builder(
                keystoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && deviceSecure) {
                fallbackBuilder.setUnlockedDeviceRequired(true)
            }
            keyGenerator.init(fallbackBuilder.build())
            keyGenerator.generateKey()
        }
    }

    // ─── Datenverschlüsselung ─────────────────────────────────────────────────

    @ReactMethod
    fun storeData(keyId: String, data: String, promise: Promise) {
        try {
            val keystoreAlias = "filevault_$keyId"
            if (!keyStore.containsAlias(keystoreAlias)) {
                generateAesKey(keyId, true)
            }

            val secretKey = keyStore.getKey(keystoreAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val iv = cipher.iv // 12 bytes, GCM standard
            val plainBytes = data.toByteArray(Charsets.UTF_8)
            val encrypted = cipher.doFinal(plainBytes) // includes 16-byte GCM tag appended

            // Format: base64(iv) + "." + base64(encrypted+tag)
            val stored = Base64.encodeToString(iv, Base64.NO_WRAP) +
                "." + Base64.encodeToString(encrypted, Base64.NO_WRAP)

            // Persist via SharedPreferences (key-ID mapped to encrypted blob)
            val prefs = reactApplicationContext
                .getSharedPreferences("filevault_keystore", android.content.Context.MODE_PRIVATE)
            prefs.edit().putString("data_$keyId", stored).apply()

            val result = Arguments.createMap()
            result.putBoolean("success", true)
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putBoolean("success", false)
            result.putString("error", e.message)
            promise.resolve(result)
        }
    }

    @ReactMethod
    fun retrieveData(keyId: String, promise: Promise) {
        try {
            val keystoreAlias = "filevault_$keyId"
            if (!keyStore.containsAlias(keystoreAlias)) {
                val result = Arguments.createMap()
                result.putBoolean("success", false)
                result.putString("error", "Key not found")
                promise.resolve(result)
                return
            }

            val prefs = reactApplicationContext
                .getSharedPreferences("filevault_keystore", android.content.Context.MODE_PRIVATE)
            val stored = prefs.getString("data_$keyId", null)
            if (stored == null) {
                val result = Arguments.createMap()
                result.putBoolean("success", false)
                result.putString("error", "Data not found")
                promise.resolve(result)
                return
            }

            val parts = stored.split(".")
            if (parts.size != 2) throw IllegalStateException("Invalid stored data format")

            val iv       = Base64.decode(parts[0], Base64.NO_WRAP)
            val encBytes = Base64.decode(parts[1], Base64.NO_WRAP)

            val secretKey = keyStore.getKey(keystoreAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            val decrypted = cipher.doFinal(encBytes)

            val result = Arguments.createMap()
            result.putBoolean("success", true)
            result.putString("data", decrypted.toString(Charsets.UTF_8))
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putBoolean("success", false)
            result.putString("error", e.message)
            promise.resolve(result)
        }
    }

    // ─── Key-Verwaltung ───────────────────────────────────────────────────────

    @ReactMethod
    fun deleteKey(keyId: String, promise: Promise) {
        try {
            val keystoreAlias = "filevault_$keyId"
            if (keyStore.containsAlias(keystoreAlias)) {
                keyStore.deleteEntry(keystoreAlias)
            }
            val prefs = reactApplicationContext
                .getSharedPreferences("filevault_keystore", android.content.Context.MODE_PRIVATE)
            prefs.edit().remove("data_$keyId").apply()

            val result = Arguments.createMap()
            result.putBoolean("success", true)
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putBoolean("success", false)
            result.putString("error", e.message)
            promise.resolve(result)
        }
    }

    @ReactMethod
    fun keyExists(keyId: String, promise: Promise) {
        try {
            val keystoreAlias = "filevault_$keyId"
            val exists = keyStore.containsAlias(keystoreAlias)
            val result = Arguments.createMap()
            result.putBoolean("success", true)
            result.putBoolean("keyExists", exists)
            promise.resolve(result)
        } catch (e: Exception) {
            val result = Arguments.createMap()
            result.putBoolean("success", false)
            result.putBoolean("keyExists", false)
            promise.resolve(result)
        }
    }

    // Layer 4: REAL per-key security level via KeyInfo — not a device-capability guess.
    // The previous version reported isHardwareBacked = "alias exists" and
    // isStrongBoxEnabled = "device has StrongBox feature", neither of which proves THIS
    // key is in secure hardware. KeyInfo.securityLevel / isInsideSecureHardware does.
    @ReactMethod
    fun getAttestation(keyId: String, promise: Promise) {
        try {
            val keystoreAlias = "filevault_$keyId"
            val attestation = Arguments.createMap()
            attestation.putString("algorithm", "AES")
            attestation.putInt("keySize", 256)

            if (!keyStore.containsAlias(keystoreAlias)) {
                attestation.putBoolean("keyExists", false)
                attestation.putBoolean("isHardwareBacked", false)
                attestation.putString("securityLevel", "NONE")
            } else {
                val key = keyStore.getKey(keystoreAlias, null) as SecretKey
                val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                val (levelName, hardware) = securityLevelOf(keyInfo)
                attestation.putBoolean("keyExists", true)
                attestation.putBoolean("isHardwareBacked", hardware)
                attestation.putString("securityLevel", levelName)
            }

            val result = Arguments.createMap()
            result.putBoolean("success", true)
            result.putMap("attestation", attestation)
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("ATTESTATION_ERROR", e.message, e)
        }
    }

    /** Real security level of a Keystore key via KeyInfo → (levelName, isHardwareBacked). */
    private fun securityLevelOf(keyInfo: KeyInfo): Pair<String, Boolean> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> Pair("STRONGBOX", true)
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Pair("TRUSTED_ENVIRONMENT", true)
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> Pair("SOFTWARE", false)
                else -> @Suppress("DEPRECATION") Pair("UNKNOWN", keyInfo.isInsideSecureHardware)
            }
        } else {
            @Suppress("DEPRECATION")
            if (keyInfo.isInsideSecureHardware) Pair("HARDWARE", true) else Pair("SOFTWARE", false)
        }
    }

    // Layer 4: export the Key Attestation certificate chain for a fresh challenge so the
    // root-of-trust (Verified Boot state + deviceLocked, in the leaf cert's attestation
    // extension OID 1.3.6.1.4.1.11129.2.1.17) can be verified off-device / server-side
    // against Google's hardware-attestation root. AES keys have no cert chain, so this
    // uses a transient EC P-256 attestation key (deleted immediately after export). We do
    // NOT hand-parse the ASN.1 here — shipping unverifiable parser code as a security check
    // would be worse than exporting the chain for a real, audited verifier.
    @ReactMethod
    fun getAttestationCertChain(challengeB64: String, promise: Promise) {
        val alias = "filevault_attest_probe"
        try {
            val challenge = Base64.decode(challengeB64, Base64.NO_WRAP)
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()

            try {
                val sb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailableInternal()
                kpg.initialize(spec(sb))
                kpg.generateKeyPair()
            } catch (e: StrongBoxUnavailableException) {
                kpg.initialize(spec(false))
                kpg.generateKeyPair()
            }

            val chain = keyStore.getCertificateChain(alias)
            val arr = Arguments.createArray()
            chain?.forEach { arr.pushString(Base64.encodeToString(it.encoded, Base64.NO_WRAP)) }
            keyStore.deleteEntry(alias)

            val result = Arguments.createMap()
            result.putInt("chainLength", chain?.size ?: 0)
            result.putArray("certChainB64", arr)
            promise.resolve(result)
        } catch (e: Exception) {
            try { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) } catch (_: Exception) {}
            promise.reject("ATTEST_CHAIN_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun isStrongBoxAvailable(promise: Promise) {
        promise.resolve(isStrongBoxAvailableInternal())
    }

    @ReactMethod
    fun getDeviceInfo(promise: Promise) {
        val result = Arguments.createMap()
        result.putString("deviceModel", Build.MODEL)
        result.putString("osVersion", Build.VERSION.RELEASE)
        result.putString("hardware", Build.HARDWARE)
        promise.resolve(result)
    }

    private fun isStrongBoxAvailableInternal(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            reactApplicationContext.packageManager
                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else false
    }
}
