package com.filevault.app.modules

import android.util.Base64
import com.facebook.react.bridge.*
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.sun.jna.NativeLong

/**
 * RNFileVaultModule — XChaCha20-Poly1305 IETF + Argon2id + constant-time comparison
 * via libsodium (lazysodium-android).
 *
 * Korrekte XChaCha20-Poly1305: crypto_aead_xchacha20poly1305_ietf_encrypt_detached
 * (nicht secretbox_easy, das ist XSalsa20).
 */
class RNFileVaultModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val ls: LazySodiumAndroid by lazy {
        LazySodiumAndroid(SodiumAndroid())
    }

    override fun getName() = "RNFileVault"

    // ─── XChaCha20-Poly1305 IETF Verschlüsselung ─────────────────────────────

    @ReactMethod
    fun encrypt(params: ReadableMap, promise: Promise) {
        try {
            val dataB64  = params.getString("data")  ?: throw IllegalArgumentException("data required")
            val keyHex   = params.getString("key")   ?: throw IllegalArgumentException("key required")
            val nonceHex = params.getString("nonce") ?: throw IllegalArgumentException("nonce required")
            // W-03: optional additional authenticated data (e.g. the backend-prefix byte).
            val aadHex   = params.getString("aad")
            val ad: ByteArray? = if (aadHex.isNullOrEmpty()) null else hexToBytes(aadHex)
            val adLen: Long = ad?.size?.toLong() ?: 0L

            val plainText = Base64.decode(dataB64, Base64.DEFAULT)
            val key   = hexToBytes(keyHex)   // 32 bytes
            val nonce = hexToBytes(nonceHex) // 24 bytes

            if (key.size != 32) throw IllegalArgumentException("Key must be 32 bytes (got ${key.size})")
            if (nonce.size != 24) throw IllegalArgumentException("Nonce must be 24 bytes (got ${nonce.size})")

            val cipherText = ByteArray(plainText.size)
            val mac        = ByteArray(16) // XCHACHA20POLY1305_IETF_ABYTES = 16
            val macLen     = LongArray(1)

            val rc = ls.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                cipherText, mac, macLen,
                plainText, plainText.size.toLong(),
                ad, adLen,
                null,
                nonce, key
            )
            // Layer 3: zero secret inputs (key + plaintext) in the JVM heap immediately
            // after the op so they do not linger until GC. cipherText/mac are outputs.
            key.fill(0)
            plainText.fill(0)
            if (rc != 0) {
                promise.reject("ENCRYPT_ERROR", "XChaCha20-Poly1305 encryption failed (rc=$rc)")
                return
            }

            val result = Arguments.createMap()
            result.putString("encrypted", bytesToHex(cipherText))
            result.putString("tag", bytesToHex(mac))
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("ENCRYPT_ERROR", e.message, e)
        }
    }

    // ─── XChaCha20-Poly1305 IETF Entschlüsselung ──────────────────────────────

    @ReactMethod
    fun decrypt(params: ReadableMap, promise: Promise) {
        try {
            val encHex   = params.getString("encrypted") ?: throw IllegalArgumentException("encrypted required")
            val nonceHex = params.getString("nonce")     ?: throw IllegalArgumentException("nonce required")
            val tagHex   = params.getString("tag")       ?: throw IllegalArgumentException("tag required")
            val keyHex   = params.getString("key")       ?: throw IllegalArgumentException("key required")
            // W-03: AAD must match the value bound at encrypt time or the tag check fails.
            val aadHex   = params.getString("aad")
            val ad: ByteArray? = if (aadHex.isNullOrEmpty()) null else hexToBytes(aadHex)
            val adLen: Long = ad?.size?.toLong() ?: 0L

            val cipherText = hexToBytes(encHex)
            val nonce      = hexToBytes(nonceHex) // 24 bytes
            val mac        = hexToBytes(tagHex)   // 16 bytes
            val key        = hexToBytes(keyHex)   // 32 bytes

            if (key.size != 32) throw IllegalArgumentException("Key must be 32 bytes")
            if (nonce.size != 24) throw IllegalArgumentException("Nonce must be 24 bytes")
            if (mac.size != 16) throw IllegalArgumentException("MAC must be 16 bytes")

            val plainText = ByteArray(cipherText.size)

            val rc = ls.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                plainText, null,
                cipherText, cipherText.size.toLong(),
                mac,
                ad, adLen,
                nonce, key
            )
            // Layer 3: key is consumed — zero it immediately (input).
            key.fill(0)
            if (rc != 0) {
                // rc != 0 means authentication tag mismatch — reject without detail to avoid oracle
                promise.reject("DECRYPT_ERROR", "XChaCha20-Poly1305 decryption failed — integrity check failed")
                return
            }

            // Layer 3: encode the recovered plaintext, then zero our copy before returning.
            val out = Base64.encodeToString(plainText, Base64.NO_WRAP)
            plainText.fill(0)
            promise.resolve(out)
        } catch (e: Exception) {
            promise.reject("DECRYPT_ERROR", e.message, e)
        }
    }

    // ─── Argon2id Key Derivation ───────────────────────────────────────────────

    @ReactMethod
    fun argon2id(params: ReadableMap, promise: Promise) {
        try {
            val passwordRaw = params.getString("password") ?: throw IllegalArgumentException("password required")
            val saltB64    = params.getString("salt")     ?: throw IllegalArgumentException("salt required")
            val iterations = if (params.hasKey("iterations")) params.getInt("iterations") else 3
            val memoryKB   = if (params.hasKey("memory"))     params.getInt("memory")     else 65536
            val keyLen     = if (params.hasKey("keyLen"))     params.getInt("keyLen")     else 32

            // R-03 / W-04: NFC-normalise here so every client (incl. non-JS callers)
            // derives the same key for NFD vs. NFC representations of the same string.
            val password = java.text.Normalizer.normalize(passwordRaw, java.text.Normalizer.Form.NFC)

            // C1: decode the Base64 salt to the RAW 16 bytes. The JS hash-wasm fallback
            // now also feeds Argon2id the raw 16 bytes (not the Base64 string), so both
            // paths derive byte-identical keys for the same password+salt.
            val salt          = Base64.decode(saltB64, Base64.DEFAULT)
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            val derivedKey    = ByteArray(keyLen)

            if (salt.size != 16) throw IllegalArgumentException("Argon2id salt must be exactly 16 bytes (got ${salt.size})")

            // crypto_pwhash: 0 = success, -1 = failure. ALG_ARGON2ID13 = 2.
            // NOTE: libsodium crypto_pwhash hardcodes parallelism (lanes) = 1 — no lanes
            // argument exists. The JS side therefore also pins p=1 (C1).
            val rc = ls.sodium.crypto_pwhash(
                derivedKey, derivedKey.size.toLong(),
                passwordBytes, passwordBytes.size.toLong(),
                salt,
                iterations.toLong(),
                NativeLong(memoryKB.toLong() * 1024L), // memlimit in bytes
                2 // crypto_pwhash_ALG_ARGON2ID13
            )
            // Layer 3: the passphrase bytes are consumed — zero them immediately.
            passwordBytes.fill(0)
            if (rc != 0) {
                promise.reject("ARGON2_ERROR", "Argon2id key derivation failed (rc=$rc, memory=${memoryKB}KB)")
                return
            }

            // Encode the derived key, then zero our copy before returning.
            val out = Base64.encodeToString(derivedKey, Base64.NO_WRAP)
            derivedKey.fill(0)
            promise.resolve(out)
        } catch (e: Exception) {
            promise.reject("ARGON2_ERROR", e.message, e)
        }
    }

    // ─── Konstanter-Zeit-Vergleich (sodium_memcmp) ─────────────────────────────

    @ReactMethod
    fun verifyConstantTime(params: ReadableMap, promise: Promise) {
        try {
            val a = params.getString("a") ?: throw IllegalArgumentException("a required")
            val b = params.getString("b") ?: throw IllegalArgumentException("b required")

            val aBytes = a.toByteArray(Charsets.UTF_8)
            val bBytes = b.toByteArray(Charsets.UTF_8)

            // Unterschiedliche Längen → ungleich, aber Längen-Leak ist hier akzeptabel
            // weil Längengleichheit ein Pflicht-Voraussetzung für HMAC-Gleichheit ist.
            if (aBytes.size != bBytes.size) {
                val result = Arguments.createMap()
                result.putBoolean("result", false)
                promise.resolve(result)
                return
            }

            // sodium_memcmp: 0 wenn gleich, -1 wenn verschieden
            val rc = ls.sodium.sodium_memcmp(aBytes, bBytes, aBytes.size)
            val result = Arguments.createMap()
            result.putBoolean("result", rc == 0)
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("MEMCMP_ERROR", e.message, e)
        }
    }

    // ─── Sichere Zufallsbytes ──────────────────────────────────────────────────

    @ReactMethod
    fun generateRandomBytes(params: ReadableMap, promise: Promise) {
        try {
            val length = if (params.hasKey("length")) params.getInt("length") else 32
            val bytes  = ByteArray(length)
            ls.sodium.randombytes_buf(bytes, length)
            promise.resolve(Base64.encodeToString(bytes, Base64.NO_WRAP))
        } catch (e: Exception) {
            promise.reject("RANDOM_ERROR", e.message, e)
        }
    }

    // ─── Hilfsmethoden ────────────────────────────────────────────────────────

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        require(len % 2 == 0) { "Hex string must have even length" }
        return ByteArray(len / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
