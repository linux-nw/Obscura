package com.filevault.app.modules

import android.util.Base64
import com.facebook.react.bridge.*
import java.nio.charset.StandardCharsets
import java.text.Normalizer

/**
 * NativeKeyCustodyModule — L3 Phase 2b React bridge for the libsodium secure-memory custody core.
 *
 * This is the @ReactMethod surface that finally WIRES NativeKeyCustody (Phase 1b) into production.
 * KeyCustody.ts selects this backing at runtime via NativeModules.NativeKeyCustody presence; when
 * it is present the raw master/content key never crosses the bridge in steady state — JS holds only
 * an opaque 128-bit handle and addresses every crypto op by it.
 *
 * Raw key crosses the bridge at exactly ONE place: registerRawKey, the documented one-time touch at
 * vault creation / rotation (audit B1/B5). Every other method takes a handle. The passphrase crosses
 * at openVault/rewrapVault (inherent — the user types it) and is NFC-normalised HERE, natively, so a
 * non-JS caller cannot diverge the KEK (R-03 / W-04, identical to RNFileVaultModule.argon2id).
 *
 * Wire-format parity is NOT re-litigated here: the byte-identity of these ops to the JS path is
 * proven by L3CustodyHandleTest (on device) and the Phase 1a host harness. This module only adapts
 * ReadableMap <-> the NativeKeyCustody object, matching RNFileVaultModule's encodings exactly:
 * incoming plaintext Base64.DEFAULT, outgoing plaintext Base64.NO_WRAP, lowercase hex.
 */
class NativeKeyCustodyModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "NativeKeyCustody"

    // ── install channel ──────────────────────────────────────────────────────────────────────

    /**
     * registerRawKey({ handle, keyHex }) — adopt a JS-minted handle over a raw key (audit B1/B5).
     * The ONLY bridge method that takes a raw key. The transient hex->bytes copy is zeroed at once.
     */
    @ReactMethod
    fun registerRawKey(params: ReadableMap, promise: Promise) {
        try {
            val handle = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val keyHex = params.getString("keyHex") ?: throw IllegalArgumentException("keyHex required")
            val raw = NativeKeyCustodyCrypto.fromHex(keyHex)
            try {
                NativeKeyCustody.adoptRawKey(handle, raw)
            } finally {
                raw.fill(0)
            }
            promise.resolve(handle)
        } catch (e: Exception) {
            promise.reject("CUSTODY_REGISTER_ERROR", e.message, e)
        }
    }

    // ── master KEK-unwrap (audit R3) ─────────────────────────────────────────────────────────

    /**
     * openVault({ password, kekSaltHex, opslimit, memlimitKB, ivHex, ctHex, macHex }) — passphrase
     * login. Argon2id KEK derive + EtM master-unwrap, both native; only the handle returns (audit R3,
     * unlockKEK). NFC native here (K7). Rejects on a wrong passphrase (EtM tag mismatch).
     */
    @ReactMethod
    fun openVault(params: ReadableMap, promise: Promise) {
        try {
            val passwordRaw = params.getString("password") ?: throw IllegalArgumentException("password required")
            val kekSaltHex  = params.getString("kekSaltHex") ?: throw IllegalArgumentException("kekSaltHex required")
            val ivHex       = params.getString("ivHex") ?: throw IllegalArgumentException("ivHex required")
            val ctHex       = params.getString("ctHex") ?: throw IllegalArgumentException("ctHex required")
            val macHex      = params.getString("macHex") ?: throw IllegalArgumentException("macHex required")
            val opslimit    = readLong(params, "opslimit", 3L)
            val memlimitKB  = readLong(params, "memlimitKB", 65536L)

            val password = Normalizer.normalize(passwordRaw, Normalizer.Form.NFC).toByteArray(StandardCharsets.UTF_8)
            val kekSalt  = NativeKeyCustodyCrypto.fromHex(kekSaltHex)
            try {
                val handle = NativeKeyCustody.openVault(password, kekSalt, opslimit, memlimitKB, ivHex, ctHex, macHex)
                promise.resolve(handle)
            } finally {
                password.fill(0)
            }
        } catch (e: Exception) {
            promise.reject("CUSTODY_OPENVAULT_ERROR", e.message, e)
        }
    }

    /**
     * unwrapVaultWithKek({ kekHex, ivHex, ctHex, macHex }) — biometric login (audit R3, B3). The KEK
     * is already in hand (hardware-stored), so no Argon2id: EtM-unwrap the master natively, return the handle.
     */
    @ReactMethod
    fun unwrapVaultWithKek(params: ReadableMap, promise: Promise) {
        try {
            val kekHex = params.getString("kekHex") ?: throw IllegalArgumentException("kekHex required")
            val ivHex  = params.getString("ivHex") ?: throw IllegalArgumentException("ivHex required")
            val ctHex  = params.getString("ctHex") ?: throw IllegalArgumentException("ctHex required")
            val macHex = params.getString("macHex") ?: throw IllegalArgumentException("macHex required")
            val handle = NativeKeyCustody.unwrapVaultWithKek(kekHex, ivHex, ctHex, macHex)
            promise.resolve(handle)
        } catch (e: Exception) {
            promise.reject("CUSTODY_UNWRAPKEK_ERROR", e.message, e)
        }
    }

    /**
     * rewrapVault({ handle, newPassword, newSaltHex, opslimit, memlimitKB, newIvHex }) — passphrase
     * change (audit R3, changePassphrase). New KEK derived natively (NFC here), master re-wrapped
     * without ever returning to JS; resolves { ivHex, ctHex, macHex } for storage.
     */
    @ReactMethod
    fun rewrapVault(params: ReadableMap, promise: Promise) {
        try {
            val handle      = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val newPassRaw  = params.getString("newPassword") ?: throw IllegalArgumentException("newPassword required")
            val newSaltHex  = params.getString("newSaltHex") ?: throw IllegalArgumentException("newSaltHex required")
            val newIvHex    = params.getString("newIvHex") ?: throw IllegalArgumentException("newIvHex required")
            val opslimit    = readLong(params, "opslimit", 3L)
            val memlimitKB  = readLong(params, "memlimitKB", 65536L)

            val newPassword = Normalizer.normalize(newPassRaw, Normalizer.Form.NFC).toByteArray(StandardCharsets.UTF_8)
            val newSalt = NativeKeyCustodyCrypto.fromHex(newSaltHex)
            val newIv   = NativeKeyCustodyCrypto.fromHex(newIvHex)
            try {
                val w = NativeKeyCustody.rewrapVault(handle, newPassword, newSalt, opslimit, memlimitKB, newIv)
                val out = Arguments.createMap()
                out.putString("ivHex", newIvHex)
                out.putString("ctHex", w.ctHex)
                out.putString("macHex", w.macHex)
                promise.resolve(out)
            } finally {
                newPassword.fill(0)
            }
        } catch (e: Exception) {
            promise.reject("CUSTODY_REWRAP_ERROR", e.message, e)
        }
    }

    // ── content AEAD by handle (audit R1) ────────────────────────────────────────────────────

    /**
     * encryptContent({ handle, dataB64, nonceHex, aadHex }) — XChaCha20-Poly1305 by handle.
     * Byte-identical to RNFileVaultModule.encrypt with the same key. Resolves { cipherHex, tagHex }.
     */
    @ReactMethod
    fun encryptContent(params: ReadableMap, promise: Promise) {
        try {
            val handle   = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val dataB64  = params.getString("dataB64") ?: throw IllegalArgumentException("dataB64 required")
            val nonceHex = params.getString("nonceHex") ?: throw IllegalArgumentException("nonceHex required")
            val aadHex   = params.getString("aadHex")

            val plain = Base64.decode(dataB64, Base64.DEFAULT)
            val nonce = NativeKeyCustodyCrypto.fromHex(nonceHex)
            val aad   = if (aadHex.isNullOrEmpty()) null else NativeKeyCustodyCrypto.fromHex(aadHex)
            try {
                val aead = NativeKeyCustody.encryptWithHandle(handle, plain, nonce, aad)
                val out = Arguments.createMap()
                out.putString("cipherHex", aead.cipherHex)
                out.putString("tagHex", aead.tagHex)
                promise.resolve(out)
            } finally {
                plain.fill(0)
            }
        } catch (e: Exception) {
            promise.reject("CUSTODY_ENCRYPT_ERROR", e.message, e)
        }
    }

    /**
     * decryptContent({ handle, cipherHex, nonceHex, tagHex, aadHex }) — XChaCha20-Poly1305 by handle.
     * Resolves the recovered plaintext as Base64.NO_WRAP (symmetric with RNFileVaultModule.decrypt).
     * Rejects on tag mismatch with no detail (no oracle).
     */
    @ReactMethod
    fun decryptContent(params: ReadableMap, promise: Promise) {
        try {
            val handle    = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val cipherHex = params.getString("cipherHex") ?: throw IllegalArgumentException("cipherHex required")
            val nonceHex  = params.getString("nonceHex") ?: throw IllegalArgumentException("nonceHex required")
            val tagHex    = params.getString("tagHex") ?: throw IllegalArgumentException("tagHex required")
            val aadHex    = params.getString("aadHex")

            val plain = NativeKeyCustody.decryptWithHandle(handle, cipherHex, nonceHex, tagHex, aadHex)
            val out = Base64.encodeToString(plain, Base64.NO_WRAP)
            plain.fill(0)
            promise.resolve(out)
        } catch (e: Exception) {
            promise.reject("CUSTODY_DECRYPT_ERROR", e.message, e)
        }
    }

    // ── file-key wrap by handle (audit R2) ───────────────────────────────────────────────────

    /**
     * wrapKey({ handle, ivHex, plaintextHex }) — AES-256-CBC + HMAC (EtM) file-key wrap by handle.
     * plaintextHex is hex(utf8(fileKeyHexString)) so the CBC plaintext bytes match aesCbcEncryptRaw's
     * CryptoJS UTF-8 treatment of the file-key string. Resolves { ctHex, macHex }.
     */
    @ReactMethod
    fun wrapKey(params: ReadableMap, promise: Promise) {
        try {
            val handle       = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val ivHex        = params.getString("ivHex") ?: throw IllegalArgumentException("ivHex required")
            val plaintextHex = params.getString("plaintextHex") ?: throw IllegalArgumentException("plaintextHex required")

            val iv    = NativeKeyCustodyCrypto.fromHex(ivHex)
            val plain = NativeKeyCustodyCrypto.fromHex(plaintextHex)
            try {
                val w = NativeKeyCustody.wrapWithHandle(handle, iv, plain)
                val out = Arguments.createMap()
                out.putString("ctHex", w.ctHex)
                out.putString("macHex", w.macHex)
                promise.resolve(out)
            } finally {
                plain.fill(0)
            }
        } catch (e: Exception) {
            promise.reject("CUSTODY_WRAP_ERROR", e.message, e)
        }
    }

    /**
     * unwrapKey({ handle, ivHex, ctHex, macHex }) — EtM file-key unwrap by handle. Resolves the
     * recovered file-key STRING directly (the unwrapped bytes are the UTF-8 hex string), matching
     * aesCbcDecryptRaw's CryptoJS UTF-8 output. Rejects on tag mismatch.
     */
    @ReactMethod
    fun unwrapKey(params: ReadableMap, promise: Promise) {
        try {
            val handle = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            val ivHex  = params.getString("ivHex") ?: throw IllegalArgumentException("ivHex required")
            val ctHex  = params.getString("ctHex") ?: throw IllegalArgumentException("ctHex required")
            val macHex = params.getString("macHex") ?: throw IllegalArgumentException("macHex required")

            val plain = NativeKeyCustody.unwrapWithHandle(handle, ivHex, ctHex, macHex)
            val out = String(plain, StandardCharsets.UTF_8)
            plain.fill(0)
            promise.resolve(out)
        } catch (e: Exception) {
            promise.reject("CUSTODY_UNWRAP_ERROR", e.message, e)
        }
    }

    // ── lifecycle ────────────────────────────────────────────────────────────────────────────

    @ReactMethod
    fun hasHandle(params: ReadableMap, promise: Promise) {
        try {
            val handle = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            promise.resolve(NativeKeyCustody.hasHandle(handle))
        } catch (e: Exception) {
            promise.reject("CUSTODY_HAS_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun closeVault(params: ReadableMap, promise: Promise) {
        try {
            val handle = params.getString("handle") ?: throw IllegalArgumentException("handle required")
            promise.resolve(NativeKeyCustody.closeVault(handle))
        } catch (e: Exception) {
            promise.reject("CUSTODY_CLOSE_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun closeAll(promise: Promise) {
        try {
            NativeKeyCustody.closeAll()
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("CUSTODY_CLOSEALL_ERROR", e.message, e)
        }
    }

    // ReadableMap numbers arrive as Double; accept either a number or a numeric string.
    private fun readLong(params: ReadableMap, key: String, default: Long): Long {
        if (!params.hasKey(key) || params.isNull(key)) return default
        return when (params.getType(key)) {
            ReadableType.Number -> params.getDouble(key).toLong()
            ReadableType.String -> params.getString(key)!!.toLong()
            else -> default
        }
    }
}
