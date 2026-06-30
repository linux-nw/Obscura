package com.filevault.app.modules

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.sun.jna.NativeLong
import com.sun.jna.Pointer
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * NativeKeyCustody — libsodium secure-memory custody core (L3 Phase 1b).
 *
 * The master key lives ONLY here, in a sodium_malloc'd guarded region (guard pages +
 * canary + automatic zeroing on sodium_free), addressed by an opaque 128-bit handle.
 * The raw key never crosses the React bridge: JS holds the handle, never the key.
 *
 * ADDITIVE — NOT WIRED. No @ReactMethod, no bridge registration, no production caller.
 * It is built next to the existing path and exercised only by L3CustodyHandleTest until
 * Phase 2 eliminates getMasterKey() and routes encrypt/decrypt through this core.
 *
 * The crypto is the SAME as today, proven byte-identical: content AEAD is libsodium
 * XChaCha20-Poly1305 detached (identical to RNFileVaultModule.encrypt); file-key wrapping
 * is NativeKeyCustodyCrypto's AES-CBC+HMAC (Phase 1a parity, host 45/45). Only WHERE the
 * key lives changes. No ciphertext byte changes; no wire-format change.
 *
 * mlock: sodium_malloc locks the pages internally. Additionally an explicit sodium_mlock
 * probe is run once and its return CHECKED — on RLIMIT_MEMLOCK it is reported honestly
 * (isLockingAvailable()/Session.mlocked = false), never crashed, so a constrained device
 * degrades to "buffer may be swappable" instead of failing closed on unlock.
 *
 * Residual: lazysodium's AEAD/HMAC take a byte[] key, so each op copies the key out of the
 * guarded region into a short-lived JVM array that is sodium_memzero'd immediately after
 * (see withKey). That transient never crosses the bridge — same exposure the current native
 * path already has. The long-lived copy, the one a memory scrape would target, is the
 * guarded native region only.
 */
object NativeKeyCustody {

    private val ls = LazySodiumAndroid(SodiumAndroid())

    private class Session(val keyPtr: Pointer, val len: Int, val mlocked: Boolean)

    private val sessions = ConcurrentHashMap<String, Session>()

    @Volatile private var lockProbe: Boolean? = null

    /** One-time sodium_init plus an explicit, return-checked mlock capability probe. */
    @Synchronized
    fun ensureInit(): Boolean {
        if (lockProbe == null) {
            ls.sodium.sodium_init()
            val probe = ByteArray(32)
            val rc = ls.sodium.sodium_mlock(probe, probe.size) // RETURN CHECKED (RLIMIT_MEMLOCK)
            lockProbe = (rc == 0)
            if (rc == 0) ls.sodium.sodium_munlock(probe, probe.size)
            ls.sodium.sodium_memzero(probe, probe.size)
        }
        return lockProbe == true
    }

    /** True if the platform permits page-locking; false = secure buffers may be swappable. */
    fun isLockingAvailable(): Boolean = ensureInit()

    // ── opaque handle (128-bit random token, NOT the key) ───────────────────────────
    private fun newHandle(): String {
        val id = ByteArray(16)
        ls.sodium.randombytes_buf(id, id.size)
        return NativeKeyCustodyCrypto.toHex(id)
    }

    // ── store a raw key into a guarded secure-memory region ─────────────────────────
    private fun storeUnder(handle: String, rawKey: ByteArray): String {
        val mlocked = ensureInit()
        val ptr = ls.sodium.sodium_malloc(rawKey.size)
            ?: throw IllegalStateException("sodium_malloc returned null")
        ptr.write(0, rawKey, 0, rawKey.size)
        sessions[handle] = Session(ptr, rawKey.size, mlocked)
        return handle
    }

    private fun store(rawKey: ByteArray): String = storeUnder(newHandle(), rawKey)

    /**
     * Register an already-derived raw key. Used by tests and (Phase 2) by callers that have
     * unwrapped the key natively. The input copy is left to the caller to zero; we copy in.
     * NOT a bridge method — no raw key path is exposed to JS.
     */
    fun registerRawKey(rawKey: ByteArray): String = store(rawKey)

    /**
     * Adopt a raw key under a CALLER-PROVIDED opaque handle (L3 Phase 2b).
     *
     * The custody seam (KeyCustody.ts, native backing) mints the 128-bit handle JS-side so it
     * can track liveness synchronously, then hands the raw key here. This is the documented
     * ONE-TIME raw-key touch at vault creation / rotation (audit B1/B5) — the only path that
     * crosses the bridge with a raw key. In steady state (content/file-key ops) the key never
     * leaves this guarded region. Same store as registerRawKey, only the id is external.
     */
    fun adoptRawKey(handle: String, rawKey: ByteArray): String = storeUnder(handle, rawKey)

    /**
     * openVault — native KEK-unwrap of the master blob straight into secure memory.
     *
     * The passphrase is the only secret crossing the bridge (inherent — the user types it).
     * The KEK is derived natively (Argon2id, identical to deriveKEK), the master key is
     * EtM-unwrapped natively (identical to unlockKEK), and only the opaque handle is returned.
     * The raw master key never exists as a JS value.
     */
    fun openVault(
        password: ByteArray,
        kekSalt: ByteArray,
        opslimit: Long,
        memlimitKB: Long,
        ivHex: String,
        encMasterCtHex: String,
        macHex: String
    ): String {
        ensureInit()
        val kek = ByteArray(32) // Argon2id output == raw 32-byte KEK (matches deriveKEK)
        val rc = ls.sodium.crypto_pwhash(
            kek, kek.size.toLong(),
            password, password.size.toLong(),
            kekSalt,
            opslimit,
            NativeLong(memlimitKB * 1024L),
            2 // crypto_pwhash_ALG_ARGON2ID13
        )
        if (rc != 0) {
            ls.sodium.sodium_memzero(kek, kek.size)
            throw SecurityException("KEK derivation failed (rc=$rc)")
        }
        // Master blob plaintext is the 64-ASCII-hex master-key string, EtM-wrapped under the KEK.
        val masterAscii = NativeKeyCustodyCrypto.unwrapEtm(kek, ivHex, encMasterCtHex, macHex)
        ls.sodium.sodium_memzero(kek, kek.size)
        val masterRaw = NativeKeyCustodyCrypto.fromHex(String(masterAscii, StandardCharsets.UTF_8))
        ls.sodium.sodium_memzero(masterAscii, masterAscii.size)
        val handle = store(masterRaw)
        ls.sodium.sodium_memzero(masterRaw, masterRaw.size)
        return handle
    }

    /**
     * unwrapVaultWithKek — native EtM-unwrap of the master blob under an ALREADY-DERIVED KEK.
     *
     * The biometric path (loadMasterKeyForBiometric, audit B3) retrieves a raw 32-byte KEK from
     * hardware-backed storage — there is no passphrase to run Argon2id over. This is openVault's
     * tail without the KDF: verify the EtM tag, AES-CBC-decrypt the master, store it guarded,
     * return only the handle. Byte-identical MAC framing to wrapAndStoreMasterKey (utf8(ivHex+ctHex)).
     */
    fun unwrapVaultWithKek(kekHex: String, ivHex: String, encMasterCtHex: String, macHex: String): String {
        ensureInit()
        val kek = NativeKeyCustodyCrypto.fromHex(kekHex)
        try {
            val masterAscii = NativeKeyCustodyCrypto.unwrapEtm(kek, ivHex, encMasterCtHex, macHex)
            val masterRaw = NativeKeyCustodyCrypto.fromHex(String(masterAscii, StandardCharsets.UTF_8))
            ls.sodium.sodium_memzero(masterAscii, masterAscii.size)
            val handle = store(masterRaw)
            ls.sodium.sodium_memzero(masterRaw, masterRaw.size)
            return handle
        } finally {
            ls.sodium.sodium_memzero(kek, kek.size)
        }
    }

    /**
     * rewrapVault — re-wrap the LIVE master key under a new passphrase, natively (audit R3, changePassphrase).
     *
     * The master never returns to JS: a new KEK is derived (Argon2id, NFC-normalised password
     * supplied by the bridge), and the master — re-materialised as its 64-ASCII-hex string, exactly
     * the plaintext wrapAndStoreMasterKey wraps — is EtM-wrapped under the new KEK. Only the new
     * {ct, mac} blob is returned for storage; the new IV is the caller's. Same master key, new wrap.
     */
    fun rewrapVault(
        handle: String,
        newPassword: ByteArray,
        newSalt: ByteArray,
        opslimit: Long,
        memlimitKB: Long,
        newIv: ByteArray
    ): NativeKeyCustodyCrypto.Wrapped {
        ensureInit()
        val newKek = ByteArray(32)
        val rc = ls.sodium.crypto_pwhash(
            newKek, newKek.size.toLong(),
            newPassword, newPassword.size.toLong(),
            newSalt,
            opslimit,
            NativeLong(memlimitKB * 1024L),
            2 // crypto_pwhash_ALG_ARGON2ID13
        )
        if (rc != 0) {
            ls.sodium.sodium_memzero(newKek, newKek.size)
            throw SecurityException("KEK derivation failed (rc=$rc)")
        }
        try {
            return withKey(handle) { masterRaw ->
                // Wrap plaintext == the 64-ASCII-hex master string (matches wrapAndStoreMasterKey).
                val masterAscii = NativeKeyCustodyCrypto.toHex(masterRaw).toByteArray(StandardCharsets.UTF_8)
                try {
                    NativeKeyCustodyCrypto.wrapEtm(newKek, newIv, masterAscii)
                } finally {
                    ls.sodium.sodium_memzero(masterAscii, masterAscii.size)
                }
            }
        } finally {
            ls.sodium.sodium_memzero(newKek, newKek.size)
        }
    }

    private fun session(handle: String): Session =
        sessions[handle] ?: throw IllegalArgumentException("invalid or closed handle")

    /** Read the key out of the guarded region into a transient that is zeroed after use. */
    private fun <T> withKey(handle: String, block: (ByteArray) -> T): T {
        val s = session(handle)
        val k = ByteArray(s.len)
        s.keyPtr.read(0, k, 0, s.len)
        try {
            return block(k)
        } finally {
            ls.sodium.sodium_memzero(k, k.size)
        }
    }

    // ── content AEAD by handle (XChaCha20-Poly1305 detached, same as RNFileVaultModule) ──
    data class Aead(val cipherHex: String, val tagHex: String)

    fun encryptWithHandle(handle: String, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray?): Aead =
        withKey(handle) { key ->
            val ct = ByteArray(plaintext.size)
            val mac = ByteArray(16)
            val macLen = LongArray(1)
            val r = ls.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                ct, mac, macLen,
                plaintext, plaintext.size.toLong(),
                aad, (aad?.size ?: 0).toLong(),
                null,
                nonce, key
            )
            if (r != 0) throw SecurityException("encryptWithHandle failed (rc=$r)")
            Aead(NativeKeyCustodyCrypto.toHex(ct), NativeKeyCustodyCrypto.toHex(mac))
        }

    fun decryptWithHandle(
        handle: String, cipherHex: String, nonceHex: String, tagHex: String, aadHex: String?
    ): ByteArray =
        withKey(handle) { key ->
            val ct = NativeKeyCustodyCrypto.fromHex(cipherHex)
            val nonce = NativeKeyCustodyCrypto.fromHex(nonceHex)
            val mac = NativeKeyCustodyCrypto.fromHex(tagHex)
            val aad = if (aadHex.isNullOrEmpty()) null else NativeKeyCustodyCrypto.fromHex(aadHex)
            val pt = ByteArray(ct.size)
            val r = ls.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                pt, null,
                ct, ct.size.toLong(),
                mac,
                aad, (aad?.size ?: 0).toLong(),
                nonce, key
            )
            if (r != 0) throw SecurityException("decryptWithHandle failed — integrity check")
            pt
        }

    // ── file-key wrap by handle (AES-CBC+HMAC via the Phase 1a parity-proven primitive) ──
    fun wrapWithHandle(handle: String, iv: ByteArray, plaintext: ByteArray): NativeKeyCustodyCrypto.Wrapped =
        withKey(handle) { key -> NativeKeyCustodyCrypto.wrapEtm(key, iv, plaintext) }

    fun unwrapWithHandle(handle: String, ivHex: String, ctHex: String, macHex: String): ByteArray =
        withKey(handle) { key -> NativeKeyCustodyCrypto.unwrapEtm(key, ivHex, ctHex, macHex) }

    // ── lifecycle ───────────────────────────────────────────────────────────────────
    fun isMlocked(handle: String): Boolean = session(handle).mlocked

    fun hasHandle(handle: String): Boolean = sessions.containsKey(handle)

    /** memzero + sodium_free (canary-checked) + invalidate. Subsequent ops on the handle throw. */
    fun closeVault(handle: String): Boolean {
        val s = sessions.remove(handle) ?: return false
        ls.sodium.sodium_mprotect_readwrite(s.keyPtr)
        ls.sodium.sodium_free(s.keyPtr) // zeroes the guarded region + verifies the canary
        return true
    }

    fun closeAll() {
        for (h in sessions.keys.toList()) closeVault(h)
    }
}
