package com.filevault.app

import com.filevault.app.modules.NativeKeyCustody
import com.filevault.app.modules.NativeKeyCustodyCrypto
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.sun.jna.NativeLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.text.Normalizer

/**
 * L3 Phase 4 device ceremony — exercises the three 2b NativeKeyCustody methods
 * (adoptRawKey, unwrapVaultWithKek, rewrapVault) that have never run on a real device.
 *
 * Runs entirely at the NativeKeyCustody object layer, same as L3CustodyHandleTest.
 * Each test is self-contained (no shared state between tests).
 * Runs in order: 4a -> 4b -> 4c -> 4d -> 4e -> 4f.
 * On the first failure the suite stops and reports.
 *
 * Argon2id params (opslimit=2, memlimit=8 MB) are kept low for test speed. The
 * production values (3 / 64 MB) are exercised in the app flow; the KDF output
 * format is identical regardless of the cost parameters.
 */
@RunWith(AndroidJUnit4::class)
class L3Phase4CeremonyTest {

    private val ls = LazySodiumAndroid(SodiumAndroid())

    // Fixed test material — deterministic across runs.
    private val MASTER_HEX  = "ab".repeat(32)                         // 64 hex = 32-byte master key
    private val PASSPHRASE   = "ceremony-passphrase-2b"
    private val NEW_PASSPHRASE = "ceremony-new-passphrase"
    private val SALT_HEX    = "0102030405060708090a0b0c0d0e0f10"      // 16 bytes (Argon2id)
    private val IV_HEX      = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"      // 16 bytes (AES-CBC)
    private val NONCE_HEX   = "77".repeat(24)                          // 24 bytes (XChaCha20)
    private val AAD_HEX     = "01"                                      // backend prefix 0x01
    private val OPSLIMIT    = 2L
    private val MEMLIMIT_KB = 8192L

    // ── helpers ──────────────────────────────────────────────────────────────────

    /** Argon2id KEK derivation identical to CryptoService.deriveKEK (NFC + ALG_ARGON2ID13). */
    private fun deriveKek(passphrase: String): ByteArray {
        val pw   = Normalizer.normalize(passphrase, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val kek  = ByteArray(32)
        val rc   = ls.sodium.crypto_pwhash(
            kek, kek.size.toLong(),
            pw, pw.size.toLong(),
            salt, OPSLIMIT, NativeLong(MEMLIMIT_KB * 1024L),
            2 /* ALG_ARGON2ID13 */)
        ls.sodium.sodium_memzero(pw, pw.size)
        assertEquals("Argon2id KEK derivation (rc=$rc)", 0, rc)
        return kek
    }

    /** EtM-wrap MASTER_HEX under a KEK — the same shape as CryptoService.wrapAndStoreMasterKey. */
    private fun buildBlob(kek: ByteArray, ivHex: String): NativeKeyCustodyCrypto.Wrapped {
        val iv          = NativeKeyCustodyCrypto.fromHex(ivHex)
        val masterAscii = MASTER_HEX.toByteArray(Charsets.UTF_8) // 64 ASCII bytes
        return NativeKeyCustodyCrypto.wrapEtm(kek, iv, masterAscii)
    }

    /** Direct libsodium XChaCha20-Poly1305 AEAD encrypt — the reference for handle path parity. */
    private fun directEncrypt(masterHex: String, pt: ByteArray): Pair<String, String> {
        val key   = NativeKeyCustodyCrypto.fromHex(masterHex)
        val nonce = NativeKeyCustodyCrypto.fromHex(NONCE_HEX)
        val aad   = NativeKeyCustodyCrypto.fromHex(AAD_HEX)
        val ct    = ByteArray(pt.size); val mac = ByteArray(16); val macLen = LongArray(1)
        val rc    = ls.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ct, mac, macLen, pt, pt.size.toLong(), aad, aad.size.toLong(), null, nonce, key)
        ls.sodium.sodium_memzero(key, key.size)
        assertEquals("directEncrypt rc=$rc", 0, rc)
        return NativeKeyCustodyCrypto.toHex(ct) to NativeKeyCustodyCrypto.toHex(mac)
    }

    // ── 4a: passphrase unlock (openVault = Argon2id KEK + EtM unwrap, native) ───

    @Test
    fun test4a_openVault_passphraseUnlock() {
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        ls.sodium.sodium_memzero(kek, kek.size)

        val pw   = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val handle = NativeKeyCustody.openVault(pw, salt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        ls.sodium.sodium_memzero(pw, pw.size)

        assertEquals("handle length", 32, handle.length)
        assertNotEquals("handle != raw key", MASTER_HEX, handle)
        assertTrue("hasHandle after open", NativeKeyCustody.hasHandle(handle))

        // Key parity: handle AEAD == direct AEAD with raw master
        val pt          = "4a-passphrase-unlock-verify".toByteArray(Charsets.UTF_8)
        val (expCt, expMac) = directEncrypt(MASTER_HEX, pt)
        val viaHandle   = NativeKeyCustody.encryptWithHandle(
            handle, pt, NativeKeyCustodyCrypto.fromHex(NONCE_HEX), NativeKeyCustodyCrypto.fromHex(AAD_HEX))
        assertEquals("4a ciphertext parity", expCt,  viaHandle.cipherHex)
        assertEquals("4a tag parity",        expMac, viaHandle.tagHex)

        // Wrong passphrase -> SecurityException
        val badPw   = "wrong-passphrase".toByteArray(Charsets.UTF_8)
        val badSalt = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        assertThrows(SecurityException::class.java) {
            NativeKeyCustody.openVault(badPw, badSalt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        }

        NativeKeyCustody.closeVault(handle)
    }

    // ── 4b: content AEAD roundtrip (encryptWithHandle / decryptWithHandle) ───────

    @Test
    fun test4b_contentAeadRoundtrip() {
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        ls.sodium.sodium_memzero(kek, kek.size)

        val pw     = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt   = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val handle = NativeKeyCustody.openVault(pw, salt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        ls.sodium.sodium_memzero(pw, pw.size)

        val plain  = "4b content roundtrip — XChaCha20-Poly1305 on S22+".toByteArray(Charsets.UTF_8)
        val nonce  = NativeKeyCustodyCrypto.fromHex(NONCE_HEX)
        val aad    = NativeKeyCustodyCrypto.fromHex(AAD_HEX)

        val enc = NativeKeyCustody.encryptWithHandle(handle, plain, nonce, aad)
        assertNotEquals("ciphertext != plaintext", NativeKeyCustodyCrypto.toHex(plain), enc.cipherHex)

        val dec = NativeKeyCustody.decryptWithHandle(handle, enc.cipherHex, NONCE_HEX, enc.tagHex, AAD_HEX)
        assertArrayEquals("4b round-trip", plain, dec)

        // Tag flip -> hard reject
        val badTag = enc.tagHex.dropLast(2) + "00"
        assertThrows(SecurityException::class.java) {
            NativeKeyCustody.decryptWithHandle(handle, enc.cipherHex, NONCE_HEX, badTag, AAD_HEX)
        }

        NativeKeyCustody.closeVault(handle)
    }

    // ── 4c: file-key EtM wrap / unwrap roundtrip ─────────────────────────────────

    @Test
    fun test4c_fileKeyWrapRoundtrip() {
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        ls.sodium.sodium_memzero(kek, kek.size)

        val pw     = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt   = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val handle = NativeKeyCustody.openVault(pw, salt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        ls.sodium.sodium_memzero(pw, pw.size)

        // Plaintext = UTF-8 bytes of the 64-hex file-key string (matches utf8ToHex on the JS side)
        val fileKeyHex   = "cd".repeat(32)
        val plaintextBytes = fileKeyHex.toByteArray(Charsets.UTF_8)
        val iv             = NativeKeyCustodyCrypto.fromHex(IV_HEX)

        val wrapped   = NativeKeyCustody.wrapWithHandle(handle, iv, plaintextBytes)
        val unwrapped = NativeKeyCustody.unwrapWithHandle(handle, IV_HEX, wrapped.ctHex, wrapped.macHex)
        assertEquals("4c file-key roundtrip", fileKeyHex, String(unwrapped, Charsets.UTF_8))

        // MAC tamper -> SecurityException
        val badMac = wrapped.macHex.dropLast(2) + "ff"
        assertThrows(SecurityException::class.java) {
            NativeKeyCustody.unwrapWithHandle(handle, IV_HEX, wrapped.ctHex, badMac)
        }

        NativeKeyCustody.closeVault(handle)
    }

    // ── 4d: changePassphrase roundtrip (rewrapVault + re-open with new passphrase)

    @Test
    fun test4d_changePassphraseRoundtrip() {
        // Open vault under original passphrase.
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        ls.sodium.sodium_memzero(kek, kek.size)

        val pw     = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt   = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val handle = NativeKeyCustody.openVault(pw, salt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        ls.sodium.sodium_memzero(pw, pw.size)

        // Re-wrap master under new passphrase (natively — master never returns to caller).
        val newSaltHex = "a0b1c2d3e4f5060718293a4b5c6d7e8f"
        val newIvHex   = "f0e1d2c3b4a5968778695a4b3c2d1e0f"
        val newPw      = Normalizer.normalize(NEW_PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val newSalt    = NativeKeyCustodyCrypto.fromHex(newSaltHex)
        val newIv      = NativeKeyCustodyCrypto.fromHex(newIvHex)

        val rewrapped = NativeKeyCustody.rewrapVault(handle, newPw, newSalt, OPSLIMIT, MEMLIMIT_KB, newIv)
        ls.sodium.sodium_memzero(newPw, newPw.size)

        // Original handle remains live (same master key in secure memory).
        assertTrue("handle still live after rewrap", NativeKeyCustody.hasHandle(handle))

        // Open vault with NEW passphrase + new blob — must resolve the SAME master key.
        val newPw2     = Normalizer.normalize(NEW_PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val newSalt2   = NativeKeyCustodyCrypto.fromHex(newSaltHex)
        val handle2    = NativeKeyCustody.openVault(
            newPw2, newSalt2, OPSLIMIT, MEMLIMIT_KB, newIvHex, rewrapped.ctHex, rewrapped.macHex)
        ls.sodium.sodium_memzero(newPw2, newPw2.size)

        // Both handles must produce byte-identical AEAD: same underlying master key.
        val pt   = "4d-passphrase-change-verify".toByteArray(Charsets.UTF_8)
        val enc1 = NativeKeyCustody.encryptWithHandle(
            handle, pt, NativeKeyCustodyCrypto.fromHex(NONCE_HEX), NativeKeyCustodyCrypto.fromHex(AAD_HEX))
        val dec2 = NativeKeyCustody.decryptWithHandle(handle2, enc1.cipherHex, NONCE_HEX, enc1.tagHex, AAD_HEX)
        assertArrayEquals("4d cross-handle decrypt (same master key)", pt, dec2)

        // Old passphrase against new blob -> SecurityException (wrong KEK -> MAC mismatch).
        val oldPw   = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val oldSalt = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        assertThrows(SecurityException::class.java) {
            NativeKeyCustody.openVault(oldPw, oldSalt, OPSLIMIT, MEMLIMIT_KB, newIvHex, rewrapped.ctHex, rewrapped.macHex)
        }
        ls.sodium.sodium_memzero(oldPw, oldPw.size)

        NativeKeyCustody.closeVault(handle)
        NativeKeyCustody.closeVault(handle2)
    }

    // ── 4e: biometric unlock roundtrip (unwrapVaultWithKek, no Argon2id) ─────────

    @Test
    fun test4e_biometricUnwrapVaultWithKek() {
        // Simulate enableBioUnlock: derive KEK, store it (hardware-backed in production),
        // and build the master blob. Here we just keep kekHex in memory for the test.
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        val kekHex = NativeKeyCustodyCrypto.toHex(kek)
        ls.sodium.sodium_memzero(kek, kek.size)

        // Biometric unlock path: KEK already available, no Argon2id.
        val handle = NativeKeyCustody.unwrapVaultWithKek(kekHex, IV_HEX, blob.ctHex, blob.macHex)

        assertEquals("handle length", 32, handle.length)
        assertNotEquals("handle != raw key", MASTER_HEX, handle)
        assertTrue("hasHandle after bio-unlock", NativeKeyCustody.hasHandle(handle))

        // Key parity: handle AEAD == direct AEAD with raw master
        val pt             = "4e-biometric-unlock-verify".toByteArray(Charsets.UTF_8)
        val (expCt, expMac) = directEncrypt(MASTER_HEX, pt)
        val viaHandle      = NativeKeyCustody.encryptWithHandle(
            handle, pt, NativeKeyCustodyCrypto.fromHex(NONCE_HEX), NativeKeyCustodyCrypto.fromHex(AAD_HEX))
        assertEquals("4e ciphertext parity", expCt,  viaHandle.cipherHex)
        assertEquals("4e tag parity",        expMac, viaHandle.tagHex)

        // Wrong KEK -> SecurityException (MAC mismatch in unwrapEtm).
        val badKekHex = "00".repeat(32)
        assertThrows(SecurityException::class.java) {
            NativeKeyCustody.unwrapVaultWithKek(badKekHex, IV_HEX, blob.ctHex, blob.macHex)
        }

        NativeKeyCustody.closeVault(handle)
    }

    // ── 4f: lock / re-lock / closeAll ────────────────────────────────────────────

    @Test
    fun test4f_lockAndRelockAndCloseAll() {
        val kek  = deriveKek(PASSPHRASE)
        val blob = buildBlob(kek, IV_HEX)
        ls.sodium.sodium_memzero(kek, kek.size)

        val pw     = Normalizer.normalize(PASSPHRASE, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val salt   = NativeKeyCustodyCrypto.fromHex(SALT_HEX)
        val handle = NativeKeyCustody.openVault(pw, salt, OPSLIMIT, MEMLIMIT_KB, IV_HEX, blob.ctHex, blob.macHex)
        ls.sodium.sodium_memzero(pw, pw.size)
        assertTrue("hasHandle before close", NativeKeyCustody.hasHandle(handle))

        // closeVault zeros the guarded region and invalidates the handle.
        assertTrue("closeVault returns true", NativeKeyCustody.closeVault(handle))
        assertFalse("hasHandle after close", NativeKeyCustody.hasHandle(handle))
        assertThrows(IllegalArgumentException::class.java) {
            NativeKeyCustody.encryptWithHandle(
                handle, ByteArray(1), NativeKeyCustodyCrypto.fromHex(NONCE_HEX), null)
        }

        // closeVault is idempotent.
        assertFalse("closeVault on closed handle returns false", NativeKeyCustody.closeVault(handle))

        // adoptRawKey (audit B1/B5 path) + closeAll clears multiple handles at once.
        val h1 = NativeKeyCustody.adoptRawKey("aa".repeat(16), NativeKeyCustodyCrypto.fromHex("cc".repeat(32)))
        val h2 = NativeKeyCustody.adoptRawKey("bb".repeat(16), NativeKeyCustodyCrypto.fromHex("dd".repeat(32)))
        assertTrue("h1 live",  NativeKeyCustody.hasHandle(h1))
        assertTrue("h2 live",  NativeKeyCustody.hasHandle(h2))
        NativeKeyCustody.closeAll()
        assertFalse("h1 dead after closeAll", NativeKeyCustody.hasHandle(h1))
        assertFalse("h2 dead after closeAll", NativeKeyCustody.hasHandle(h2))
    }
}
