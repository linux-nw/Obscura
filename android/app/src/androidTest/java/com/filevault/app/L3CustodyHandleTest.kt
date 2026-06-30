package com.filevault.app

import com.filevault.app.modules.NativeKeyCustody
import com.filevault.app.modules.NativeKeyCustodyCrypto
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.sun.jna.NativeLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * L3 Phase 1b — on-device test for the secure-memory custody core (NativeKeyCustody).
 *
 * Proves, on the real device, that routing through an opaque handle changes NO ciphertext:
 *   1. encryptWithHandle == a direct XChaCha20-Poly1305 call with the raw key (byte-identical),
 *      and decryptWithHandle round-trips;
 *   2. wrapWithHandle == the Phase 1a golden file-key blob (custody wrap == JS path);
 *   3. openVault performs the KEK-unwrap natively: the handle holds the right key (its AEAD
 *      output matches the raw-key output), and the handle is NOT the key;
 *   4. closeVault invalidates — subsequent ops throw, hasHandle == false;
 *   5. the mlock probe runs without crashing and reports a boolean (RLIMIT_MEMLOCK honest path).
 *
 * NativeKeyCustody has no production caller yet (Phase 2 wires it); this is its only caller.
 */
@RunWith(AndroidJUnit4::class)
class L3CustodyHandleTest {

    private val ls = LazySodiumAndroid(SodiumAndroid())

    private val KEY = NativeKeyCustodyCrypto.fromHex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    private val IV = NativeKeyCustodyCrypto.fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    private val LEN64_CT = "022ae7d0cd5faf24b4e0eb876a4ec72b8d16c3b2605112040878bd74eced6027" +
        "ea64182be6550e67b30c91df8cfdaefdcba95faf5c70237fb17e671ad30b4e81b9556c1c7231f21c47ef789bc3c35c94"
    private val LEN64_MAC = "c4a2ce82f195e31c83540fec63dbbf020de4ffc50a09bee29b2be128b5c2c0d7"

    private fun plain(len: Int): ByteArray =
        (0 until len).map { (33 + it % 90).toChar() }.joinToString("").toByteArray(Charsets.UTF_8)

    /** Direct XChaCha20-Poly1305 detached with the raw key — the reference the handle path must match. */
    private fun directEncrypt(key: ByteArray, pt: ByteArray, nonce: ByteArray, aad: ByteArray?): Pair<String, String> {
        val ct = ByteArray(pt.size); val mac = ByteArray(16); val macLen = LongArray(1)
        val r = ls.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ct, mac, macLen, pt, pt.size.toLong(), aad, (aad?.size ?: 0).toLong(), null, nonce, key)
        assertEquals(0, r)
        return NativeKeyCustodyCrypto.toHex(ct) to NativeKeyCustodyCrypto.toHex(mac)
    }

    @Test
    fun encryptWithHandleMatchesRawKeyAndRoundtrips() {
        val handle = NativeKeyCustody.registerRawKey(KEY)
        assertEquals(32, handle.length)          // 128-bit hex token
        assertNotEquals(NativeKeyCustodyCrypto.toHex(KEY), handle) // handle is NOT the key

        val pt = "secret content payload".toByteArray(Charsets.UTF_8)
        val nonce = NativeKeyCustodyCrypto.fromHex("".padEnd(48, '7')) // 24-byte nonce
        val aad = NativeKeyCustodyCrypto.fromHex("01")

        val direct = directEncrypt(KEY, pt, nonce, aad)
        val viaHandle = NativeKeyCustody.encryptWithHandle(handle, pt, nonce, aad)
        assertEquals(direct.first, viaHandle.cipherHex)   // byte-identical ciphertext
        assertEquals(direct.second, viaHandle.tagHex)     // byte-identical tag

        val back = NativeKeyCustody.decryptWithHandle(
            handle, viaHandle.cipherHex, NativeKeyCustodyCrypto.toHex(nonce), viaHandle.tagHex, "01")
        assertEquals(String(pt, Charsets.UTF_8), String(back, Charsets.UTF_8))
        NativeKeyCustody.closeVault(handle)
    }

    @Test
    fun wrapWithHandleMatchesPhase1aGolden() {
        val handle = NativeKeyCustody.registerRawKey(KEY)
        val w = NativeKeyCustody.wrapWithHandle(handle, IV, plain(64))
        assertEquals(LEN64_CT, w.ctHex)
        assertEquals(LEN64_MAC, w.macHex)
        // unwrap recovers byte-identical plaintext
        val back = NativeKeyCustody.unwrapWithHandle(handle, NativeKeyCustodyCrypto.toHex(IV), LEN64_CT, LEN64_MAC)
        assertEquals(String(plain(64), Charsets.UTF_8), String(back, Charsets.UTF_8))
        NativeKeyCustody.closeVault(handle)
    }

    @Test
    fun openVaultUnwrapsMasterNativelyAndIsClosable() {
        // Build a real master blob: master key wrapped (EtM) under an Argon2id KEK.
        val passphrase = "device-test-passphrase".toByteArray(Charsets.UTF_8)
        val salt = NativeKeyCustodyCrypto.fromHex("0102030405060708090a0b0c0d0e0f10") // 16 bytes
        val ops = 2L
        val memKB = 8192L
        val kek = ByteArray(32)
        assertEquals(0, ls.sodium.crypto_pwhash(
            kek, kek.size.toLong(), passphrase, passphrase.size.toLong(), salt,
            ops, NativeLong(memKB * 1024L), 2))
        val masterHex = "ab".repeat(32)                  // known 32-byte master key as 64-hex ASCII
        val wrapped = NativeKeyCustodyCrypto.wrapEtm(kek, IV, masterHex.toByteArray(Charsets.UTF_8))

        val handle = NativeKeyCustody.openVault(
            passphrase, salt, ops, memKB, NativeKeyCustodyCrypto.toHex(IV), wrapped.ctHex, wrapped.macHex)
        assertNotEquals(masterHex, handle)

        // The custody key must equal the wrapped master key: handle AEAD == raw-master AEAD.
        val pt = "x".repeat(40).toByteArray(Charsets.UTF_8)
        val nonce = NativeKeyCustodyCrypto.fromHex("ab".repeat(24))
        val direct = directEncrypt(NativeKeyCustodyCrypto.fromHex(masterHex), pt, nonce, null)
        val viaHandle = NativeKeyCustody.encryptWithHandle(handle, pt, nonce, null)
        assertEquals(direct.first, viaHandle.cipherHex)
        assertEquals(direct.second, viaHandle.tagHex)

        // mlock probe is a boolean, never a crash.
        val locked = NativeKeyCustody.isMlocked(handle)
        assertTrue(locked || !locked)

        // closeVault invalidates the handle.
        assertTrue(NativeKeyCustody.closeVault(handle))
        assertFalse(NativeKeyCustody.hasHandle(handle))
        assertThrows(IllegalArgumentException::class.java) {
            NativeKeyCustody.encryptWithHandle(handle, pt, nonce, null)
        }
    }
}
