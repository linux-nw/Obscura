package com.filevault.app

import com.filevault.app.modules.NativeKeyCustodyCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * L3 Phase 1a — on-device parity Known-Answer Test for NativeKeyCustodyCrypto.
 *
 * Pins the native JCA path to the SAME golden vectors the JS production primitives emit
 * (__tests__/L3_CustodyParity.test.ts -> tools/parity/L3ParityHarness.java, host-proven 45/45).
 * Confirms on the real Android security provider that:
 *   1. AES-256-CBC/PKCS7 == CryptoJS PKCS7, incl. the exact block-boundary case (16 -> 32 bytes);
 *   2. HKDF-SHA256(filevault-mac-v1) + HMAC-SHA256 == deriveMacKey/computeMac;
 *   3. a pre-rebuild Encrypt-then-MAC blob (64-byte file-key plaintext -> 80-byte ct)
 *      verifies + decrypts + re-encrypts byte-identical through the native path.
 *
 * If any vector diverges, the file-key path cannot move to native custody without changing
 * the wire format (forbidden) -> L3-file-key stays Partial. No production code is wired to
 * NativeKeyCustodyCrypto yet; this test is its only caller.
 */
@RunWith(AndroidJUnit4::class)
class L3CustodyParityTest {

    private val KEY = NativeKeyCustodyCrypto.fromHex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    private val IV = NativeKeyCustodyCrypto.fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

    // plain[i] = char(33 + i % 90), matching the JS reference generator (ASCII).
    private fun plain(len: Int): ByteArray =
        (0 until len).map { (33 + it % 90).toChar() }.joinToString("").toByteArray(Charsets.UTF_8)

    private val MACKEY_HEX = "9b10c116efd8dffd4b0e30709d4af53725daf41d067f87250719a7bf747197ce"
    private val LEN16_CT = "022ae7d0cd5faf24b4e0eb876a4ec72b23aa5c9dd1ecddd170c986dbbb72f76b"
    private val LEN64_CT = "022ae7d0cd5faf24b4e0eb876a4ec72b8d16c3b2605112040878bd74eced6027" +
        "ea64182be6550e67b30c91df8cfdaefdcba95faf5c70237fb17e671ad30b4e81b9556c1c7231f21c47ef789bc3c35c94"
    private val LEN64_MAC = "c4a2ce82f195e31c83540fec63dbbf020de4ffc50a09bee29b2be128b5c2c0d7"

    @Test
    fun aesCbcMatchesCryptoJsAtBlockBoundary() {
        // 16-byte input -> PKCS7 adds a full padding block -> 32-byte ciphertext.
        val ct16 = NativeKeyCustodyCrypto.aesCbcEncrypt(KEY, IV, plain(16))
        assertEquals(32, ct16.size)
        assertEquals(LEN16_CT, NativeKeyCustodyCrypto.toHex(ct16))
        assertEquals(
            String(plain(16), Charsets.UTF_8),
            String(NativeKeyCustodyCrypto.aesCbcDecrypt(KEY, IV, ct16), Charsets.UTF_8))

        // 64-byte input (file-key size) -> 80-byte ciphertext.
        val ct64 = NativeKeyCustodyCrypto.aesCbcEncrypt(KEY, IV, plain(64))
        assertEquals(80, ct64.size)
        assertEquals(LEN64_CT, NativeKeyCustodyCrypto.toHex(ct64))
    }

    @Test
    fun hkdfAndHmacMatchJs() {
        assertEquals(MACKEY_HEX, NativeKeyCustodyCrypto.toHex(NativeKeyCustodyCrypto.deriveMacKey(KEY)))
        assertEquals(
            "7eb3dc397bbca0b17cae61282b8e4e1ffb0d242a68a265d573307f0a6bd9daae",
            NativeKeyCustodyCrypto.toHex(
                NativeKeyCustodyCrypto.hmacSha256(
                    NativeKeyCustodyCrypto.fromHex(MACKEY_HEX), "abc".toByteArray(Charsets.UTF_8))))
    }

    @Test
    fun etmWrapUnwrapBlobByteIdentical() {
        // Wrap == the stored Encrypt-then-MAC blob.
        val w = NativeKeyCustodyCrypto.wrapEtm(KEY, IV, plain(64))
        assertEquals(LEN64_CT, w.ctHex)
        assertEquals(LEN64_MAC, w.macHex)

        // Pre-rebuild blob decrypts byte-identical through the native path.
        val dec = NativeKeyCustodyCrypto.unwrapEtm(KEY, NativeKeyCustodyCrypto.toHex(IV), LEN64_CT, LEN64_MAC)
        assertEquals(String(plain(64), Charsets.UTF_8), String(dec, Charsets.UTF_8))

        // Tampered tag -> reject, no decrypt.
        val badMac = LEN64_MAC.dropLast(2) + "00"
        assertThrows(SecurityException::class.java) {
            NativeKeyCustodyCrypto.unwrapEtm(KEY, NativeKeyCustodyCrypto.toHex(IV), LEN64_CT, badMac)
        }
    }
}
