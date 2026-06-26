package com.filevault.app

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * FIX 2 — On-device test for the native XChaCha20-Poly1305-IETF bridge.
 *
 * RNFileVaultModule.encrypt/decrypt are React bridge methods (ReadableMap + Promise),
 * so this test calls the SAME libsodium primitives the module uses
 * (`crypto_aead_xchacha20poly1305_ietf_encrypt_detached` / `_decrypt_detached`,
 * detached MAC, with AAD) to exercise the real JNI path on a device/emulator.
 *
 * Covers: official KAT vector (S4), roundtrip, AEAD tamper detection, AAD binding
 * (H2/A3), determinism.
 *
 * S4: `xchacha20_official_kat_a31` pins the published draft-irtf-cfrg-xchacha-03 §A.3.1
 * AEAD vector. The expected ciphertext/tag bytes are the SAME constants asserted by the
 * JS reference (__tests__/XChaCha20KAT.test.ts, @noble/ciphers). Native libsodium and
 * @noble/ciphers both matching the published vector ⇒ byte-identical (cross-impl, S4).
 *
 * Requires in android/app/build.gradle:
 *   androidTestImplementation "androidx.test.ext:junit:1.1.5"
 *   androidTestImplementation "androidx.test:runner:1.5.2"
 * and defaultConfig.testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner".
 * Run: ./gradlew connectedAndroidTest   (emulator API 28+)
 */
@RunWith(AndroidJUnit4::class)
class XChaCha20BridgeTest {

    private val ls = LazySodiumAndroid(SodiumAndroid())
    private val ABYTES = 16 // crypto_aead_xchacha20poly1305_ietf_ABYTES

    private fun random(n: Int): ByteArray {
        val b = ByteArray(n)
        ls.sodium.randombytes_buf(b, n)
        return b
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /**
     * S4 — official Known-Answer Test, draft-irtf-cfrg-xchacha-03 §A.3.1.
     * Pins the native libsodium output to the published vector. The expected ct/tag are
     * the same constants the JS reference (@noble/ciphers) asserts in
     * __tests__/XChaCha20KAT.test.ts.
     */
    @Test
    fun xchacha20_official_kat_a31() {
        val key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657") // 24 bytes
        val aad = hexToBytes("50515253c0c1c2c3c4c5c6c7")
        val plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .toByteArray(Charsets.UTF_8)

        val expectedCt =
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52e"
        val expectedTag = "c0875924c1c7987947deafd8780acf49"

        val (ct, mac) = encrypt(plain, aad, nonce, key)
        assertEquals("ciphertext must match the §A.3.1 KAT", expectedCt, bytesToHex(ct))
        assertEquals("tag must match the §A.3.1 KAT", expectedTag, bytesToHex(mac))

        // And the same vector must decrypt back to the plaintext.
        val (rc, out) = decrypt(ct, mac, aad, nonce, key)
        assertEquals("decrypt rc", 0, rc)
        assertArrayEquals(plain, out)
    }

    private fun encrypt(plain: ByteArray, aad: ByteArray, nonce: ByteArray, key: ByteArray): Pair<ByteArray, ByteArray> {
        val ct = ByteArray(plain.size)
        val mac = ByteArray(ABYTES)
        val macLen = LongArray(1)
        val rc = ls.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ct, mac, macLen,
            plain, plain.size.toLong(),
            aad, aad.size.toLong(),
            null,
            nonce, key
        )
        assertEquals("encrypt rc", 0, rc)
        return Pair(ct, mac)
    }

    private fun decrypt(ct: ByteArray, mac: ByteArray, aad: ByteArray, nonce: ByteArray, key: ByteArray): Pair<Int, ByteArray> {
        val out = ByteArray(ct.size)
        val rc = ls.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            out, null,
            ct, ct.size.toLong(),
            mac,
            aad, aad.size.toLong(),
            nonce, key
        )
        return Pair(rc, out)
    }

    @Test
    fun xchacha20_roundtrip() {
        val key = random(32); val nonce = random(24)
        val plain = "Hello FileVault 🔐".toByteArray(Charsets.UTF_8)
        val aad = "testfile:content:v1".toByteArray(Charsets.UTF_8)

        val (ct, mac) = encrypt(plain, aad, nonce, key)
        val (rc, out) = decrypt(ct, mac, aad, nonce, key)

        assertEquals("decrypt rc", 0, rc)
        assertArrayEquals(plain, out)
    }

    @Test
    fun xchacha20_tamper_detection() {
        val key = random(32); val nonce = random(24)
        val plain = "integrity".toByteArray()
        val aad = "f:content:v1".toByteArray()
        val (ct, mac) = encrypt(plain, aad, nonce, key)

        ct[0] = (ct[0].toInt() xor 0x01).toByte() // flip a ciphertext bit
        val (rc, _) = decrypt(ct, mac, aad, nonce, key)
        assertFalse("tampered ciphertext must NOT verify", rc == 0)
    }

    @Test
    fun xchacha20_wrong_aad_rejected() {
        val key = random(32); val nonce = random(24)
        val plain = "ctx-bound".toByteArray()
        val (ct, mac) = encrypt(plain, "file1:content:v1".toByteArray(), nonce, key)

        val (rc, _) = decrypt(ct, mac, "file2:content:v1".toByteArray(), nonce, key)
        assertFalse("wrong AAD must NOT verify", rc == 0)
    }

    @Test
    fun xchacha20_deterministic_for_fixed_inputs() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { (it + 1).toByte() }
        val plain = "deterministic".toByteArray()
        val aad = "a:b:v1".toByteArray()

        val (ct1, mac1) = encrypt(plain, aad, nonce, key)
        val (ct2, mac2) = encrypt(plain, aad, nonce, key)
        assertArrayEquals(ct1, ct2)
        assertArrayEquals(mac1, mac2)
        assertTrue(mac1.size == ABYTES)
    }
}
