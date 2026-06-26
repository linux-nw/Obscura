package com.filevault.app

import android.util.Base64
import com.facebook.react.bridge.BridgeReactContext
import com.facebook.react.bridge.JavaOnlyMap
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.soloader.SoLoader
import com.filevault.app.modules.RNFileVaultModule
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Point 3 (Round 6.1) — End-to-end bridge roundtrip through the REAL React module.
 *
 * The KAT tests (XChaCha20BridgeTest, Argon2idKatTest) pin the libsodium *primitives*.
 * They call crypto_aead_* directly and therefore do NOT exercise the JNI marshalling
 * layer in RNFileVaultModule: Base64 decode/encode of the payload, hex parse of
 * key/nonce/tag, the detached-tag split, and the AAD-from-hex path. A byte-off in any of
 * those (wrong Base64 flag, nonce/tag order, hex padding) would pass the KATs but corrupt
 * real data.
 *
 * This test drives RNFileVaultModule.encrypt -> decrypt exactly as the bridge does
 * (ReadableMap in, Promise out) and byte-compares the result, across empty / 1-byte /
 * >1 MiB payloads, plus a Poly1305 tamper case. The module resolves the Promise
 * synchronously inside the @ReactMethod body, so no async wait is needed.
 *
 * Run: ./gradlew :app:connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class RNFileVaultBridgeRoundtripTest {

    private lateinit var module: RNFileVaultModule

    // 32-byte key / 24-byte nonce, fixed so a failure is reproducible.
    private val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    private val nonceHex = "404142434445464748494a4b4c4d4e4f5051525354555657"

    @Before
    fun setUp() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        // Arguments.createMap() inside the module builds a WritableNativeMap, which needs
        // the RN native libs registered with SoLoader. Safe to call repeatedly.
        SoLoader.init(ctx, false)
        // ReactApplicationContext is abstract under the New Architecture; BridgeReactContext
        // is its concrete subclass. encrypt()/decrypt() never touch the stored context (they
        // only use libsodium), but the Kotlin constructor enforces a non-null context.
        module = RNFileVaultModule(BridgeReactContext(ctx))
    }

    /** Capturing Promise: the module resolves/rejects synchronously, so we just read it back. */
    private class CapturingPromise : Promise {
        var resolved: Any? = null
        var didResolve = false
        var didReject = false
        var rejectCode: String? = null
        var rejectMessage: String? = null

        override fun resolve(value: Any?) { resolved = value; didResolve = true }
        override fun reject(code: String, message: String?) { fail(code, message) }
        override fun reject(code: String, throwable: Throwable?) { fail(code, throwable?.message) }
        override fun reject(code: String, message: String?, throwable: Throwable?) { fail(code, message) }
        override fun reject(throwable: Throwable) { fail("EXCEPTION", throwable.message) }
        override fun reject(throwable: Throwable, userInfo: WritableMap) { fail("EXCEPTION", throwable.message) }
        override fun reject(code: String, userInfo: WritableMap) { fail(code, null) }
        override fun reject(code: String, throwable: Throwable?, userInfo: WritableMap) { fail(code, throwable?.message) }
        override fun reject(code: String, message: String?, userInfo: WritableMap) { fail(code, message) }
        override fun reject(code: String?, message: String?, throwable: Throwable?, userInfo: WritableMap?) { fail(code ?: "NULL", message) }
        @Deprecated("legacy", ReplaceWith("reject(code, message)"))
        override fun reject(message: String) { fail("UNSPECIFIED", message) }

        private fun fail(code: String, message: String?) { didReject = true; rejectCode = code; rejectMessage = message }
    }

    private fun bytesToHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** encrypt(plain) -> Pair(encryptedHex, tagHex), going through the real module. */
    private fun encrypt(plain: ByteArray, aadHex: String? = null): Pair<String, String> {
        val params = JavaOnlyMap()
        params.putString("data", Base64.encodeToString(plain, Base64.NO_WRAP))
        params.putString("key", keyHex)
        params.putString("nonce", nonceHex)
        if (aadHex != null) params.putString("aad", aadHex)

        val p = CapturingPromise()
        module.encrypt(params, p)
        assertFalse("encrypt rejected: ${p.rejectCode}/${p.rejectMessage}", p.didReject)
        assertTrue("encrypt did not resolve", p.didResolve)
        val map = p.resolved as ReadableMap
        val enc = map.getString("encrypted"); val tag = map.getString("tag")
        assertNotNull("encrypted missing", enc); assertNotNull("tag missing", tag)
        return Pair(enc!!, tag!!)
    }

    /** decrypt -> plaintext bytes, going through the real module. */
    private fun decrypt(encHex: String, tagHex: String, aadHex: String? = null): ByteArray {
        val params = JavaOnlyMap()
        params.putString("encrypted", encHex)
        params.putString("nonce", nonceHex)
        params.putString("tag", tagHex)
        params.putString("key", keyHex)
        if (aadHex != null) params.putString("aad", aadHex)

        val p = CapturingPromise()
        module.decrypt(params, p)
        assertFalse("decrypt rejected: ${p.rejectCode}/${p.rejectMessage}", p.didReject)
        assertTrue("decrypt did not resolve", p.didResolve)
        return Base64.decode(p.resolved as String, Base64.DEFAULT)
    }

    private fun roundtrip(plain: ByteArray, aadHex: String? = null) {
        val (encHex, tagHex) = encrypt(plain, aadHex)
        // Detached tag must be exactly 16 bytes (32 hex chars); ciphertext same length as input.
        assertEquals("tag must be 16 bytes", 32, tagHex.length)
        assertEquals("ciphertext length must equal plaintext length", plain.size * 2, encHex.length)
        val out = decrypt(encHex, tagHex, aadHex)
        assertArrayEquals("roundtrip must return the original bytes", plain, out)
    }

    @Test
    fun bridge_roundtrip_empty() = roundtrip(ByteArray(0))

    @Test
    fun bridge_roundtrip_one_byte() = roundtrip(byteArrayOf(0x42))

    @Test
    fun bridge_roundtrip_large_over_1mib() {
        val data = ByteArray(1_500_000) { (it and 0xff).toByte() }
        roundtrip(data)
    }

    @Test
    fun bridge_roundtrip_with_aad() {
        roundtrip("Hello FileVault".toByteArray(Charsets.UTF_8), aadHex = bytesToHex("file1:content:v1".toByteArray()))
    }

    @Test
    fun bridge_tamper_one_byte_rejected() {
        val plain = "integrity matters".toByteArray(Charsets.UTF_8)
        val (encHex, tagHex) = encrypt(plain)

        // Flip the first ciphertext byte (first hex pair) and decrypt -> Poly1305 must reject.
        val firstByte = encHex.substring(0, 2).toInt(16)
        val flipped = "%02x".format(firstByte xor 0x01) + encHex.substring(2)

        val params = JavaOnlyMap()
        params.putString("encrypted", flipped)
        params.putString("nonce", nonceHex)
        params.putString("tag", tagHex)
        params.putString("key", keyHex)

        val p = CapturingPromise()
        module.decrypt(params, p)
        assertTrue("tampered ciphertext must be rejected", p.didReject)
        assertFalse("tampered ciphertext must NOT resolve", p.didResolve)
        assertEquals("DECRYPT_ERROR", p.rejectCode)
    }

    @Test
    fun bridge_wrong_aad_rejected() {
        val plain = "context bound".toByteArray(Charsets.UTF_8)
        val (encHex, tagHex) = encrypt(plain, aadHex = bytesToHex("file1:content:v1".toByteArray()))

        val params = JavaOnlyMap()
        params.putString("encrypted", encHex)
        params.putString("nonce", nonceHex)
        params.putString("tag", tagHex)
        params.putString("key", keyHex)
        params.putString("aad", bytesToHex("file2:content:v1".toByteArray()))

        val p = CapturingPromise()
        module.decrypt(params, p)
        assertTrue("wrong AAD must be rejected", p.didReject)
        assertFalse("wrong AAD must NOT resolve", p.didResolve)
    }
}
