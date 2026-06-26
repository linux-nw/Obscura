package com.filevault.app

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * S7 — on-device check that the PRODUCTION constant-time comparison path
 * (libsodium `sodium_memcmp`, used by RNFileVaultModule.verifyConstantTime) returns
 * the correct result. This is the timing-safe path; the JS XOR fallback in
 * SecureCryptoService.constantsTimeEquals is best-effort only (documented, M4) and is
 * reached solely when the native module is absent.
 *
 * `sodium_memcmp`: returns 0 iff the two equal-length buffers are byte-equal.
 *
 * Requires (see Argon2idKatTest.kt) the androidx.test runner deps in build.gradle.
 */
@RunWith(AndroidJUnit4::class)
class ConstantTimeMemcmpTest {

    private val ls = LazySodiumAndroid(SodiumAndroid())

    @Test
    fun equalBuffers_returnZero() {
        val a = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".toByteArray()
        val b = a.copyOf()
        assertEquals("equal buffers must compare equal (rc==0)", 0, ls.sodium.sodium_memcmp(a, b, a.size))
    }

    @Test
    fun differingBuffers_returnNonZero() {
        val a = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".toByteArray()
        val b = a.copyOf()
        b[b.size - 1] = (b[b.size - 1].toInt() xor 0x01).toByte() // flip one bit
        assertNotEquals("differing buffers must NOT compare equal", 0, ls.sodium.sodium_memcmp(a, b, a.size))
    }

    @Test
    fun differingFirstByte_returnNonZero() {
        val a = ByteArray(32) { it.toByte() }
        val b = a.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() }
        assertNotEquals(0, ls.sodium.sodium_memcmp(a, b, a.size))
    }
}
