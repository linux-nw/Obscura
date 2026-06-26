package com.filevault.app

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.sun.jna.NativeLong
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * C1 — On-device Known-Answer Test for the NATIVE Argon2id (libsodium crypto_pwhash).
 *
 * Pins the JNI path to the SAME vector the JS test asserts
 * (__tests__/Argon2idReal.test.ts). If both pass, native libsodium and the hash-wasm
 * fallback derive byte-identical keys for the same password + RAW 16-byte salt — which
 * is exactly what C1 requires (no KEK divergence across paths).
 *
 * Vector: Argon2id v1.3, password "correct horse battery staple",
 *         salt = bytes 01..10 (16 bytes), opslimit(t)=2, memlimit=64 KiB, p=1, out=32.
 *
 * Requires in android/app/build.gradle:
 *   androidTestImplementation "androidx.test.ext:junit:1.1.5"
 *   androidTestImplementation "androidx.test:runner:1.5.2"
 * and defaultConfig.testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner".
 */
@RunWith(AndroidJUnit4::class)
class Argon2idKatTest {

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Test
    fun nativeArgon2idMatchesKnownAnswer() {
        val ls = LazySodiumAndroid(SodiumAndroid())

        val password = "correct horse battery staple".toByteArray(Charsets.UTF_8)
        val salt = hexToBytes("0102030405060708090a0b0c0d0e0f10") // 16 raw bytes
        val out = ByteArray(32)

        val rc = ls.sodium.crypto_pwhash(
            out, out.size.toLong(),
            password, password.size.toLong(),
            salt,
            2L,                              // opslimit (iterations)
            NativeLong(65536L),              // memlimit in BYTES (64 KiB)
            2                                // crypto_pwhash_ALG_ARGON2ID13
        )

        assertEquals("crypto_pwhash returned non-zero", 0, rc)
        assertEquals(
            "c97f06cb90ae1188ee3be8416d6bdd7668c7440a720998f470ef2afee37b8f38",
            bytesToHex(out)
        )
    }
}
