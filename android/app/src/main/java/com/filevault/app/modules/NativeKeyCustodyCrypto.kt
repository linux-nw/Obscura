package com.filevault.app.modules

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * NativeKeyCustodyCrypto — byte-identical native re-home of the JS key-wrapping primitives.
 *
 * Phase 1a of L3 Native Key Custody. This is the PRIMITIVE LAYER only: AES-256-CBC/PKCS7,
 * HMAC-SHA256, HKDF-SHA256 and the Encrypt-then-MAC wrap/unwrap that today live in JS
 * (AesCbcHmac.ts + CryptoService.computeMac/deriveMacKey + FastPBKDF2.hkdfSha256). It exists
 * so a later phase can move file-key wrapping and the master-blob unwrap off the JS heap
 * WITHOUT changing a single ciphertext byte.
 *
 * NOT WIRED. No @ReactMethod, no bridge registration, no production caller. It is reachable
 * only from the parity androidTest until Phase 1b introduces the libsodium secure-memory
 * custody (sodium_malloc / sodium_mlock / opaque handle) that will call into it.
 *
 * Byte-for-byte parity with the JS production path is proven host-side in Phase 1a
 * (tools/parity/L3ParityHarness.java vs __tests__/L3_CustodyParity.test.ts, 45/45) and
 * on-device by L3CustodyParityTest. "AES/CBC/PKCS5Padding" == CryptoJS PKCS7 for 16-byte
 * blocks; "HmacSHA256" and the RFC-5869 HKDF below reproduce computeMac/deriveMacKey exactly.
 *
 * Invariant: same key, same AEAD/wrap construction, same wire format. Only where the key
 * lives changes — and in THIS file nothing changes yet; it is the parity-proven building block.
 */
object NativeKeyCustodyCrypto {

    private const val HKDF_LABEL = "filevault-mac-v1"

    // ── AES-256-CBC / PKCS7 ──────────────────────────────────────────────────────
    fun aesCbcEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding") // PKCS5 == PKCS7 for 16-byte blocks
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(plaintext)
    }

    fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(ciphertext)
    }

    // ── HMAC-SHA256 ──────────────────────────────────────────────────────────────
    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(key, "HmacSHA256"))
        return m.doFinal(message)
    }

    // ── HKDF-SHA256 (RFC 5869), salt = 32 zero bytes, single Expand round (len <= 32) ──
    // Mirrors FastPBKDF2.ts hkdfSha256: PRK = HMAC(0x00*32, IKM); T1 = HMAC(PRK, info || 0x01).
    fun hkdfSha256(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val salt = ByteArray(32)
        val prk = hmacSha256(salt, ikm)
        val t1in = info + byteArrayOf(0x01)
        return hmacSha256(prk, t1in).copyOf(length)
    }

    /** MAC subkey from the master key, exactly as CryptoService.deriveMacKey. */
    fun deriveMacKey(masterKey: ByteArray): ByteArray =
        hkdfSha256(masterKey, HKDF_LABEL.toByteArray(StandardCharsets.UTF_8), 32)

    // ── Encrypt-then-MAC wrap / unwrap (file-key wrap + master-blob) ──────────────
    // Matches aesCbcHmacWrapEncrypt/Decrypt: ct = AES-CBC(key, iv, plaintext);
    // mac = HMAC(deriveMacKey(key), utf8(ivHex + ctHex)). The MAC is over the ASCII hex strings.
    data class Wrapped(val ctHex: String, val macHex: String)

    fun wrapEtm(key: ByteArray, iv: ByteArray, plaintext: ByteArray): Wrapped {
        val ct = aesCbcEncrypt(key, iv, plaintext)
        val ctHex = toHex(ct)
        val ivHex = toHex(iv)
        val mac = hmacSha256(deriveMacKey(key), (ivHex + ctHex).toByteArray(StandardCharsets.UTF_8))
        return Wrapped(ctHex, toHex(mac))
    }

    /**
     * Verifies the Encrypt-then-MAC tag in constant time, then AES-CBC-decrypts.
     * Throws on tag mismatch (no decrypt on failure). Used for both file-key unwrap and the
     * master-blob KEK-unwrap (caller passes the KEK as `key`).
     */
    fun unwrapEtm(key: ByteArray, ivHex: String, ctHex: String, macHex: String): ByteArray {
        val expected = hmacSha256(deriveMacKey(key), (ivHex + ctHex).toByteArray(StandardCharsets.UTF_8))
        if (!MessageDigest.isEqual(expected, fromHex(macHex))) {
            throw SecurityException("EtM tag mismatch")
        }
        return aesCbcDecrypt(key, fromHex(ivHex), fromHex(ctHex))
    }

    // ── hex (lowercase, matching JS bufferToHex / CryptoJS) ───────────────────────
    fun toHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            sb.append(Character.forDigit((x.toInt() shr 4) and 0xf, 16))
            sb.append(Character.forDigit(x.toInt() and 0xf, 16))
        }
        return sb.toString()
    }

    fun fromHex(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex length must be even" }
        return ByteArray(s.length / 2) { i ->
            s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
