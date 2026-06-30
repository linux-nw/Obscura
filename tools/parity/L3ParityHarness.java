/*
 * L3 Phase 1a — host JCA parity harness.
 *
 * The host (desktop JDK / SunJCE) stand-in for the production native crypto in
 * NativeKeyCustody.kt. "AES/CBC/PKCS5Padding" and "HmacSHA256" are standard,
 * provider-independent transforms, so byte-identical output here is a faithful proxy
 * for Android's provider; the Phase 4 androidTest (L3CustodyParityTest.kt) confirms on
 * the actual device provider.
 *
 * Reads the flat vectors emitted by __tests__/L3_CustodyParity.test.ts (the REAL
 * production JS primitives) and re-derives each one through JCA, comparing byte for byte:
 *   1. AES-256-CBC/PKCS7 ciphertext (multiple lengths incl. exact block boundary)
 *   2. HKDF-SHA256(filevault-mac-v1) + HMAC-SHA256
 *   3. real pre-rebuild blobs (file-key wrap + master-blob) decrypt + re-encrypt identical
 *
 * Any single-byte divergence -> nonzero exit and a FAIL line. No production code is touched.
 *
 * Run:  javac L3ParityHarness.java && java L3ParityHarness <l3_vectors.txt>
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class L3ParityHarness {
    static int pass = 0, fail = 0;

    // ── JCA primitives (mirror NativeKeyCustody.kt) ──────────────────────────────
    static byte[] aesCbcEncrypt(byte[] key, byte[] iv, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(plain);
    }
    static byte[] aesCbcDecrypt(byte[] key, byte[] iv, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(ct);
    }
    static byte[] hmacSha256(byte[] key, byte[] msg) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }
    // RFC 5869, salt = 32 zero bytes, single Expand round (length <= 32) — matches FastPBKDF2.ts.
    static byte[] hkdfSha256(byte[] ikm, byte[] info, int length) throws Exception {
        byte[] salt = new byte[32];
        byte[] prk  = hmacSha256(salt, ikm);
        byte[] t1in = new byte[info.length + 1];
        System.arraycopy(info, 0, t1in, 0, info.length);
        t1in[info.length] = 0x01;
        byte[] t1 = hmacSha256(prk, t1in);
        return Arrays.copyOf(t1, length);
    }
    static byte[] deriveMacKey(byte[] masterKey) throws Exception {
        return hkdfSha256(masterKey, "filevault-mac-v1".getBytes(StandardCharsets.UTF_8), 32);
    }

    // ── helpers ──────────────────────────────────────────────────────────────────
    static byte[] hex(String s) {
        int n = s.length(); byte[] b = new byte[n / 2];
        for (int i = 0; i < n; i += 2) b[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return b;
    }
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }
    static byte[] b64(String s) { return Base64.getDecoder().decode(s); }
    static void check(String label, String expected, String got) {
        boolean ok = expected.equals(got);
        if (ok) { pass++; System.out.println("  PASS  " + label); }
        else { fail++; System.out.println("  FAIL  " + label + "\n        expected=" + expected + "\n        got     =" + got); }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) { System.err.println("usage: java L3ParityHarness <vectors.txt>"); System.exit(2); }
        System.out.println("AES max key bits = " + Cipher.getMaxAllowedKeyLength("AES") + " (need >=256)");
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            String[] p = line.split("\\|");
            switch (p[0]) {
                case "AES": {
                    // AES|name|keyHex|ivHex|plainB64|ctHex|macHex|macKeyHex
                    String name = p[1]; byte[] key = hex(p[2]); byte[] iv = hex(p[3]);
                    byte[] plain = b64(p[4]); String ctHexExp = p[5], macHexExp = p[6], macKeyExp = p[7];
                    String ct = hex(aesCbcEncrypt(key, iv, plain));
                    check("AES.ct      " + name, ctHexExp, ct);
                    String mk = hex(deriveMacKey(key));
                    check("AES.macKey  " + name, macKeyExp, mk);
                    String mac = hex(hmacSha256(hex(mk), (p[3] + ct).getBytes(StandardCharsets.UTF_8)));
                    check("AES.mac     " + name, macHexExp, mac);
                    String dec = new String(aesCbcDecrypt(key, iv, hex(ctHexExp)), StandardCharsets.UTF_8);
                    check("AES.dec     " + name, new String(plain, StandardCharsets.UTF_8), dec);
                    break;
                }
                case "HKDF": {
                    // HKDF|ikmHex|info|len|outHex
                    String out = hex(hkdfSha256(hex(p[1]), p[2].getBytes(StandardCharsets.UTF_8), Integer.parseInt(p[3])));
                    check("HKDF        " + p[1].substring(0, 8) + ".." , p[4], out);
                    break;
                }
                case "HMAC": {
                    // HMAC|name|keyHex|msgB64|outHex
                    String out = hex(hmacSha256(hex(p[2]), b64(p[3])));
                    check("HMAC        " + p[1], p[4], out);
                    break;
                }
                case "BLOB": {
                    // BLOB|name|keyHex|ivHex|plainB64|ctHex|macHex  (real pre-rebuild vault blob)
                    String name = p[1]; byte[] key = hex(p[2]); byte[] iv = hex(p[3]);
                    byte[] plain = b64(p[4]); String ctHexExp = p[5], macHexExp = p[6];
                    // MAC verify (Encrypt-then-MAC, key = HKDF(masterKey))
                    String mac = hex(hmacSha256(deriveMacKey(key), (p[3] + ctHexExp).getBytes(StandardCharsets.UTF_8)));
                    check("BLOB.macOK  " + name, macHexExp, mac);
                    // native-path decrypt byte-identical to the stored plaintext
                    String dec = new String(aesCbcDecrypt(key, iv, hex(ctHexExp)), StandardCharsets.UTF_8);
                    check("BLOB.dec    " + name, new String(plain, StandardCharsets.UTF_8), dec);
                    // re-encrypt under same key/iv reproduces the exact stored ciphertext
                    String ct = hex(aesCbcEncrypt(key, iv, plain));
                    check("BLOB.reEnc  " + name, ctHexExp, ct);
                    break;
                }
                default: System.err.println("unknown row: " + p[0]);
            }
        }
        System.out.println("\n==== L3 PARITY: " + pass + " pass, " + fail + " fail ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
