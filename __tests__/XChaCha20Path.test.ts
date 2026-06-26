/**
 * XChaCha20Path.test.ts
 *
 * Gives the PRIMARY production cipher path (backend 0x01, XChaCha20-Poly1305 via
 * the native module) the test coverage it previously lacked. On a real device the
 * native module IS present, so this — not the AES fallback — is the path that runs.
 *
 * A faithful native mock implements the encrypt/decrypt contract from
 * src/native/RNFileVault.ts (data is Base64 of the plaintext bytes; encrypt
 * returns hex ciphertext + hex tag; decrypt verifies the tag and throws on
 * mismatch, simulating Poly1305).
 *
 * Verifies:
 *   1. encryptData → decryptData round-trip on the 0x01 path (prefix '01').
 *   2. UTF-8 correctness: non-Latin1 content (emoji, CJK) survives the round-trip.
 *      The old code used btoa(data) and threw on any code point > 0xFF.
 *   3. Tamper detection: a flipped ciphertext byte fails the AEAD tag check.
 */

const CryptoJS = require('crypto-js');

// The RNFileVault bridge captures NativeModules.RNFileVault at import time, so the
// mock MUST be installed before CryptoService (and thus RNFileVault) is required.
const rn = require('react-native');
rn.NativeModules.RNFileVault = {
  encrypt: async ({ data, key, nonce, aad }: { data: string; key: string; nonce: string; aad?: string }) => {
    const ptWords = CryptoJS.enc.Base64.parse(data);
    const keyWords = CryptoJS.enc.Hex.parse(key);
    // Derive a 16-byte CBC IV from the 24-byte nonce (test substitute for the stream cipher).
    const ivWords = CryptoJS.enc.Hex.parse(nonce.substring(0, 32));
    const ct = CryptoJS.AES.encrypt(ptWords, keyWords, {
      iv: ivWords,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const encrypted = ct.ciphertext.toString(CryptoJS.enc.Hex);
    // Bind AAD (the backend prefix) into the tag, mirroring Poly1305 AAD (W-03).
    const tag = CryptoJS.HmacSHA256((aad ?? '') + nonce + encrypted, keyWords).toString(CryptoJS.enc.Hex).substring(0, 32);
    return { encrypted, tag };
  },
  decrypt: async ({ encrypted, nonce, tag, key, aad }: { encrypted: string; nonce: string; tag: string; key: string; aad?: string }) => {
    const keyWords = CryptoJS.enc.Hex.parse(key);
    const expectedTag = CryptoJS.HmacSHA256((aad ?? '') + nonce + encrypted, keyWords).toString(CryptoJS.enc.Hex).substring(0, 32);
    if (expectedTag !== tag) {
      throw new Error('AEAD tag mismatch');
    }
    const ivWords = CryptoJS.enc.Hex.parse(nonce.substring(0, 32));
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(encrypted),
    });
    const pt = CryptoJS.AES.decrypt(cipherParams, keyWords, {
      iv: ivWords,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return pt.toString(CryptoJS.enc.Base64);
  },
  verifyConstantTime: async ({ a, b }: { a: string; b: string }) => ({ result: a === b }),
};

const { SecureCryptoService } = require('../src/services/CryptoService');

const MASTER_KEY = 'a'.repeat(64); // 32-byte hex key

beforeEach(() => {
  (SecureCryptoService as any)._masterKeyCache = MASTER_KEY;
});

test('XChaCha20 path: encryptData uses backend 0x01 and round-trips', async () => {
  const plaintext = 'Hello, secure world.';
  const enc = await SecureCryptoService.encryptData(plaintext);

  expect(enc.encryptedData.substring(0, 2)).toBe('01'); // BACKEND_XCHACHA prefix
  expect(enc.iv.length).toBe(48); // 24-byte nonce → 48 hex chars

  const dec = await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac);
  expect(dec).toBe(plaintext);
});

test('XChaCha20 path: non-Latin1 content (emoji/CJK) survives round-trip', async () => {
  // Old btoa(data) threw "InvalidCharacterError" on any code point > 0xFF.
  const plaintext = 'Grüße 🔐 機密 — Ω≈ç√∫˜µ';
  const enc = await SecureCryptoService.encryptData(plaintext);
  const dec = await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac);
  expect(dec).toBe(plaintext);
});

test('XChaCha20 path: tampered ciphertext fails AEAD verification', async () => {
  const enc = await SecureCryptoService.encryptData('integrity-protected');

  // Flip one hex nibble in the ciphertext body (after the 2-char backend prefix).
  const body = enc.encryptedData.substring(2);
  const flipped = (parseInt(body[0], 16) ^ 0x1).toString(16) + body.substring(1);
  const tampered = '01' + flipped;

  await expect(
    SecureCryptoService.decryptData(tampered, enc.iv, enc.mac)
  ).rejects.toThrow();
});

test('XChaCha20 path: tampered backend prefix (W-03) is rejected', async () => {
  const enc = await SecureCryptoService.encryptData('prefix-bound');
  expect(enc.encryptedData.substring(0, 2)).toBe('01');
  // Flip the authenticated backend prefix 0x01 → 0x02.
  const tampered = '02' + enc.encryptedData.substring(2);
  await expect(
    SecureCryptoService.decryptData(tampered, enc.iv, enc.mac)
  ).rejects.toThrow();
});

test('XChaCha20 path: H2 aadContext binding (wrong context rejected)', async () => {
  const enc = await SecureCryptoService.encryptData('ctx-bound', 'noteX:content');
  expect(await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'noteX:content')).toBe('ctx-bound');
  await expect(SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'noteY:content')).rejects.toThrow();
});
