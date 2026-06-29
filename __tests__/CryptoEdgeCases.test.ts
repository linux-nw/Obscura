/**
 * CryptoEdgeCases.test.ts
 *
 * Edge-cases that the main roundtrip tests don't cover:
 *   1. Empty string encrypt/decrypt roundtrip
 *   2. Unicode (emoji, CJK, RTL) encrypt/decrypt roundtrip
 *   3. Unknown backend header byte → decryptData throws immediately
 *   4. Tampered MAC tag → decryptData throws (AES-CBC+HMAC path)
 *   5. HKDF deriveMacKey: deterministic, different key → different mac key
 *   6. HKDF deriveMacKey: NOT PBKDF2 (verifies HKDF replaced the old primitive)
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { hkdfSha256 } from '../src/services/FastPBKDF2';

const PASSPHRASE = 'EdgeCaseTest42!';
let sharedKey: string;

beforeAll(async () => {
  await SecureCryptoService.setupMasterKey(PASSPHRASE);
  // L3 Phase 2: getMasterKey() is gone (throws). Resolve the master via the test-only seam.
  sharedKey = SecureCryptoService.__masterKeyHexForTest()!;
}, 60000);

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
  (SecureCryptoService as any)._masterKeyCache = sharedKey;
});

// ─── 1. Empty string roundtrip ───────────────────────────────────────────────

test('empty string: encryptData → decryptData → ""', async () => {
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData('');
  const result = await SecureCryptoService.decryptData(encryptedData, iv, mac);
  expect(result).toBe('');
});

// ─── 2. Unicode roundtrip ────────────────────────────────────────────────────

test('emoji: 🔐🗝️🔒 survives roundtrip', async () => {
  const input = '🔐🗝️🔒';
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(input);
  const result = await SecureCryptoService.decryptData(encryptedData, iv, mac);
  expect(result).toBe(input);
});

test('CJK characters survive roundtrip', async () => {
  const input = '密码保险库 — 安全存储';
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(input);
  const result = await SecureCryptoService.decryptData(encryptedData, iv, mac);
  expect(result).toBe(input);
});

test('RTL + mixed unicode survive roundtrip', async () => {
  const input = 'مرحبا Hello שלום ñ ü ô';
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(input);
  const result = await SecureCryptoService.decryptData(encryptedData, iv, mac);
  expect(result).toBe(input);
});

// ─── 3. Unknown backend header → immediate throw ─────────────────────────────

test('unknown backend 0xFF in header → decryptData throws, does not produce garbage', async () => {
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData('test');
  // Replace first byte with 0xFF (unknown backend)
  const corrupted = 'ff' + encryptedData.substring(2);
  await expect(SecureCryptoService.decryptData(corrupted, iv, mac)).rejects.toThrow();
});

test('header 0x00 → decryptData throws (not a valid backend)', async () => {
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData('test');
  const corrupted = '00' + encryptedData.substring(2);
  await expect(SecureCryptoService.decryptData(corrupted, iv, mac)).rejects.toThrow();
});

// ─── 4. Tampered MAC → throw, not garbage output ─────────────────────────────

test('single byte flip in MAC → decryptData throws', async () => {
  const { encryptedData, iv, mac } = await SecureCryptoService.encryptData('sensitive data');
  // Flip first nibble of mac
  const badMac = ((parseInt(mac[0], 16) ^ 0xf) & 0xf).toString(16) + mac.substring(1);
  await expect(SecureCryptoService.decryptData(encryptedData, iv, badMac)).rejects.toThrow();
});

// ─── 5. HKDF: deterministic + key-separated ──────────────────────────────────

test('hkdfSha256: same input → same output (deterministic)', () => {
  const key = 'a'.repeat(64);
  const k1 = hkdfSha256(key, 'filevault-mac-v1', 32);
  const k2 = hkdfSha256(key, 'filevault-mac-v1', 32);
  expect(k1).toBe(k2);
  expect(k1).toHaveLength(64); // 32 bytes = 64 hex chars
});

test('hkdfSha256: different IKMs → different outputs', () => {
  const k1 = hkdfSha256('a'.repeat(64), 'filevault-mac-v1', 32);
  const k2 = hkdfSha256('b'.repeat(64), 'filevault-mac-v1', 32);
  expect(k1).not.toBe(k2);
});

test('hkdfSha256: different info labels → different outputs (domain separation)', () => {
  const ikm = 'c'.repeat(64);
  const k1 = hkdfSha256(ikm, 'filevault-mac-v1', 32);
  const k2 = hkdfSha256(ikm, 'filevault-enc-v1', 32);
  expect(k1).not.toBe(k2);
});

// ─── 6. deriveMacKey uses HKDF, NOT PBKDF2 ────────────────────────────────────

test('deriveMacKey result matches hkdfSha256 output (not PBKDF2)', async () => {
  const key = 'd'.repeat(64);

  const macKey = await SecureCryptoService.deriveMacKey(key);
  const hkdfKey = hkdfSha256(key, 'filevault-mac-v1', 32);

  expect(macKey).toBe(hkdfKey);
  expect(macKey).not.toBe(
    // Old PBKDF2 value would be different — this shows we switched
    // (we don't recompute PBKDF2 here; we just assert HKDF matches)
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  );
});
