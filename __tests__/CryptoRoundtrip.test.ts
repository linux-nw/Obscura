/**
 * CryptoRoundtrip.test.ts
 *
 * Verified:
 *   1. AES-CBC+HMAC (0x02): encryptData → decryptData → original plaintext
 *   2. CryptoJS (0x03): manually prefixed ciphertext routes correctly through
 *      decryptData — exercises the prefix-strip code path directly
 *   3. Bit-flip in ciphertext body → decryptData throws (HMAC mismatch)
 *   4. Bit-flip in MAC tag → decryptData throws (tag mismatch)
 *
 * XChaCha20 (0x01) is intentionally absent: it requires NativeModules.RNFileVault
 * which is undefined in the Jest environment (react-native mock returns {}).
 *
 * Performance note: setupMasterKey runs PBKDF2-600k once in beforeAll (~14 s).
 * Individual tests restore _masterKeyCache directly to avoid repeating that cost.
 * The per-test overhead is only deriveMacKey (PBKDF2-10k, ~0.24 s, cached after
 * first call) plus the AES-CBC encrypt/decrypt itself (< 1 ms).
 */

const secureStore = require('../__mocks__/expo-secure-store');

import { SecureCryptoService } from '../src/services/CryptoService';

const PASSPHRASE = 'RoundtripTestPass42!';
const PLAINTEXT  = 'Hello, World! This is the encryption roundtrip test message.';

// Flip one nibble at position pos in a hex string, changing every bit in that nibble.
function flipNibbleAt(hex: string, pos: number): string {
  const chars = hex.split('');
  chars[pos] = ((parseInt(chars[pos], 16) ^ 0xf) & 0xf).toString(16);
  return chars.join('');
}

// Run setupMasterKey once per suite; restore cache in beforeEach to avoid re-running PBKDF2-600k.
let sharedMasterKey: string;

beforeAll(async () => {
  await SecureCryptoService.setupMasterKey(PASSPHRASE);
  // L3 Phase 2: getMasterKey() is gone (throws). Resolve the master via the test-only seam.
  sharedMasterKey = SecureCryptoService.__masterKeyHexForTest()!;
}, 30000);

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  // Clear caches, then restore master key without re-deriving KEK.
  SecureCryptoService.clearAllCaches();
  (SecureCryptoService as any)._masterKeyCache = sharedMasterKey;
});

// ─────────────────────────────── AES-CBC+HMAC backend (0x02) ───────────────────────────────

describe('AES-CBC+HMAC backend (0x02)', () => {
  test('encryptData → decryptData → original plaintext', async () => {
    const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(PLAINTEXT);

    // Assert backend prefix is 0x02 (AES-CBC+HMAC, the first fallback in the test env).
    expect(encryptedData.substring(0, 2)).toBe('02');

    const decrypted = await SecureCryptoService.decryptData(encryptedData, iv, mac);
    expect(decrypted).toBe(PLAINTEXT);
  });

  test('bit-flip in ciphertext body → decryptData throws (HMAC mismatch)', async () => {
    const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(PLAINTEXT);

    // Flip a nibble inside the raw ciphertext (skip the 2-char prefix).
    // The HMAC was computed over the original ciphertext; any mutation fails MAC verify.
    const rawCipher   = encryptedData.substring(2);
    const flippedBody = flipNibbleAt(rawCipher, 4);
    const corrupted   = '02' + flippedBody;

    await expect(SecureCryptoService.decryptData(corrupted, iv, mac)).rejects.toThrow();
  });

  test('bit-flip in MAC tag → decryptData throws (tag mismatch)', async () => {
    const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(PLAINTEXT);
    const corruptedMac = flipNibbleAt(mac, 0);

    await expect(SecureCryptoService.decryptData(encryptedData, iv, corruptedMac)).rejects.toThrow();
  });
});

// ─────────────────────────────── CryptoJS backend (0x03) ───────────────────────────────

describe('CryptoJS backend (0x03) — prefix-strip path', () => {
  test('0x03-prefixed ciphertext routes to CryptoJS decrypt, roundtrip succeeds', async () => {
    const ivBuf = await SecureCryptoService.generateSecureBytes(16);
    const ivHex = SecureCryptoService.bufferToHex(ivBuf);

    // Build a CryptoJS ciphertext+MAC using the private encrypt helper. The MAC binds
    // the backend prefix '03' as AAD (W-03), matching what legacyCryptoJsCbcHmacDecrypt expects.
    const { encryptedData, tag } = await (SecureCryptoService as any)
      .legacyCryptoJsCbcHmacEncrypt(PLAINTEXT, sharedMasterKey, ivHex, '03');

    // Prefix with 0x03 so decryptData routes to CryptoJS — and strips the prefix
    // before calling legacyCryptoJsCbcHmacDecrypt. This is the exact code path that was broken
    // before the prefix-strip fix (encryptedData.substring(2)).
    const prefixed = '03' + encryptedData;

    const decrypted = await SecureCryptoService.decryptData(prefixed, ivHex, tag);
    expect(decrypted).toBe(PLAINTEXT);
  });

  test('0x03-prefixed ciphertext with flipped body → decryptData throws', async () => {
    const ivBuf = await SecureCryptoService.generateSecureBytes(16);
    const ivHex = SecureCryptoService.bufferToHex(ivBuf);

    const { encryptedData, tag } = await (SecureCryptoService as any)
      .legacyCryptoJsCbcHmacEncrypt(PLAINTEXT, sharedMasterKey, ivHex, '03');

    const corrupted = '03' + flipNibbleAt(encryptedData, 0);

    await expect(SecureCryptoService.decryptData(corrupted, ivHex, tag)).rejects.toThrow();
  });
});

// ─────────────────────────────── W-03: backend prefix authentication ───────────────────────────────

describe('W-03: backend prefix is authenticated', () => {
  test('flipping the 0x02 prefix to 0x03 is rejected (prefix bound into MAC)', async () => {
    const { encryptedData, iv, mac } = await SecureCryptoService.encryptData(PLAINTEXT);
    expect(encryptedData.substring(0, 2)).toBe('02');

    // Same AES-CBC+HMAC ciphertext, but relabelled as backend 0x03. Before W-03 the
    // MAC did not cover the prefix, so this decoded fine; now the MAC over '03'+iv+ct
    // differs from the stored MAC over '02'+iv+ct → rejected.
    const relabelled = '03' + encryptedData.substring(2);
    await expect(SecureCryptoService.decryptData(relabelled, iv, mac)).rejects.toThrow();
  });
});

// ─────────────────────────────── H2: AAD context binding ───────────────────────────────

describe('H2: blob is bound to its aadContext', () => {
  test('correct context decrypts, wrong context (blob-swap) is rejected', async () => {
    const enc = await SecureCryptoService.encryptData(PLAINTEXT, 'fileA:content');

    // Right context → plaintext back.
    expect(await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:content')).toBe(PLAINTEXT);

    // Different fileId (swap) or different role → MAC fail → reject.
    await expect(SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileB:content')).rejects.toThrow();
    await expect(SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:name')).rejects.toThrow();
    // Empty context (pre-H2 caller) also rejected.
    await expect(SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac)).rejects.toThrow();
  });
});
