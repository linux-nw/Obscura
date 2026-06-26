/**
 * Argon2idReal.test.ts — REAL Argon2id, not the PBKDF2 mock.
 *
 * The default Jest setup maps `@noble/hashes/argon2.js` to a PBKDF2 stub
 * (deterministic, fast). This file overrides that with the actual @noble/hashes
 * Argon2id so the Argon2idService key-derivation path is exercised for real and
 * pinned to a known-answer test (KAT).
 *
 * Coverage scope:
 *   - JS fallback path (@noble/hashes pure-JS Argon2id) — verified here against a KAT.
 *   - Native path (libsodium `crypto_pwhash` via JNI in RNFileVaultModule.kt) is
 *     selected only when `global.__argon2_native_available` is set on a device; it
 *     cannot run under Jest (no JNI) and is verifiable on-device only.
 */

// Replace the global @noble/hashes/argon2 stub with the REAL package for THIS file
// only, so the JS fallback path runs genuine Argon2id and is pinned to the KAT.
// The relative path bypasses the moduleNameMapper stub (which matches the bare
// specifier "@noble/hashes/argon2.js" only).
jest.mock('@noble/hashes/argon2.js', () => require('../node_modules/@noble/hashes/argon2.js'));

import { Argon2idService, Argon2Params } from '../src/services/Argon2idService';

const PARAMS: Argon2Params = {
  version: 0x13,
  type: 2, // Argon2id
  memoryKB: 64,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
};

// Build a clean 16-byte ArrayBuffer (avoid Buffer's pooled .buffer).
function salt16(hex: string): ArrayBuffer {
  const bytes = Buffer.from(hex, 'hex');
  const ab = new ArrayBuffer(bytes.length);
  new Uint8Array(ab).set(bytes);
  return ab;
}

const toHex = (ab: ArrayBuffer) => Buffer.from(new Uint8Array(ab)).toString('hex');

test('Argon2idService.deriveKey matches a real Argon2id KAT (hash-wasm WASM, RAW salt)', async () => {
  const out = await Argon2idService.deriveKey(
    'correct horse battery staple',
    salt16('0102030405060708090a0b0c0d0e0f10'),
    PARAMS
  );
  // C1: pinned against real hash-wasm Argon2id with the salt as RAW 16 bytes, p=1
  // (Argon2id v1.3, m=64KiB, t=2). This equals what libsodium crypto_pwhash produces
  // for the same raw salt — see Argon2idC1.test.ts for the equivalence guard.
  expect(toHex(out)).toBe('c97f06cb90ae1188ee3be8416d6bdd7668c7440a720998f470ef2afee37b8f38');
}, 30000);

test('C1 guard: deriveKey uses RAW salt bytes, NOT the Base64 string', async () => {
  const real = require('../node_modules/hash-wasm');
  const saltAb = salt16('0102030405060708090a0b0c0d0e0f10');
  const rawBytes = new Uint8Array(saltAb);
  const b64 = Buffer.from(rawBytes).toString('base64');

  const service = toHex(await Argon2idService.deriveKey('pw', saltAb, PARAMS));

  // What the NATIVE bridge effectively does: send Base64, Kotlin Base64-decodes back
  // to the same raw bytes, crypto_pwhash hashes RAW bytes. Replicate that with real
  // hash-wasm + raw bytes → MUST equal the service output.
  const nativeEquivalent = await real.argon2id({
    password: 'pw', salt: Buffer.from(b64, 'base64'),
    iterations: 2, memorySize: 64, parallelism: 1, hashLength: 32, outputType: 'hex',
  });
  expect(service).toBe(nativeEquivalent);

  // The OLD buggy behaviour hashed the Base64 STRING. The service must NOT match it.
  const oldStringSaltBug = await real.argon2id({
    password: 'pw', salt: b64,
    iterations: 2, memorySize: 64, parallelism: 1, hashLength: 32, outputType: 'hex',
  });
  expect(service).not.toBe(oldStringSaltBug);
}, 30000);

test('deterministic: same password + salt + params → same key', async () => {
  const a = await Argon2idService.deriveKey('pw', salt16('00112233445566778899aabbccddeeff'), PARAMS);
  const b = await Argon2idService.deriveKey('pw', salt16('00112233445566778899aabbccddeeff'), PARAMS);
  expect(toHex(a)).toBe(toHex(b));
  expect(toHex(a)).toHaveLength(64); // 32 bytes
}, 30000);

test('salt-sensitive: different salt → different key', async () => {
  const a = await Argon2idService.deriveKey('pw', salt16('00000000000000000000000000000000'), PARAMS);
  const b = await Argon2idService.deriveKey('pw', salt16('00000000000000000000000000000001'), PARAMS);
  expect(toHex(a)).not.toBe(toHex(b));
}, 30000);

test('not PBKDF2: real Argon2id differs from the PBKDF2 stub output', async () => {
  // The PBKDF2 stub returns pbkdf2(password, base64(salt), 1 iter). Argon2id must differ.
  const real = await Argon2idService.deriveKey('pw', salt16('0102030405060708090a0b0c0d0e0f10'), PARAMS);
  const saltB64 = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex').toString('base64');
  const pbkdf2 = require('crypto').pbkdf2Sync('pw', Buffer.from(saltB64), 1, 32, 'sha256').toString('hex');
  expect(toHex(real)).not.toBe(pbkdf2);
}, 30000);
