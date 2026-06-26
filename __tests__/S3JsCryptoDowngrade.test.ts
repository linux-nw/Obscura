/**
 * S3: no silent JS-crypto downgrade on the content WRITE path.
 *
 * In Jest there is no native module (react-native mock returns NativeModules = {}), so
 * getEncryptionBackend() selects the pure-JS AES-256-CBC+HMAC fallback (0x02). The S3
 * policy permits that ONLY under NODE_ENV==='test' or an explicit global opt-in. These
 * tests temporarily simulate a production environment (NODE_ENV='production', no opt-in)
 * to prove:
 *   A. a production write with the native module absent THROWS (no silent downgrade);
 *   B. existing 0x02 ciphertext stays READABLE in production (read path is never gated);
 *   C. an explicit, logged opt-in re-enables the write (developer escape hatch).
 */

const secureStore = require('../__mocks__/expo-secure-store');

import { SecureCryptoService } from '../src/services/CryptoService';

const PASSPHRASE = 'S3GuardPass_123!';
const PLAINTEXT  = 'sensitive content that must not be silently JS-encrypted';

let sharedMasterKey: string;

beforeAll(async () => {
  await SecureCryptoService.setupMasterKey(PASSPHRASE);
  sharedMasterKey = (await SecureCryptoService.getMasterKey())!;
}, 30000);

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
  (SecureCryptoService as any)._masterKeyCache = sharedMasterKey;
  delete (global as any).__filevault_allow_js_crypto;
});

afterEach(() => {
  process.env.NODE_ENV = 'test';
  delete (global as any).__filevault_allow_js_crypto;
});

// Must be async and await fn: encryptData yields at its first `await getMasterKey()`, so
// a synchronous finally would restore NODE_ENV before the S3 guard microtask runs. The
// guard reads NODE_ENV at execution time (correct), so the env must stay 'production' for
// the whole async body.
async function withProductionEnv<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    return await fn();
  } finally {
    process.env.NODE_ENV = prev;
  }
}

describe('S3: content write downgrade guard', () => {
  test('A. production + native absent + no opt-in → encryptData THROWS (no silent JS write)', async () => {
    await withProductionEnv(async () => {
      await expect(SecureCryptoService.encryptData(PLAINTEXT, 'fileA:content:v1')).rejects.toThrow();
    });
  });

  test('B. existing 0x02 ciphertext stays readable in production (read path not gated)', async () => {
    // Write under the test env (allowed) → produces a 0x02 blob.
    const enc = await SecureCryptoService.encryptData(PLAINTEXT, 'fileA:content:v1');
    expect(enc.encryptedData.substring(0, 2)).toBe('02');

    // Now simulate production: the read must still succeed.
    await withProductionEnv(async () => {
      const out = await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:content:v1');
      expect(out).toBe(PLAINTEXT);
    });
  });

  test('C. explicit opt-in re-enables the JS-fallback write in production', async () => {
    await withProductionEnv(async () => {
      (global as any).__filevault_allow_js_crypto = true;
      const enc = await SecureCryptoService.encryptData(PLAINTEXT, 'fileA:content:v1');
      expect(enc.encryptedData.substring(0, 2)).toBe('02');
      const out = await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:content:v1');
      expect(out).toBe(PLAINTEXT);
    });
  });
});
