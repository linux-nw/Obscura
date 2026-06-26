/**
 * F1_Argon2id.test.ts — guards against regression to PBKDF2 for KEK derivation.
 *
 * The original F1 bug: `__argon2_native_available` was never set, so deriveKEK
 * silently used PBKDF2. These tests assert that KEK derivation goes through
 * Argon2idService (the Argon2id path), NOT the old PBKDF2 fallback.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { Argon2idService } from '../src/services/Argon2idService';
import * as FastPBKDF2 from '../src/services/FastPBKDF2';

describe('F1: KEK derivation uses Argon2id, never PBKDF2', () => {
  test('setupMasterKey calls Argon2idService.deriveKey (Argon2id path)', async () => {
    const argonSpy = jest.spyOn(Argon2idService, 'deriveKey');

    await SecureCryptoService.setupMasterKey('FortressX99');

    // deriveKEK MUST route through Argon2id
    expect(argonSpy).toHaveBeenCalled();
    argonSpy.mockRestore();
  }, 60000);

  test('KEK derivation does NOT call fastPbkdf2 (no PBKDF2 fallback)', async () => {
    const pbkdf2Spy = jest.spyOn(FastPBKDF2, 'fastPbkdf2');

    await SecureCryptoService.setupMasterKey('FortressX99');

    // fastPbkdf2 may be called for the MAC-key in older code, but deriveMacKey
    // now uses HKDF. So the KEK path must not invoke PBKDF2 at all.
    // (deriveMacKey uses hkdfSha256, not fastPbkdf2.)
    expect(pbkdf2Spy).not.toHaveBeenCalled();
    pbkdf2Spy.mockRestore();
  }, 60000);

  test('KEK salt is 16 bytes (libsodium crypto_pwhash requirement)', async () => {
    await SecureCryptoService.setupMasterKey('FortressX99');
    const kekSaltHex = secureStore._store.get('filevault_kek_salt');
    expect(kekSaltHex).toBeDefined();
    // 16 bytes = 32 hex chars. A 32-byte salt (64 hex) would make native
    // Argon2id throw "salt must be exactly 16 bytes".
    expect(kekSaltHex.length).toBe(32);
  }, 60000);

  test('setup → clearCaches → unlock roundtrip works with Argon2id KEK', async () => {
    await SecureCryptoService.setupMasterKey('FortressX99');
    const masterKey = (SecureCryptoService as any)._masterKeyCache;
    SecureCryptoService.clearAllCaches();

    const ok = await SecureCryptoService.unlock('FortressX99');
    expect(ok).toBe(true);
    expect((SecureCryptoService as any)._masterKeyCache).toBe(masterKey);
  }, 60000);
});
