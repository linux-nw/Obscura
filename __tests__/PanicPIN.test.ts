/**
 * R-01 + S1: Panic PIN tests
 *
 * Verified:
 *  1. verifyPanicPin returns true for correct PIN
 *  2. verifyPanicPin returns false for wrong PIN
 *  3. verifyPanicPin returns false when no panic PIN is set
 *  4. No early-return timing leak: the KDF (Argon2id) runs UNCONDITIONALLY on both the
 *     correct- and wrong-PIN path. (S1: the previous wall-clock >=500 ms assertion only
 *     held because the old code ran un-mocked CryptoJS PBKDF2-10k. Argon2id is mocked
 *     fast in this suite, so we assert the structural invariant — the KDF is invoked on
 *     both paths — which is the property that actually defeats the timing oracle.)
 *  5. S1 migration: a legacy PBKDF2-10k hash (no algo marker) still verifies, and is
 *     transparently re-hashed to Argon2id on the first successful verify (no lockout).
 */

// Reset in-memory SecureStore before each test.
const secureStore = require('../__mocks__/expo-secure-store');
beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
});

import { PanicService } from '../src/services/PanicService';
import { Argon2idService } from '../src/services/Argon2idService';
import { fastPbkdf2 } from '../src/services/FastPBKDF2';

const CORRECT_PANIC_PIN = 'panic123!';
const WRONG_PIN         = 'wrong000';

describe('PanicService', () => {
  test('verifyPanicPin: no panic PIN → false', async () => {
    const result = await PanicService.verifyPanicPin('anything');
    expect(result).toBe(false);
  });

  test('verifyPanicPin: correct PIN → true', async () => {
    await PanicService.setPanicPin(CORRECT_PANIC_PIN);
    const result = await PanicService.verifyPanicPin(CORRECT_PANIC_PIN);
    expect(result).toBe(true);
  }, 60000);

  test('verifyPanicPin: wrong PIN → false', async () => {
    await PanicService.setPanicPin(CORRECT_PANIC_PIN);
    const result = await PanicService.verifyPanicPin(WRONG_PIN);
    expect(result).toBe(false);
  }, 60000);

  test('S1: setPanicPin stores the argon2id KDF marker', async () => {
    await PanicService.setPanicPin(CORRECT_PANIC_PIN);
    const algo = await secureStore.getItemAsync('filevault_panic_pin_algo');
    expect(algo).toBe('argon2id');
  }, 60000);

  test('R-01: KDF runs unconditionally on BOTH the correct and the wrong path (no early return)', async () => {
    await PanicService.setPanicPin(CORRECT_PANIC_PIN);

    const spy = jest.spyOn(Argon2idService, 'deriveKey');

    await PanicService.verifyPanicPin(CORRECT_PANIC_PIN);
    const callsAfterCorrect = spy.mock.calls.length;

    await PanicService.verifyPanicPin(WRONG_PIN);
    const callsAfterWrong = spy.mock.calls.length - callsAfterCorrect;

    // Argon2id must have been invoked on each path → no wrong-PIN early-return bypass.
    expect(callsAfterCorrect).toBeGreaterThanOrEqual(1);
    expect(callsAfterWrong).toBeGreaterThanOrEqual(1);

    spy.mockRestore();
  }, 60000);

  test('S1 migration: legacy PBKDF2-10k hash still verifies and is upgraded to argon2id', async () => {
    // Seed a pre-S1 stored hash: PBKDF2-10k, no algo marker.
    const salt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const legacyHash = await fastPbkdf2(CORRECT_PANIC_PIN.normalize('NFC'), salt, 10000, 32);
    await secureStore.setItemAsync('filevault_panic_pin_hash', legacyHash);
    await secureStore.setItemAsync('filevault_panic_pin_salt', salt);
    // (intentionally NO filevault_panic_pin_algo — this is what "legacy" looks like)

    // Correct PIN must still verify against the legacy hash.
    const ok = await PanicService.verifyPanicPin(CORRECT_PANIC_PIN);
    expect(ok).toBe(true);

    // After a successful verify, the hash must have been migrated to Argon2id.
    const algo = await secureStore.getItemAsync('filevault_panic_pin_algo');
    expect(algo).toBe('argon2id');
    const newHash = await secureStore.getItemAsync('filevault_panic_pin_hash');
    expect(newHash).not.toBe(legacyHash); // re-hashed (fresh salt + Argon2id)

    // The migrated hash still verifies the same PIN.
    expect(await PanicService.verifyPanicPin(CORRECT_PANIC_PIN)).toBe(true);
    // And a wrong PIN is still rejected post-migration.
    expect(await PanicService.verifyPanicPin(WRONG_PIN)).toBe(false);
  }, 60000);
});
