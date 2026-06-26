/**
 * RegressionBugs.test.ts — guards for Round 4 catastrophic data-loss bugs.
 *
 * These tests use the REAL CryptoService (no module mock).
 * FileManager persistence tests (R-C, R-D) are in RegressionFileManager.test.ts.
 *
 * R-A: clearAllCaches() must NOT delete SecureStore keys (Bug 1+2)
 * R-B: isAppInitialized() must survive clearAllCaches() (Bug 3)
 * R-E: AutoLockService.triggerLock() fires the registered callback (Bug 9)
 * R-F: Key wrapping never dispatches to XChaCha20 (device crash: nonce 16≠24)
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { AutoLockService } from '../src/services/AutoLockService';

// ─── R-A: clearAllCaches() nur In-Memory, kein SecureStore-Touch ─────────────

describe('R-A: clearAllCaches() does NOT delete SecureStore keys', () => {
  test('master key wrapper survives clearAllCaches()', async () => {
    await SecureCryptoService.setupMasterKey('RegressionTest!');

    expect(secureStore._store.has('filevault_master_enc')).toBe(true);
    expect(secureStore._store.has('filevault_kek_salt')).toBe(true);

    SecureCryptoService.clearAllCaches();

    // SecureStore must be untouched
    expect(secureStore._store.has('filevault_master_enc')).toBe(true);
    expect(secureStore._store.has('filevault_kek_salt')).toBe(true);
    expect(secureStore._store.has('filevault_master_iv')).toBe(true);
    expect(secureStore._store.has('filevault_master_mac')).toBe(true);

    // Only in-memory cache cleared
    expect((SecureCryptoService as any)._masterKeyCache).toBeNull();
    expect((SecureCryptoService as any).macKeyCache.size).toBe(0);
  }, 60000);

  test('vault is still unlockable after clearAllCaches()', async () => {
    await SecureCryptoService.setupMasterKey('RegressionTest!');
    SecureCryptoService.clearAllCaches();

    const unlocked = await SecureCryptoService.unlock('RegressionTest!');
    expect(unlocked).toBe(true);
    expect((SecureCryptoService as any)._masterKeyCache).not.toBeNull();
  }, 60000);
});

// ─── R-B: isAppInitialized() überlebt clearAllCaches() ───────────────────────

describe('R-B: isAppInitialized() survives clearAllCaches()', () => {
  test('setAppInitialized(true) → clearAllCaches() → still true', async () => {
    await SecureCryptoService.setAppInitialized(true);
    expect(await SecureCryptoService.isAppInitialized()).toBe(true);

    SecureCryptoService.clearAllCaches();

    // Must still be true — clearAllCaches() must NOT call setAppInitialized(false)
    expect(await SecureCryptoService.isAppInitialized()).toBe(true);
  });
});

// ─── R-E: AutoLock-Callback ───────────────────────────────────────────────────

describe('R-E: AutoLockService.triggerLock() fires the registered callback', () => {
  test('callback is called exactly once on triggerLock()', async () => {
    const mockCallback = jest.fn();
    AutoLockService.setLockCallback(mockCallback);
    await AutoLockService.triggerLock();
    expect(mockCallback).toHaveBeenCalledTimes(1);
    AutoLockService.setLockCallback(() => {});
  });

  test('no callback (null) → triggerLock() does not throw', async () => {
    (AutoLockService as any).lockCallback = null;
    await expect(AutoLockService.triggerLock()).resolves.not.toThrow();
  });
});

// ─── R-F: Key wrapping nutzt nie XChaCha20 (Device crash fix) ────────────────

describe('R-F: key wrapping (aesCBCEncrypt) never dispatches to XChaCha20', () => {
  test('xchacha20Encrypt is NOT called during setupMasterKey', async () => {
    const spy = jest.spyOn(SecureCryptoService as any, 'xchacha20Encrypt');

    await SecureCryptoService.setupMasterKey('NonceBugTest!');

    // If this spy was called, it would fail with "Nonce must be 24 bytes (got 16)"
    // on a real device. It must NEVER be called for key wrapping.
    expect(spy).not.toHaveBeenCalled();

    spy.mockRestore();
  }, 60000);

  test('xchacha20Encrypt is NOT called during encryptFileKey', async () => {
    await SecureCryptoService.setupMasterKey('FileKeyTest!');
    const spy = jest.spyOn(SecureCryptoService as any, 'xchacha20Encrypt');

    await SecureCryptoService.encryptFileKey('a'.repeat(64));

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  }, 60000);

  test('aesCbcHmacWrapEncrypt IS called during key wrapping', async () => {
    const spy = jest.spyOn(SecureCryptoService as any, 'aesCbcHmacWrapEncrypt');

    await SecureCryptoService.setupMasterKey('AesCbcHmacTest!');

    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  }, 60000);
});
