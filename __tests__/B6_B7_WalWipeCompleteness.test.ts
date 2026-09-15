/**
 * B6_B7_WalWipeCompleteness.test.ts
 *
 * B.6 (AUDIT_2026-09-15-v2.md): restoreMasterWalIfNeeded()'s old `finally` deleted the WAL
 * unconditionally — even if the repair itself failed partway through (one of the 5 field
 * writes throws). That discards the one artifact a later attempt could have retried the
 * repair from. Proves: a failed repair attempt leaves the WAL in place; a subsequent,
 * unobstructed attempt then succeeds and the WAL is gone.
 *
 * B.7: deleteEncryptionKey() (used by both PanicService.performPanicWipe() and
 * SecureDeleteService.secureWipeAll()) never cleared filevault_master_wal or
 * filevault_kdf_meta. In the narrow window between a crash mid-write and the next unlock,
 * a "complete" wipe could leave old wrapped-master key material behind. Proves: both keys
 * are gone after deleteEncryptionKey(), when a leftover WAL/kdf_meta existed beforehand.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';

const OLD_PASSPHRASE = 'OldPassphrase42!';
const NEW_PASSPHRASE = 'NewPassphrase99!';

describe('B.6: WAL is only discarded once a repair actually succeeds', () => {
  test('a second failure DURING the repair leaves the WAL in place; a later clean attempt then heals it', async () => {
    await SecureCryptoService.setupMasterKey(OLD_PASSPHRASE);
    const master = SecureCryptoService.__masterKeyHexForTest()!;

    const original = (SecureCryptoService as any).setItemSecure.bind(SecureCryptoService);

    // First crash: leaves a genuine leftover WAL (same setup as MasterKeyWAL.test.ts).
    let firstCrashed = false;
    let spy = jest
      .spyOn(SecureCryptoService as any, 'setItemSecure')
      .mockImplementation(async (...args: unknown[]) => {
        const [key, value] = args as [string, string];
        if (!firstCrashed && key === 'filevault_master_mac') {
          firstCrashed = true;
          throw new Error('simulated process death mid-write');
        }
        return original(key, value);
      });
    const changed = await SecureCryptoService.changePassphrase(OLD_PASSPHRASE, NEW_PASSPHRASE);
    expect(changed).toBe(false);
    spy.mockRestore();
    expect(secureStore._store.has('filevault_master_wal')).toBe(true);

    // Second failure: THIS TIME during the repair itself (restoreMasterWalIfNeeded's own
    // field writes), triggered by the next unlock() attempt.
    let secondCrashed = false;
    spy = jest
      .spyOn(SecureCryptoService as any, 'setItemSecure')
      .mockImplementation(async (...args: unknown[]) => {
        const [key, value] = args as [string, string];
        if (!secondCrashed && key === 'filevault_master_iv') {
          secondCrashed = true;
          throw new Error('simulated second, unrelated failure during WAL repair');
        }
        return original(key, value);
      });

    const failedUnlock = await SecureCryptoService.unlock(NEW_PASSPHRASE);
    expect(failedUnlock).toBe(false);
    expect(secondCrashed).toBe(true);
    spy.mockRestore();

    // The fix: the WAL must still be here — the old unconditional `finally` would have
    // deleted it even though the repair it was tracking never completed.
    expect(secureStore._store.has('filevault_master_wal')).toBe(true);

    // A later, unobstructed attempt can still heal from that surviving WAL.
    const healedUnlock = await SecureCryptoService.unlock(NEW_PASSPHRASE);
    expect(healedUnlock).toBe(true);
    expect(SecureCryptoService.__masterKeyHexForTest()).toBe(master);
    expect(secureStore._store.has('filevault_master_wal')).toBe(false);
  }, 60000);
});

describe('B.7: deleteEncryptionKey() clears the WAL and KDF-meta marker too', () => {
  test('a leftover WAL blob and kdf_meta marker are gone after deleteEncryptionKey()', async () => {
    await SecureCryptoService.setupMasterKey(OLD_PASSPHRASE);

    // Simulate the crash window: a WAL blob left behind (kdf_meta already exists from setup).
    secureStore._store.set(
      'filevault_master_wal',
      JSON.stringify({
        kekSaltHex: 'aa'.repeat(16),
        kdfMeta: 'argon2id-v1',
        ctHex: 'bb'.repeat(32),
        ivHex: 'cc'.repeat(16),
        macHex: 'dd'.repeat(32),
      }),
    );
    expect(secureStore._store.has('filevault_master_wal')).toBe(true);
    expect(secureStore._store.has('filevault_kdf_meta')).toBe(true);

    await SecureCryptoService.deleteEncryptionKey();

    expect(secureStore._store.has('filevault_master_wal')).toBe(false);
    expect(secureStore._store.has('filevault_kdf_meta')).toBe(false);
    // Existing wipe coverage unaffected.
    expect(secureStore._store.has('filevault_master_enc')).toBe(false);
    expect(secureStore._store.has('filevault_master_mac')).toBe(false);
  }, 30000);
});
