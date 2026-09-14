/**
 * Atomic persistence of the wrapped master key (kek_salt / kdf_meta / master_enc / master_iv /
 * master_mac). These five values used to be written as five independent sequential SecureStore
 * calls with no journal. A process death between two of those writes left a mix of old and new
 * values — the next unlock attempt derives a KEK from one and tries to verify it against the
 * other, the MAC check fails for every passphrase, and the vault is permanently unrecoverable
 * (resumeRotationIfNeeded cannot help here: it requires a prior successful unlock, which this
 * exact corruption blocks).
 *
 * storeWrappedMaster now writes a single WAL blob with the full target state first, then the
 * five individual fields, then deletes the WAL. unlock() / loadMasterKeyForBiometric() restore
 * from a leftover WAL before doing anything else, healing any partial write from before.
 *
 * Verifies:
 *   1. changePassphrase without a crash: old passphrase stops working, new one works.
 *   2. A crash mid-write (WAL written, some fields updated, master_mac still stale) is healed
 *      on the next unlock attempt — the new passphrase unlocks the SAME master key, the old
 *      passphrase no longer works, and the leftover WAL is gone afterward.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';

const OLD_PASSPHRASE = 'OldPassphrase42!';
const NEW_PASSPHRASE = 'NewPassphrase99!';

test('changePassphrase without a crash: old passphrase stops working, new one works', async () => {
  await SecureCryptoService.setupMasterKey(OLD_PASSPHRASE);
  const master = SecureCryptoService.__masterKeyHexForTest()!;

  const changed = await SecureCryptoService.changePassphrase(OLD_PASSPHRASE, NEW_PASSPHRASE);
  expect(changed).toBe(true);

  SecureCryptoService.clearAllCaches();
  expect(await SecureCryptoService.unlock(NEW_PASSPHRASE)).toBe(true);
  expect(SecureCryptoService.__masterKeyHexForTest()).toBe(master);

  SecureCryptoService.clearAllCaches();
  expect(await SecureCryptoService.unlock(OLD_PASSPHRASE)).toBe(false);
});

test('a crash mid-write while persisting the re-wrapped master key is healed on the next unlock attempt', async () => {
  await SecureCryptoService.setupMasterKey(OLD_PASSPHRASE);
  const master = SecureCryptoService.__masterKeyHexForTest()!;

  const original = (SecureCryptoService as any).setItemSecure.bind(SecureCryptoService);
  let crashed = false;
  const spy = jest
    .spyOn(SecureCryptoService as any, 'setItemSecure')
    .mockImplementation(async (...args: unknown[]) => {
      const [key, value] = args as [string, string];
      if (!crashed && key === 'filevault_master_mac') {
        crashed = true;
        throw new Error('simulated process death mid-write');
      }
      return original(key, value);
    });

  const changed = await SecureCryptoService.changePassphrase(OLD_PASSPHRASE, NEW_PASSPHRASE);
  expect(changed).toBe(false);
  expect(crashed).toBe(true);

  spy.mockRestore();

  const walRaw = secureStore._store.get('filevault_master_wal');
  const walMac = walRaw ? JSON.parse(walRaw).macHex : undefined;
  expect(secureStore._store.get('filevault_master_mac')).not.toBe(walMac);
  expect(secureStore._store.has('filevault_master_wal')).toBe(true);

  SecureCryptoService.clearAllCaches();
  const unlockedWithNew = await SecureCryptoService.unlock(NEW_PASSPHRASE);
  expect(unlockedWithNew).toBe(true);
  expect(SecureCryptoService.__masterKeyHexForTest()).toBe(master);
  expect(secureStore._store.has('filevault_master_wal')).toBe(false);

  SecureCryptoService.clearAllCaches();
  expect(await SecureCryptoService.unlock(OLD_PASSPHRASE)).toBe(false);
});
