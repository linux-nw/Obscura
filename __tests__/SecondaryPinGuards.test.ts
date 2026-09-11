/**
 * SecondaryPinGuards.test.ts
 *
 * Two Entsperr-Flow findings from the audit:
 *
 *  1. PIN-length inconsistency: DecoyVaultService.setDecoyPin already enforced
 *     SettingsService.minPinLength; PanicService.setPanicPin enforced nothing at the
 *     service level (only a hardcoded UI check existed, bypassable by any other caller).
 *     PanicService.setPanicPin now enforces the same floor.
 *
 *  2. No collision check between panic/decoy PIN and the real vault passphrase: since
 *     AuthScreen checks the panic PIN first, a panic PIN colliding with the real
 *     passphrase would make the correct passphrase silently trigger a wipe/lock instead
 *     of unlocking. SettingsScreen's panic/decoy PIN setup now probes
 *     SecureCryptoService.unlock() (the same primitive AuthScreen itself uses to
 *     recognise the real passphrase) and PanicService.verifyPanicPin /
 *     DecoyVaultService.verifyDecoyPin before accepting a new secondary PIN. This test
 *     proves those underlying primitives actually detect the collision the UI guards
 *     against (SettingsScreen.tsx:367-379, :411-429) — the component itself has no
 *     render-level test harness in this project, so the guard's real precondition
 *     (unlock() recognising the exact vault passphrase) is verified directly here.
 *
 * Also verifies the isAppInitialized() self-healing fix (CryptoService.ts): a wipe that
 * crashes after deleting the master key but before persisting app_initialized=false must
 * not leave the app in a state that looks "initialized" yet can never unlock again.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { PanicService } from '../src/services/PanicService';
import { DecoyVaultService } from '../src/services/DecoyVaultService';

const VAULT_PASSPHRASE = 'RealVaultPassphrase42!';

describe('PanicService.setPanicPin: minPinLength enforcement', () => {
  test('rejects a PIN shorter than the configured floor (default 8)', async () => {
    await expect(PanicService.setPanicPin('short')).rejects.toThrow(/mindestens/i);
  });

  test('accepts a PIN meeting the floor', async () => {
    await expect(PanicService.setPanicPin('longenough1')).resolves.toBeUndefined();
  });
});

describe('Collision primitives used by the SettingsScreen panic/decoy PIN guards', () => {
  test('SecureCryptoService.unlock() recognises the real vault passphrase (the panic/decoy-vs-passphrase guard relies on this)', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASSPHRASE);
    await expect(SecureCryptoService.unlock(VAULT_PASSPHRASE)).resolves.toBe(true);
    await expect(SecureCryptoService.unlock('something-else-entirely')).resolves.toBe(false);
  }, 60000);

  test('PanicService.verifyPanicPin / DecoyVaultService.verifyDecoyPin detect a cross-collision', async () => {
    await PanicService.setPanicPin('panicpin123');
    await expect(DecoyVaultService.verifyDecoyPin('panicpin123')).resolves.toBe(false);
    await expect(PanicService.verifyPanicPin('panicpin123')).resolves.toBe(true);

    // Simulating what SettingsScreen's decoy-PIN guard checks before accepting 'panicpin123'
    // as a NEW decoy PIN: it must see the existing panic PIN and refuse.
    const wouldCollide = await PanicService.verifyPanicPin('panicpin123');
    expect(wouldCollide).toBe(true);
  }, 60000);
});

describe('CryptoService.isAppInitialized: self-healing against a crash mid-wipe', () => {
  test('flag true + master key present → initialized', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASSPHRASE);
    await SecureCryptoService.setAppInitialized(true);
    await expect(SecureCryptoService.isAppInitialized()).resolves.toBe(true);
  }, 60000);

  test('flag true but master key material missing (crash after key deletion, before flag write) → NOT initialized', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASSPHRASE);
    await SecureCryptoService.setAppInitialized(true);

    // Simulate the crash window: the wipe already deleted the master key material but
    // never reached the final setAppInitialized(false) call.
    secureStore._store.delete('filevault_master_enc');
    secureStore._store.delete('filevault_encryption_key');

    await expect(SecureCryptoService.isAppInitialized()).resolves.toBe(false);
  }, 60000);

  test('flag false → never initialized regardless of key material', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASSPHRASE);
    await SecureCryptoService.setAppInitialized(false);
    await expect(SecureCryptoService.isAppInitialized()).resolves.toBe(false);
  }, 60000);
});
