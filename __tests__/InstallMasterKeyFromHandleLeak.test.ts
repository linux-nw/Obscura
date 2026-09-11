/**
 * InstallMasterKeyFromHandleLeak.test.ts
 *
 * Regression found by an independent review of this session's fixes:
 * installMasterKeyFromHandle's JS-backed branch (Jest/dev without the native module -
 * the only branch Jest can ever exercise) resolved the caller's `handle` to raw hex,
 * wrapped it, and assigned through the `_masterKeyCache` setter - which mints its OWN
 * fresh handle for that hex and never closed the original `handle` parameter. On a real
 * device (native branch) `setMasterHandle(handle)` already retires the old handle and
 * keeps `handle` itself live, so this never reaches production - but every JS-backed
 * key rotation leaked one KeyCustody session (an un-zeroed copy of the now-installed
 * master key) that was never freed. Fixed by explicitly closing `handle` once its value
 * has been resolved and re-registered under the cache's own handle.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { keyCustody } from '../src/services/KeyCustody';

test('installMasterKeyFromHandle (JS-backed) closes the caller-provided handle, no leak', async () => {
  expect(keyCustody.isNative).toBe(false); // sanity: this test only makes sense off-device

  const masterKeyHex = 'ab'.repeat(32);
  const handle = (keyCustody as any).registerRawKey(masterKeyHex);
  expect(keyCustody.has(handle)).toBe(true);

  await SecureCryptoService.installMasterKeyFromHandle(handle, 'TestPassphrase42!');

  // The caller's handle must be closed - its raw key now lives only under the cache's
  // own internally-minted handle, not under the one passed in.
  expect(keyCustody.has(handle)).toBe(false);

  // And the install itself still worked: the vault unlocks with the given passphrase.
  SecureCryptoService.clearAllCaches();
  expect(await SecureCryptoService.unlock('TestPassphrase42!')).toBe(true);
});
