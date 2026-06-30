/**
 * Layer 3 / L3 Phase 2 — the master key is addressed by an opaque custody HANDLE, and the
 * underlying key material is zeroed + dropped when the vault locks (clearAllCaches) or the
 * key is replaced.
 *
 * This asserts the real mechanism after the Phase 2 rewire:
 *   - installing a key (the `_masterKeyCache` setter) registers it into KeyCustody and stores
 *     only the opaque handle on the service (`__masterHandle`); the raw key is never held as
 *     a field;
 *   - locking (clearAllCaches) closes the handle: KeyCustody zeroes the key bytes in place
 *     and drops them, so the handle is no longer resolvable and the key is gone;
 *   - reassigning the key closes the previous handle (old key material zeroed + dropped).
 *
 * Phase 2a is JS-BACKED (documented in KeyCustody.ts and CRYPTO_PROTOCOL_SPEC.md §15.5): the
 * raw key still lives in the JS heap inside KeyCustody until Phase 2b moves it to native
 * secure memory. getMasterKey() no longer returns the key — it throws; tests resolve the
 * current key through the test-only `__masterKeyHexForTest()` seam.
 */

require('../__mocks__/expo-secure-store');

import { SecureCryptoService } from '../src/services/CryptoService';
import { keyCustody, JsBackedKeyCustody } from '../src/services/KeyCustody';

// Under Jest there is no native module, so custody is JS-backed and the resolve() seam exists.
// (On device the backing is native, isNative === true, and resolve() is gone — see KeyCustody.ts.)
const jsCustody = keyCustody as JsBackedKeyCustody;

describe('Layer 3: master key lives behind a custody handle and is zeroed on lock', () => {
  test('installing a key stores only a handle; the key is resolvable via the handle', () => {
    (SecureCryptoService as any)._masterKeyCache = 'ab'.repeat(32); // 64 hex chars = 32 bytes
    const handle = (SecureCryptoService as any).__masterHandle as string;

    // The service holds an opaque 128-bit handle (32 hex chars), NOT the key bytes.
    expect(typeof handle).toBe('string');
    expect(handle).toHaveLength(32);
    expect(handle).not.toBe('ab'.repeat(32));
    expect(keyCustody.has(handle)).toBe(true);
    // The key is resolvable only through the custody handle (test-only seam).
    expect(SecureCryptoService.__masterKeyHexForTest()).toBe('ab'.repeat(32));

    SecureCryptoService.clearAllCaches();
  });

  test('clearAllCaches() closes the handle: key zeroed + dropped, vault locked', () => {
    (SecureCryptoService as any)._masterKeyCache = 'ab'.repeat(32);
    const handle = (SecureCryptoService as any).__masterHandle as string;
    expect(keyCustody.has(handle)).toBe(true);

    // Lock the vault.
    SecureCryptoService.clearAllCaches();

    // The handle is closed (key bytes zeroed in place + dropped) and the vault is locked.
    expect(keyCustody.has(handle)).toBe(false);
    expect(() => jsCustody.resolve(handle)).toThrow();
    expect((SecureCryptoService as any).__masterHandle).toBeNull();
    expect(SecureCryptoService.__masterKeyHexForTest()).toBeNull();
  });

  test('reassigning the key closes the previous handle', () => {
    (SecureCryptoService as any)._masterKeyCache = 'cd'.repeat(32);
    const first = (SecureCryptoService as any).__masterHandle as string;
    expect(SecureCryptoService.__masterKeyHexForTest()).toBe('cd'.repeat(32));

    (SecureCryptoService as any)._masterKeyCache = 'ef'.repeat(32);

    // The old handle is closed; the new one holds the new key.
    expect(keyCustody.has(first)).toBe(false);
    expect(() => jsCustody.resolve(first)).toThrow();
    const second = (SecureCryptoService as any).__masterHandle as string;
    expect(second).not.toBe(first);
    expect(SecureCryptoService.__masterKeyHexForTest()).toBe('ef'.repeat(32));

    SecureCryptoService.clearAllCaches();
  });
});
