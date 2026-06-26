/**
 * Layer 3 — the persistent master-key copy is held as a zeroable Uint8Array (M2) and is
 * actively zeroed in place when the vault locks (clearAllCaches) or the key is replaced.
 *
 * This asserts the real mechanism: the `_masterKeyCache` setter backs the key with
 * `__mkBytes` (a Uint8Array) and fills the previous bytes with 0 on every reassignment and
 * on clear — so a memory dump after lock does not find the long-lived key in plaintext.
 *
 * Residual (documented in CRYPTO_PROTOCOL_SPEC.md §15, Layer 3): getMasterKey() returns a
 * fresh transient hex string per call, which lingers in the GC heap until collected; and
 * the key must stay JS-reachable for the AES-CBC+HMAC fallback / KEK-wrapping paths, so a
 * full native-only key custody is not possible in this design.
 */

require('../__mocks__/expo-secure-store');

import { SecureCryptoService } from '../src/services/CryptoService';

describe('Layer 3: master key is zeroed on lock', () => {
  test('clearAllCaches() zeroes the persistent master-key bytes in place', async () => {
    // Install a known 32-byte key via the real getter/setter path.
    (SecureCryptoService as any)._masterKeyCache = 'ab'.repeat(32); // 64 hex chars = 32 bytes
    const backing = (SecureCryptoService as any).__mkBytes as Uint8Array;

    expect(backing).toBeInstanceOf(Uint8Array);
    expect(backing.length).toBe(32);
    expect(Array.from(backing).every((b) => b === 0xab)).toBe(true); // key material present
    expect(await SecureCryptoService.getMasterKey()).toBe('ab'.repeat(32));

    // Lock the vault.
    SecureCryptoService.clearAllCaches();

    // The previously-held array is zeroed in place (same reference), and the key is gone.
    expect(Array.from(backing).every((b) => b === 0)).toBe(true);
    expect((SecureCryptoService as any).__mkBytes).toBeNull();
    expect(await SecureCryptoService.getMasterKey()).toBeNull();
  });

  test('reassigning the key zeroes the previous key material', async () => {
    (SecureCryptoService as any)._masterKeyCache = 'cd'.repeat(32);
    const first = (SecureCryptoService as any).__mkBytes as Uint8Array;
    expect(Array.from(first).every((b) => b === 0xcd)).toBe(true);

    (SecureCryptoService as any)._masterKeyCache = 'ef'.repeat(32);

    // The old buffer is zeroed; the new one holds the new key.
    expect(Array.from(first).every((b) => b === 0)).toBe(true);
    const second = (SecureCryptoService as any).__mkBytes as Uint8Array;
    expect(Array.from(second).every((b) => b === 0xef)).toBe(true);

    SecureCryptoService.clearAllCaches();
  });
});
