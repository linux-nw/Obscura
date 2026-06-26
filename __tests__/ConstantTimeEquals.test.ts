/**
 * S7: correctness of the constant-time comparison FALLBACK.
 *
 * In Jest there is no native module, so SecureCryptoService.constantsTimeEquals takes the
 * JS XOR-accumulate fallback (the native sodium_memcmp path is verified on-device in
 * androidTest/ConstantTimeMemcmpTest.kt). This test asserts the fallback's functional
 * correctness — equal/unequal/length-mismatch. It does NOT assert timing: the JS fallback
 * is documented best-effort only (M4), not guaranteed constant-time.
 */

import { SecureCryptoService } from '../src/services/CryptoService';

describe('S7: constantsTimeEquals JS fallback correctness', () => {
  const A = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

  test('equal strings → true', async () => {
    expect(await SecureCryptoService.constantsTimeEquals(A, A)).toBe(true);
  });

  test('one-nibble difference → false', async () => {
    const B = A.slice(0, -1) + (A.slice(-1) === '8' ? '9' : '8');
    expect(await SecureCryptoService.constantsTimeEquals(A, B)).toBe(false);
  });

  test('first-char difference → false', async () => {
    const B = (A[0] === '0' ? '1' : '0') + A.slice(1);
    expect(await SecureCryptoService.constantsTimeEquals(A, B)).toBe(false);
  });

  test('length mismatch → false', async () => {
    expect(await SecureCryptoService.constantsTimeEquals(A, A + 'ff')).toBe(false);
  });
});
