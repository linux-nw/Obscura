/**
 * Layer 7 — APK signing-cert self-check is real and FAIL-CLOSED.
 *
 * Before L7 the JS IntegrityService.checkSignature() was a stub: it read a
 * SecureStore placeholder ('expected_app_hash_placeholder'), self-seeded it on
 * first run (TOFU — a repackager just lets it seed), and `return true`d
 * unconditionally. Nothing ever called the (real) native IntegrityModule.
 *
 * L7 wires JS -> native verifyPinnedSignature(), which compares the running APK's
 * signing cert against BuildConfig.SIGNING_CERT_SHA256 (baked in at build time).
 *
 * This proves the verdict mapping and that the aggregate integrity check is:
 *   - fail-closed on a real mismatch ('invalid' -> isIntact false), AND
 *   - non-bricking on absence/unconfigured ('unverifiable' -> isIntact true),
 *     so a debug build or a missing native module never locks a legit user out.
 *
 * The native module is captured at import time, so each case re-requires the
 * module under test inside jest.isolateModules with a fresh react-native mock.
 */

type Verdict = 'valid' | 'invalid' | 'unverifiable';

interface NativeStub {
  verifyPinnedSignature?: jest.Mock;
  checkInstallerIntegrity?: jest.Mock;
}

function loadNative(native: NativeStub | undefined) {
  let mod!: typeof import('../src/native/IntegrityNative');
  jest.isolateModules(() => {
    const RN = require('react-native');
    RN.NativeModules.IntegrityNative = native;
    mod = require('../src/native/IntegrityNative');
  });
  return mod;
}

function loadService(native: NativeStub | undefined) {
  let svc!: typeof import('../src/services/IntegrityService').IntegrityService;
  jest.isolateModules(() => {
    const RN = require('react-native');
    RN.NativeModules.IntegrityNative = native;
    require('../__mocks__/expo-secure-store')._reset?.();
    svc = require('../src/services/IntegrityService').IntegrityService;
  });
  return svc;
}

const ok = (over: Partial<{ configured: boolean; isValid: boolean; actualHash: string }> = {}) =>
  jest.fn(async () => ({ configured: true, isValid: true, actualHash: 'AB:CD', ...over }));

describe('Layer 7: pinned signature verification (verdict mapping)', () => {
  const cases: Array<[string, NativeStub | undefined, Verdict]> = [
    ['cert matches pinned hash', { verifyPinnedSignature: ok() }, 'valid'],
    ['cert mismatched (repackaged)', { verifyPinnedSignature: ok({ isValid: false }) }, 'invalid'],
    ['no hash pinned (debug build)', { verifyPinnedSignature: ok({ configured: false, isValid: false }) }, 'unverifiable'],
    ['native module absent', undefined, 'unverifiable'],
    ['native module empty (no method)', {}, 'unverifiable'],
  ];

  test.each(cases)('%s -> %s', async (_label, native, expected) => {
    const { verifyPinnedSignature } = loadNative(native);
    await expect(verifyPinnedSignature()).resolves.toBe(expected);
  });

  test('native throws -> unverifiable (never a false valid)', async () => {
    const native = { verifyPinnedSignature: jest.fn(async () => { throw new Error('bridge error'); }) };
    const { verifyPinnedSignature } = loadNative(native);
    await expect(verifyPinnedSignature()).resolves.toBe('unverifiable');
  });
});

describe('Layer 7: aggregate integrity is fail-closed but not self-bricking', () => {
  test('mismatched cert -> isIntact false', async () => {
    const svc = loadService({ verifyPinnedSignature: ok({ isValid: false }) });
    const status = await svc.checkIntegrity();
    expect(status.isIntact).toBe(false);
    expect(status.checksFailed).toBeGreaterThanOrEqual(1);
  });

  test('matching cert -> isIntact true', async () => {
    const svc = loadService({ verifyPinnedSignature: ok() });
    const status = await svc.checkIntegrity();
    expect(status.isIntact).toBe(true);
  });

  test('unverifiable (native absent) -> isIntact true (no false lockout)', async () => {
    const svc = loadService(undefined);
    const status = await svc.checkIntegrity();
    expect(status.isIntact).toBe(true);
    await expect(svc.verifyAppSignature()).resolves.toBe('unverifiable');
  });
});
