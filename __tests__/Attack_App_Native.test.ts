/**
 * Attack_App_Native — red-team: forged/missing/throwing native results must fail closed.
 */
// Each test starts from a fresh module registry; NM is rebound to that registry's NativeModules
// (modules read NativeModules at load time, so natives must be planted before the first require).
let NM: any;
beforeEach(() => {
  jest.resetModules();
  NM = require('react-native').NativeModules;
});
afterEach(() => {
  require('../__mocks__/expo-secure-store')._reset();
});

const loadIntegrityNative = (mod: any) => {
  NM.IntegrityNative = mod;
  jest.resetModules();
  const rn = require('react-native');
  rn.NativeModules.IntegrityNative = mod;
  NM = rn.NativeModules;
  return require('../src/native/IntegrityNative');
};

describe('Attack_App: IntegrityNative forged results', () => {
  const forged: Array<[string, any]> = [
    ['string "false" isValid', { configured: true, isValid: 'false' }],
    ['numeric 1 isValid', { configured: true, isValid: 1 }],
    ['string configured + valid', { configured: 'yes', isValid: true }],
    ['null result', null],
    ['undefined result', undefined],
    ['primitive result', 'valid'],
    ['empty object', {}],
  ];
  test.each(forged)('%s never yields valid', async (_n, r) => {
    const m = loadIntegrityNative({ verifyPinnedSignature: async () => r });
    expect(await m.verifyPinnedSignature()).not.toBe('valid');
  });
  test('mismatch is invalid; match is valid; throw/reject is unverifiable', async () => {
    expect(await loadIntegrityNative({ verifyPinnedSignature: async () => ({ configured: true, isValid: false }) }).verifyPinnedSignature()).toBe('invalid');
    expect(await loadIntegrityNative({ verifyPinnedSignature: async () => ({ configured: true, isValid: true }) }).verifyPinnedSignature()).toBe('valid');
    expect(await loadIntegrityNative({ verifyPinnedSignature: async () => { throw new Error('x'); } }).verifyPinnedSignature()).toBe('unverifiable');
    expect(await loadIntegrityNative({ verifyPinnedSignature: () => { throw new Error('sync'); } }).verifyPinnedSignature()).toBe('unverifiable');
  });
  test('missing module is unverifiable, never valid', async () => {
    const m = loadIntegrityNative(undefined);
    expect(await m.verifyPinnedSignature()).toBe('unverifiable');
  });
  test('installer check: forged truthy string is not trusted; malformed result degrades', async () => {
    const m = loadIntegrityNative({ checkInstallerIntegrity: async () => ({ installer: 'evil', fromTrustedSource: 'true' }) });
    expect((await m.checkInstallerIntegrity()).fromTrustedSource).toBe(false);
    const m2 = loadIntegrityNative({ checkInstallerIntegrity: async () => null });
    expect(await m2.checkInstallerIntegrity()).toEqual({ installer: 'unknown', fromTrustedSource: false });
  });
});

describe('Attack_App: IntegrityService stored result tamper', () => {
  const KEY = 'filevault_integrity_result';
  const check = async (raw: string) => {
    require('../__mocks__/expo-secure-store')._store.set(KEY, raw);
    const { IntegrityService } = require('../src/services/IntegrityService');
    return IntegrityService;
  };
  test.each(['not json', 'null', '"str"', '{}', '{"isIntact":"true"}', '{"isIntact":1}', '[]'])('corrupt record %s => compromised', async (raw) => {
    const S = await check(raw);
    expect(await S.wasCompromised()).toBe(true);
    expect((await S.getLastCheckStatus()).isIntact).toBe(false);
  });
  test('well-formed intact record is intact', async () => {
    const S = await check('{"isIntact":true,"timestamp":1}');
    expect(await S.wasCompromised()).toBe(false);
  });
  test('invalid signature verdict fails integrity check', async () => {
    NM.IntegrityNative = { verifyPinnedSignature: async () => ({ configured: true, isValid: false }) };
    const { IntegrityService } = require('../src/services/IntegrityService');
    const st = await IntegrityService.checkIntegrity();
    expect(st.isIntact).toBe(false);
    expect(await IntegrityService.wasCompromised()).toBe(true);
  });
  test('signature verify throwing at module level never reports intact via checkIntegrity', async () => {
    NM.IntegrityNative = { verifyPinnedSignature: async () => ({ configured: true, isValid: 'false' }) };
    const { IntegrityService } = require('../src/services/IntegrityService');
    expect((await IntegrityService.checkIntegrity()).isIntact).toBe(false as boolean);
  });
  test('tamper response sets permanent lock even when key deletion throws', async () => {
    const CS = require('../src/services/CryptoService').SecureCryptoService;
    jest.spyOn(CS, 'deleteEncryptionKey').mockRejectedValue(new Error('fs'));
    const { IntegrityService } = require('../src/services/IntegrityService');
    await IntegrityService.triggerTamperResponse();
    const lock = require('../__mocks__/expo-secure-store')._store.get('filevault_lock_until');
    // Fail-closed expectation: permanent lock must be applied despite the throw.
    expect(lock).toBeDefined();
  });
});

describe('Attack_App: DeviceSecurity fail-closed', () => {
  const base = () => ({
    getTracerPid: async () => 0,
    checkFridaModules: async () => [],
    checkDebuggable: async () => false,
    checkSuBinary: async () => false,
    checkRootKeysInPackage: async () => false,
  });
  const run = async () => {
    const { DeviceSecurityService } = require('../src/services/DeviceSecurityService');
    const r = await DeviceSecurityService.checkDeviceSecurity();
    await DeviceSecurityService.resetSecurityChecks();
    return r;
  };
  test('baseline clean is secure', async () => {
    NM.DeviceSecurity = base();
    expect((await run()).securityLevel).toBe('secure');
  });
  test.each(['getTracerPid', 'checkFridaModules', 'checkDebuggable', 'checkSuBinary', 'checkRootKeysInPackage'])('%s rejecting is not "clean"', async (m) => {
    NM.DeviceSecurity = { ...base(), [m]: async () => { throw new Error('hooked'); } };
    const r = await run();
    expect(r.isSecure).toBe(false);
    expect(r.detectedTampering).toBe(true);
  });
  test.each(['getTracerPid', 'checkFridaModules', 'checkSuBinary'])('%s stripped from module is not "clean"', async (m) => {
    const d: any = base(); delete d[m];
    NM.DeviceSecurity = d;
    expect((await run()).isSecure).toBe(false);
  });
  test('forged non-array Frida result is not clean', async () => {
    NM.DeviceSecurity = { ...base(), checkFridaModules: async () => 'frida' };
    expect((await run()).securityLevel).toBe('critical');
  });
  test('forged tracer pid values', async () => {
    for (const v of [1, 4242, '1', -1, true]) {
      NM.DeviceSecurity = { ...base(), getTracerPid: async () => v };
      expect((await run()).securityLevel).toBe('critical');
    }
  });
  test('module missing in release build => not secure', async () => {
    (global as any).__DEV__ = false;
    const r = await run();
    expect(r.isSecure).toBe(false);
    expect(r.detectionMethod).toBe('native_module_missing');
    (global as any).__DEV__ = true;
  });
  test('PenTest audit never passes native checks when modules are absent/throwing', async () => {
    NM.DeviceSecurity = { ...base(), checkSuBinary: async () => { throw new Error('x'); } };
    const { PenTestService } = require('../src/services/PenTestService');
    const rep = await PenTestService.runSecurityAudit();
    const by = (n: string) => rep.checks.find((c: any) => c.check === n);
    expect(by('NativeCrypto').passed).toBe(false);
    expect(by('KeyDerivation').passed).toBe(false);
    expect(by('AppIntegrity').passed).toBe(false);
    expect(by('ScreenProtection').passed).toBe(false);
    expect(by('DeviceSecurity').passed).toBe(false);
    expect(rep.overallScore).toBeLessThan(rep.maxScore);
    expect(await PenTestService.wereAllChecksPassed()).toBe(false);
  });
  test('PenTest: planted passed-count in store cannot fake all-clear without a real zero', async () => {
    const ss = require('../__mocks__/expo-secure-store');
    const { PenTestService } = require('../src/services/PenTestService');
    expect(await PenTestService.wereAllChecksPassed()).toBe(false);
    ss._store.set('filevault_checks_failed', 'abc');
    expect(await PenTestService.wereAllChecksPassed()).toBe(false);
  });
});

describe('Attack_App: ScreenProtection cannot be disabled from JS', () => {
  test('disable never calls native disable and flag stays reported', async () => {
    const disable = jest.fn(async () => true);
    NM.ScreenSecurity = { enable: jest.fn(async () => true), disable, isEnabled: jest.fn(async () => true) };
    const { ScreenProtectionService } = require('../src/services/ScreenProtectionService');
    await ScreenProtectionService.enableScreenCaptureBlocking();
    await ScreenProtectionService.disableScreenCaptureBlocking();
    expect(disable).not.toHaveBeenCalled();
    expect(await ScreenProtectionService.isScreenCaptureBlocked()).toBe(true);
  });
  test('native isEnabled throwing or module absent => reported NOT blocked (never claims safe)', async () => {
    NM.ScreenSecurity = { enable: async () => true, disable: async () => true, isEnabled: async () => { throw new Error('x'); } };
    let S = require('../src/services/ScreenProtectionService').ScreenProtectionService;
    expect(await S.isScreenCaptureBlocked()).toBe(false);
    delete NM.ScreenSecurity; jest.resetModules();
    S = require('../src/services/ScreenProtectionService').ScreenProtectionService;
    expect(await S.isScreenCaptureBlocked()).toBe(false);
    expect((await S.checkProtectionStatus()).nativeModuleAvailable).toBe(false);
  });
  test('screenshot/recording "detection" never fakes an all-clear true', async () => {
    const S = require('../src/services/ScreenProtectionService').ScreenProtectionService;
    expect(await S.detectScreenshot()).toBe(false);
    expect(await S.checkScreenRecording()).toBe(false);
  });
  test('Kotlin ScreenSecurity.disable never clears FLAG_SECURE; MainActivity sets it', () => {
    const fs = require('fs');
    const k = fs.readFileSync('android/app/src/main/java/com/filevault/app/modules/ScreenSecurityModule.kt', 'utf8');
    expect(k).not.toMatch(/clearFlags/);
    const a = fs.readFileSync('android/app/src/main/java/com/filevault/app/MainActivity.kt', 'utf8');
    expect(a).toMatch(/FLAG_SECURE/);
    expect(a).not.toMatch(/clearFlags/);
  });
});
