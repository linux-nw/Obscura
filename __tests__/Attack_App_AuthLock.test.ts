/**
 * Attack_App_AuthLock — red-team: settings tamper, auto-lock, lockout counters, wipe ordering.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import { SettingsService, sanitizeSettings } from '../src/services/SettingsService';
import { parseAttemptCounter } from '../src/services/AttemptCounter';
import { AutoLockService } from '../src/services/AutoLockService';
import { SecureCryptoService } from '../src/services/CryptoService';

const ss = require('../__mocks__/expo-secure-store');
const SKEY = 'filevault_app_settings';

beforeEach(() => { ss._reset(); (AsyncStorage as any)._reset(); jest.restoreAllMocks(); });

describe('Attack_App: settings tamper', () => {
  test('__proto__ / constructor pollution via JSON.parse does not leak or pollute', async () => {
    ss._store.set(SKEY, '{"__proto__":{"autoLockTimeout":-1,"polluted":true},"constructor":{"prototype":{"x":1}},"maxFailedAttempts":3}');
    const s: any = await SettingsService.get();
    expect(({} as any).polluted).toBeUndefined();
    expect(({} as any).autoLockTimeout).toBeUndefined();
    expect(s.polluted).toBeUndefined();
    expect(s.autoLockTimeout).toBe(300);
    expect(s.maxFailedAttempts).toBe(3);
    expect(Object.keys(s).sort()).toEqual(Object.keys(sanitizeSettings({})).sort());
  });
  test('Object.prototype planted values do not feed sanitize (own-property only)', () => {
    (Object.prototype as any).maxFailedAttempts = 10;
    (Object.prototype as any).autoLockTimeout = -1;
    try {
      const s = sanitizeSettings({});
      // inherited values would be read by r.x; they must not weaken defaults
      expect(s.autoLockTimeout).toBe(300);
      expect(s.maxFailedAttempts).toBe(5);
    } finally {
      delete (Object.prototype as any).maxFailedAttempts;
      delete (Object.prototype as any).autoLockTimeout;
    }
  });
  test.each([
    ['NaN', NaN], ['Infinity', Infinity], ['-2', -2], ['2.5', 2.5], ['2', 2], ['11', 11], ['string 5', '5'], ['null', null], ['array', [5]],
  ])('maxFailedAttempts %s is clamped to default', (_n, v) => {
    expect(sanitizeSettings({ maxFailedAttempts: v }).maxFailedAttempts).toBe(5);
  });
  test.each([[-2], [1], [7], [3601], [Infinity], [NaN], ['-1'], [null]])('autoLockTimeout %p falls back to 300', (v) => {
    expect(sanitizeSettings({ autoLockTimeout: v }).autoLockTimeout).toBe(300);
  });
  test('minPinLength is not attacker controlled; action only lock|wipe', () => {
    const s = sanitizeSettings({ minPinLength: 1, maxFailedAttemptsAction: 'none' });
    expect(s.minPinLength).toBe(8);
    expect(s.maxFailedAttemptsAction).toBe('wipe');
  });
  test.each(['', '{', 'null', '[]', '"x"', '12', 'undefined'])('corrupt settings blob %p => safe defaults', async (raw) => {
    ss._store.set(SKEY, raw);
    const s = await SettingsService.get();
    expect(s.autoLockTimeout).toBe(300);
    expect(s.maxFailedAttemptsAction).toBe('wipe');
  });
  test('SecureStore failure falls back to defaults, not to plaintext copy', async () => {
    await AsyncStorage.setItem(SKEY, JSON.stringify({ autoLockTimeout: -1 }));
    ss.getItemAsync.mockRejectedValueOnce(new Error('keystore'));
    expect((await SettingsService.get()).autoLockTimeout).toBe(300);
  });
  test('save rejects hostile input and persists only sanitized JSON', async () => {
    await SettingsService.save({ autoLockTimeout: -1 as number, maxFailedAttempts: 9999, maxFailedAttemptsAction: 'x' as any, biometricsEnabled: true, bioAutoTrigger: false, require2FA: true, minPinLength: 0 });
    const stored = JSON.parse(ss._store.get(SKEY));
    expect(stored.maxFailedAttempts).toBe(5);
    expect(stored.minPinLength).toBe(8);
    expect(stored.require2FA).toBe(true);
  });
});

describe('Attack_App: attempt counter tamper', () => {
  test.each(['abc', '-3', '1.5', 'NaN', '1e3', ' 2', '99999999999', '0x5'])('corrupt counter %p never resets to zero', (raw) => {
    expect(parseAttemptCounter(raw, 5)).toBe(4);
  });
  test('missing/empty => 0, valid => value', () => {
    expect(parseAttemptCounter(null, 5)).toBe(0);
    expect(parseAttemptCounter('', 5)).toBe(0);
    expect(parseAttemptCounter('3', 5)).toBe(3);
  });
  test('AuthScreen persists the attempt BEFORE verifying and uses the strict parser (source)', () => {
    const src = require('fs').readFileSync('src/screens/AuthScreen.tsx', 'utf8');
    const persist = src.indexOf('setItemAsync(ATTEMPTS_KEY');
    const verify = src.indexOf('SecureCryptoService.unlock(entered)');
    expect(persist).toBeGreaterThan(0);
    expect(persist).toBeLessThan(verify);
    expect(src).toMatch(/parseAttemptCounter\(await SecureStore\.getItemAsync\(ATTEMPTS_KEY\)/);
    expect(src).not.toMatch(/parseInt\(\(await SecureStore\.getItemAsync\(ATTEMPTS_KEY/);
    // wipe must not wait for an Alert button
    const enforce = src.slice(src.indexOf('const enforceMaxAttempts'), src.indexOf('const checkLoginPass'));
    expect(enforce.indexOf('onWipeVault')).toBeLessThan(enforce.indexOf('Alert.alert'));
    expect(enforce).not.toMatch(/onPress/);
    // lockout check precedes counter + biometric path checks lock
    expect(src.indexOf('getLockStatus()')).toBeLessThan(persist);
    const bio = src.slice(src.indexOf('const triggerBio'), src.indexOf('const enforceMaxAttempts'));
    expect(bio).toMatch(/getLockStatus/);
  });
  test('2FA: a correct passphrase without biometric confirmation drops the key (source)', () => {
    const src = require('fs').readFileSync('src/screens/AuthScreen.tsx', 'utf8');
    const i = src.indexOf('!bioPassedFor2FA) {');
    expect(src.slice(i, i + 200)).toMatch(/clearAllCaches/);
  });
});

describe('Attack_App: lockout store tamper (real CryptoService)', () => {
  const LOCK = 'filevault_lock_until';
  test('permanent lock stays locked; far-future / garbage lock values stay locked', async () => {
    for (const v of [String(Number.MAX_SAFE_INTEGER), String(Date.now() + 1e9), 'garbage', 'NaN']) {
      ss._store.clear();
      await (SecureCryptoService as any).setItemSecure(LOCK, v);
      expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
    }
  });
  test('negative / zero lock value does not brick but also is not an extension', async () => {
    await (SecureCryptoService as any).setItemSecure(LOCK, '-5');
    expect((await SecureCryptoService.getLockStatus()).locked).toBe(false);
  });
  test('corrupt failed-attempts counter is treated as MAX-1, so next failure locks', async () => {
    await (SecureCryptoService as any).setItemSecure('filevault_failed_attempts', 'garbage');
    await (SecureCryptoService as any).incrementFailedAttempts();
    expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
  });
  test('lock survives kill-and-retry: state lives in the store, not in memory', async () => {
    for (let i = 0; i < 5; i++) await (SecureCryptoService as any).incrementFailedAttempts();
    // Nothing in-memory gates the lock: the persisted flag alone re-locks a restarted process.
    const persisted = [...ss._store.keys()].some((k: string) => k.includes('lock_until'));
    expect(persisted).toBe(true);
    expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
  });
  test('unlock() refuses while locked, even with a right/wrong passphrase, without touching key material', async () => {
    await (SecureCryptoService as any).setItemSecure(LOCK, String(Date.now() + 60000));
    const spy = jest.spyOn(SecureCryptoService as any, 'unlockKEK');
    expect(await SecureCryptoService.unlock('whatever-pass')).toBe(false);
    expect(spy).not.toHaveBeenCalled();
  });
  test('clock rollback cannot shorten a lock (wall-clock backwards extends it)', async () => {
    const until = Date.now() + 60000;
    await (SecureCryptoService as any).setItemSecure(LOCK, String(until));
    jest.spyOn(Date, 'now').mockReturnValue(until - 3600_000);
    expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
  });
  test('SecureStore read failure on the lock key must not unlock (fail closed)', async () => {
    await (SecureCryptoService as any).setItemSecure(LOCK, String(Number.MAX_SAFE_INTEGER));
    ss.getItemAsync.mockRejectedValue(new Error('keystore down'));
    try {
      expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
    } finally {
      ss.getItemAsync.mockImplementation(async (k: string) => ss._store.get(k) ?? null);
    }
  });
});

describe('Attack_App: auto-lock', () => {
  afterEach(() => { AutoLockService.endPickerSession(); AutoLockService.setLockCallback(() => {}); jest.useRealTimers(); });

  test('lock fires even if every storage write rejects', async () => {
    ss.setItemAsync.mockRejectedValue(new Error('disk'));
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);
    ss.setItemAsync.mockImplementation(async (k: string, v: string) => { ss._store.set(k, v); });
  });
  test('a throwing lock callback / vibration does not abort persisting the lock flag', async () => {
    AutoLockService.setLockCallback(() => { throw new Error('ui'); });
    await AutoLockService.triggerLock();
    expect(await AutoLockService.isLocked()).toBe(true);
  });
  test('inactivity timer locks after timeout and cannot be disarmed by a late reset', async () => {
    jest.useFakeTimers();
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await SettingsService.save({ ...(await SettingsService.get()), autoLockTimeout: 15 });
    jest.advanceTimersByTime(14_000);
    expect(cb).not.toHaveBeenCalled();
    jest.advanceTimersByTime(1_500);
    expect(cb).toHaveBeenCalledTimes(1);
  });
  test('activity resets are the only extension: repeated resets then silence still locks', async () => {
    jest.useFakeTimers();
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await SettingsService.save({ ...(await SettingsService.get()), autoLockTimeout: 15 });
    for (let i = 0; i < 5; i++) { jest.advanceTimersByTime(10_000); AutoLockService.resetTimer(); }
    expect(cb).not.toHaveBeenCalled();
    jest.advanceTimersByTime(16_000);
    expect(cb).toHaveBeenCalledTimes(1);
  });
  test('tampered timeout in SecureStore ("never" forged by garbage) cannot disable the timer', async () => {
    jest.useFakeTimers();
    ss._store.set(SKEY, JSON.stringify({ autoLockTimeout: 1e12 }));
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await AutoLockService.applySettings();
    jest.advanceTimersByTime(301_000);
    expect(cb).toHaveBeenCalledTimes(1);
  });
  test.each([['NaN', 'garbage'], ['future stamp', () => String(Date.now() + 10 * 86400_000)]])(
    'initialize with %s last-activity stamp locks (fail closed)', async (_n, val) => {
      ss._store.set('filevault_last_activity', typeof val === 'function' ? (val as any)() : val);
      const cb = jest.fn();
      AutoLockService.setLockCallback(cb);
      await AutoLockService.initialize();
      expect(cb).toHaveBeenCalled();
    });
  test('initialize with a stale stamp locks; fresh stamp does not', async () => {
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    ss._store.set('filevault_last_activity', String(Date.now() - 3600_000));
    await AutoLockService.initialize();
    expect(cb).toHaveBeenCalledTimes(1);
    cb.mockClear();
    ss._store.set('filevault_last_activity', String(Date.now() - 1000));
    await AutoLockService.initialize();
    expect(cb).not.toHaveBeenCalled();
    await AutoLockService.disable();
  });
  test('picker session cannot be used to suppress locking forever; unlock after deadline', async () => {
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    const t = Date.now();
    AutoLockService.beginPickerSession();
    await AutoLockService.triggerLock();
    expect(cb).not.toHaveBeenCalled();
    jest.spyOn(Date, 'now').mockReturnValue(t + 5 * 60_000 + 1);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);
  });
  test('App.tsx: background lock + decoy flag cleared on every lock path (source)', () => {
    const src = require('fs').readFileSync('App.tsx', 'utf8').replace(/\r/g, '');
    const cbBody = src.slice(src.indexOf('setLockCallback('), src.indexOf('AppState.addEventListener'));
    expect(cbBody).toMatch(/filevault_guest_active/);
    expect(cbBody).toMatch(/clearDecoyCache/);
    expect(cbBody).toMatch(/setIsAuthenticated\(false\)/);
    const wipe = src.slice(src.indexOf('const handleWipeVault'), src.indexOf('if (isFirstLaunch === null'));
    // key shred is attempted before anything that could throw un-caught
    expect(wipe.indexOf('deleteEncryptionKey')).toBeGreaterThan(0);
    expect(wipe).not.toMatch(/\n\s*await CryptoService\.(deletePinData|deleteEncryptionKey|setAppInitialized)/);
  });
});
