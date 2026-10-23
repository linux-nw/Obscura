import AsyncStorage from '@react-native-async-storage/async-storage';
import { SettingsService, sanitizeSettings } from '../src/services/SettingsService';

const KEY = 'filevault_app_settings';

beforeEach(() => {
  require('../__mocks__/expo-secure-store')._reset();
});

describe('Sec_App: settings tamper resistance', () => {
  test('sanitize clamps hostile values to safe defaults', () => {
    const s = sanitizeSettings({
      autoLockTimeout: 99999999,
      maxFailedAttempts: 100000,
      maxFailedAttemptsAction: 'ignore',
      biometricsEnabled: 'yes',
    });
    expect(s.autoLockTimeout).toBe(300);
    expect(s.maxFailedAttempts).toBe(5);
    expect(s.maxFailedAttemptsAction).toBe('wipe');
    expect(s.biometricsEnabled).toBe(false);
  });

  test('plaintext AsyncStorage copy is never honoured', async () => {
    await AsyncStorage.setItem(KEY, JSON.stringify({ autoLockTimeout: -1, maxFailedAttempts: 10 }));
    const s = await SettingsService.get();
    expect(s.autoLockTimeout).toBe(300);
    expect(s.maxFailedAttempts).toBe(5);
  });

  test('save sanitizes and does not mirror to AsyncStorage', async () => {
    await SettingsService.save({ ...(await SettingsService.get()), maxFailedAttempts: 3, autoLockTimeout: 60 });
    const s = await SettingsService.get();
    expect(s.maxFailedAttempts).toBe(3);
    expect(s.autoLockTimeout).toBe(60);
    expect(await AsyncStorage.getItem(KEY)).toBeNull();
  });
});
