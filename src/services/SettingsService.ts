import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';

export type AutoLockTimeout = number; // seconds; -1 = never, 0 = immediate

export interface AppSettings {
  biometricsEnabled: boolean;
  bioAutoTrigger: boolean;
  require2FA: boolean;
  autoLockTimeout: AutoLockTimeout;
  maxFailedAttempts: number;
  maxFailedAttemptsAction: 'lock' | 'wipe';
  minPinLength: number;
}

const STORAGE_KEY = 'filevault_app_settings';

const defaults: AppSettings = {
  biometricsEnabled: false,
  bioAutoTrigger: false,
  require2FA: false,
  autoLockTimeout: 300,
  maxFailedAttempts: 5,
  maxFailedAttemptsAction: 'wipe',
  minPinLength: 8,
};

export class SettingsService {
  static async get(): Promise<AppSettings> {
    // Try SecureStore first (primary), fall back to AsyncStorage (secondary).
    try {
      const raw = await SecureStore.getItemAsync(STORAGE_KEY);
      if (raw) return { ...defaults, ...(JSON.parse(raw) as Partial<AppSettings>) };
    } catch {}

    try {
      const raw = await AsyncStorage.getItem(STORAGE_KEY);
      if (raw) return { ...defaults, ...(JSON.parse(raw) as Partial<AppSettings>) };
    } catch {}

    return { ...defaults };
  }

  static async save(settings: AppSettings): Promise<void> {
    const json = JSON.stringify(settings);
    const results = await Promise.allSettled([
      SecureStore.setItemAsync(STORAGE_KEY, json),
      AsyncStorage.setItem(STORAGE_KEY, json),
    ]);
    // Fail only if both stores failed.
    if (results.every(r => r.status === 'rejected')) {
      throw new Error('Einstellungen konnten nicht gespeichert werden');
    }
  }
}
