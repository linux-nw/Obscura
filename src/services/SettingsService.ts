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

const ALLOWED_TIMEOUTS = [-1, 0, 15, 30, 60, 300, 600, 900, 1800];

/** Clamp every field to a known-good value so a tampered/corrupt store cannot weaken protections. */
export function sanitizeSettings(raw: unknown): AppSettings {
  const src = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  // Own properties only: an inherited (polluted) Object.prototype value must never be honoured.
  const r: Record<string, unknown> = Object.create(null);
  for (const k of ['biometricsEnabled', 'bioAutoTrigger', 'require2FA', 'autoLockTimeout', 'maxFailedAttempts', 'maxFailedAttemptsAction']) {
    if (Object.prototype.hasOwnProperty.call(src, k)) r[k] = src[k];
  }
  const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
  const t = r.autoLockTimeout;
  const m = r.maxFailedAttempts;
  return {
    biometricsEnabled: bool(r.biometricsEnabled, defaults.biometricsEnabled),
    bioAutoTrigger: bool(r.bioAutoTrigger, defaults.bioAutoTrigger),
    require2FA: bool(r.require2FA, defaults.require2FA),
    autoLockTimeout: typeof t === 'number' && ALLOWED_TIMEOUTS.includes(t) ? t : defaults.autoLockTimeout,
    maxFailedAttempts:
      typeof m === 'number' && Number.isInteger(m) && m >= 3 && m <= 10 ? m : defaults.maxFailedAttempts,
    maxFailedAttemptsAction: r.maxFailedAttemptsAction === 'lock' ? 'lock' : 'wipe',
    minPinLength: defaults.minPinLength,
  };
}

export class SettingsService {
  /**
   * SecureStore only (Keystore-bound). The former plaintext AsyncStorage mirror let anyone
   * with file access edit settings whenever the SecureStore entry was absent; it is purged.
   */
  static async get(): Promise<AppSettings> {
    try {
      const raw = await SecureStore.getItemAsync(STORAGE_KEY);
      if (raw) return sanitizeSettings(JSON.parse(raw));
    } catch {}
    AsyncStorage.removeItem(STORAGE_KEY).catch(() => {});
    return { ...defaults };
  }

  static async save(settings: AppSettings): Promise<void> {
    const clean = sanitizeSettings(settings);
    await SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(clean));
    AsyncStorage.removeItem(STORAGE_KEY).catch(() => {});
    try {
      const { AutoLockService } = require('./AutoLockService');
      await AutoLockService.applySettings();
    } catch {}
  }
}
