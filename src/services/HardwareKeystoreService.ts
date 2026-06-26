/**
 * HardwareBackedStorage — wraps expo-secure-store with a clean CRUD interface.
 *
 * Hardware backing:
 *   - Android: expo-secure-store stores values in the hardware-backed Android
 *     Keystore (TEE; StrongBox on devices that have it) by default — no flag needed.
 *     Note: expo-secure-store does NOT expose a StrongBox/keychainServiceLevel toggle;
 *     selecting StrongBox specifically would require a custom native module.
 *   - iOS: Keychain / Secure Enclave. We pin `keychainAccessible` to
 *     WHEN_UNLOCKED_THIS_DEVICE_ONLY so items are non-exportable and never leave
 *     the device (no iCloud/backup migration).
 *
 * `requireAuthentication`:
 *   When true, expo-secure-store binds the item to a user-authentication-gated
 *   Keystore key (biometric/device PIN) — genuine TEE/StrongBox auth-gating. BUT it
 *   then prompts on EVERY read/write, so it is **opt-in per call**, never blanket.
 *   Gating routine secrets (master_enc, salts, failed-attempt counters) would force a
 *   biometric prompt on every unlock and every counter write, and would hard-break
 *   devices with no enrolled biometrics. It is therefore reserved for the biometric
 *   KEK (the one secret whose whole purpose is biometric-gated access).
 */

import * as SecureStore from 'expo-secure-store';

function baseOptions(requireAuthentication: boolean): SecureStore.SecureStoreOptions {
  return {
    // iOS hardening: device-only, only readable while unlocked. No effect on Android.
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    ...(requireAuthentication
      ? {
          requireAuthentication: true,
          authenticationPrompt: 'Tresor entsperren',
        }
      : {}),
  };
}

export class HardwareBackedStorage {
  static async getItem(key: string, requireAuthentication = false): Promise<string | null> {
    return SecureStore.getItemAsync(key, baseOptions(requireAuthentication));
  }

  static async setItem(key: string, value: string, requireAuthentication = false): Promise<void> {
    await SecureStore.setItemAsync(key, value, baseOptions(requireAuthentication));
  }

  static async deleteItem(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key);
  }

  static async exists(key: string): Promise<boolean> {
    const val = await SecureStore.getItemAsync(key, baseOptions(false));
    return val !== null;
  }

  /**
   * M3 — best-effort hardware-keystore assessment.
   *
   * expo-secure-store exposes no StrongBox/keystore-level query, so this is a
   * heuristic: biometric hardware is a strong proxy for a hardware-backed keystore on
   * modern Android (API 23+ Keystore, API 28+ StrongBox) and iOS (Secure Enclave). A
   * definitive StrongBox/TEE check would require a custom native module.
   */
  static async assessHardwareBacking(): Promise<{ likelyHardwareBacked: boolean; enrolled: boolean; reason: string }> {
    try {
      // Lazy require: keep expo-local-authentication's native-module side effects out
      // of the module-load path (it is imported transitively by CryptoService).
      const LocalAuthentication = require('expo-local-authentication');
      const hasHw = await LocalAuthentication.hasHardwareAsync();
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      if (hasHw) {
        return {
          likelyHardwareBacked: true,
          enrolled,
          reason: enrolled ? 'biometric hardware enrolled' : 'biometric hardware present, not enrolled',
        };
      }
      return { likelyHardwareBacked: false, enrolled: false, reason: 'no biometric/secure hardware detected' };
    } catch {
      return { likelyHardwareBacked: false, enrolled: false, reason: 'capability probe failed' };
    }
  }
}
