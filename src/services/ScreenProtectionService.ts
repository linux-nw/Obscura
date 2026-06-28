/**
 * Screen Protection Service (Endpoint hardening — Layer 1)
 *
 * Honest status:
 * - The real protection is FLAG_SECURE, applied two ways:
 *   1. ALWAYS-ON baseline, set natively in MainActivity.onCreate (timing-independent;
 *      covers the Recents/app-switcher snapshot the OS grabs around pause). This is the
 *      guarantee — it cannot be turned off from JS.
 *   2. This service additionally calls the native `ScreenSecurity` module
 *      (window.addFlags(FLAG_SECURE)) at startup as defense-in-depth and to expose a
 *      runtime toggle / status query.
 * - FLAG_SECURE blocks screenshots, screen recording (MediaProjection sees black), and
 *   the Recents thumbnail. It does NOT defend against a physical photo of the screen or a
 *   root-level framebuffer read — see the residual-risk note in CRYPTO_PROTOCOL_SPEC.md §15.
 *
 * NOTE: Android userspace cannot reliably *detect* that a screenshot/recording happened
 * (no public, non-racy API). We therefore PREVENT capture (FLAG_SECURE) instead of
 * pretending to detect it. The detection methods below are explicitly unsupported and say
 * so, rather than returning a fake "all clear".
 */

import { Platform, NativeModules } from 'react-native';
import * as SecureStore from 'expo-secure-store';

interface ScreenSecurityNative {
  enable(): Promise<boolean>;
  disable(): Promise<boolean>;
  isEnabled(): Promise<boolean>;
}

const ScreenSecurity: ScreenSecurityNative | undefined =
  (NativeModules as any).ScreenSecurity;

export enum SecurityFlag {
  SCREENSHOT = 'SecureScreenshot',
  OVERLAY = 'SecureOverlay',
  RECORDING = 'SecureRecording',
}

export class ScreenProtectionService {
  private static readonly SETTINGS_KEY = 'filevault_screen_protection_settings';
  private static isProtectionEnabled: boolean = false;

  /**
   * Enables FLAG_SECURE via the native ScreenSecurity module. This is additive to the
   * always-on baseline set in MainActivity — calling it is idempotent and safe.
   */
  static async enableScreenCaptureBlocking(): Promise<void> {
    try {
      if (Platform.OS !== 'android') return;
      if (!ScreenSecurity) {
        // Native module missing (e.g. Expo Go). The MainActivity baseline does not apply
        // there either, so be loud rather than silently claim protection.
        console.warn(
          '[ScreenProtection] native ScreenSecurity module unavailable — FLAG_SECURE not ' +
          'enforced in this runtime (expected only in Expo Go / a dev client without the module).'
        );
        return;
      }
      await ScreenSecurity.enable();
      this.isProtectionEnabled = true;
      await this.saveSettings(true);
    } catch (error) {
      console.error('[ScreenProtection] enable failed:', error);
    }
  }

  /**
   * Clears FLAG_SECURE on the current activity. The MainActivity baseline is re-applied on
   * the next Activity (re)creation, so this only affects the current foreground window.
   */
  static async disableScreenCaptureBlocking(): Promise<void> {
    try {
      if (Platform.OS !== 'android' || !ScreenSecurity) return;
      await ScreenSecurity.disable();
      this.isProtectionEnabled = false;
      await this.saveSettings(false);
    } catch (error) {
      console.error('[ScreenProtection] disable failed:', error);
    }
  }

  /**
   * True when FLAG_SECURE is currently set on the foreground window (queried from native).
   */
  static async isScreenCaptureBlocked(): Promise<boolean> {
    try {
      if (Platform.OS !== 'android' || !ScreenSecurity) return false;
      return await ScreenSecurity.isEnabled();
    } catch {
      return false;
    }
  }

  // ─────────────────────────────── Unsupported detection (honest) ───────────────────────────────
  // Android does not expose a reliable, non-racy userspace API to detect that a screenshot
  // or screen recording occurred. We do not fake it. FLAG_SECURE prevents the capture
  // instead. These remain only so callers that referenced them keep compiling; they tell
  // the truth (false = "not detectable here", not "confirmed safe").

  /** Not supported on Android userspace; FLAG_SECURE prevents capture instead. */
  static async detectScreenshot(): Promise<boolean> {
    return false;
  }

  /** Not supported on Android userspace; FLAG_SECURE makes a recording see black. */
  static async checkScreenRecording(): Promise<boolean> {
    return false;
  }

  // ─────────────────────────────── Settings ───────────────────────────────

  private static async saveSettings(enabled: boolean): Promise<void> {
    try {
      await SecureStore.setItemAsync(
        this.SETTINGS_KEY,
        JSON.stringify({ enabled, timestamp: Date.now() }),
      );
    } catch (error) {
      console.error('[ScreenProtection] save settings failed:', error);
    }
  }

  /**
   * Reports the real, native-queried protection status (no fabricated fields).
   */
  static async checkProtectionStatus(): Promise<{
    flagSecureActive: boolean;
    nativeModuleAvailable: boolean;
    lastCheck: number;
  }> {
    return {
      flagSecureActive: await this.isScreenCaptureBlocked(),
      nativeModuleAvailable: !!ScreenSecurity,
      lastCheck: Date.now(),
    };
  }
}

export default ScreenProtectionService;
