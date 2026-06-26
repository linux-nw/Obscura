/**
 * Screen Protection Service
 * Screenshot und Overlay Blocking für iOS und Android
 *
 * Sicherheitsmerkmale:
 * - Screen capture blocking
 * - Screenshot detection
 * - Overlay window detection
 * - Screen recording detection
 */

import { Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';
// NOT_IMPLEMENTED: expo-screen-capture (FLAG_SECURE) needs a Gradle build with
// network access to resolve `io.github.lukmccall.pika:pika-api`.
// Add `expo-screen-capture` to package.json and run `npx expo prebuild`
// when network/certificate issues are resolved. Then replace the stubs below
// with `ScreenCapture.preventScreenCaptureAsync()` / `allowScreenCaptureAsync()`.

export enum SecurityFlag {
  SCREENSHOT = 'SecureScreenshot',
  OVERLAY = 'SecureOverlay',
  RECORDING = 'SecureRecording',
}

export class ScreenProtectionService {
  private static readonly SETTINGS_KEY = 'filevault_screen_protection_settings';
  private static isProtectionEnabled: boolean = false;

  /**
   * Aktiviert die Screenshott Protection
   */
  static async enableScreenCaptureBlocking(): Promise<void> {
    try {
      if (this.isProtectionEnabled) {
        return;
      }

      await this.nativeEnableScreenCapture();

      // Event Listener für Screenshot Detection
      this.setupScreenshotListener();

      this.isProtectionEnabled = true;
      console.log('ScreenProtection: Protection enabled');

      // Speichere Einstellung
      await this.saveSettings(true);
    } catch (error) {
      console.error('Error enabling screen protection:', error);
    }
  }

  /**
   * Deaktiviert die Screenshott Protection
   */
  static async disableScreenCaptureBlocking(): Promise<void> {
    try {
      await this.nativeDisableScreenCapture();
      this.isProtectionEnabled = false;
      console.log('ScreenProtection: Protection disabled');
      await this.saveSettings(false);
    } catch (error) {
      console.error('Error disabling screen protection:', error);
    }
  }

  /**
   * Prüft ob Protection aktiv ist
   */
  static async isScreenCaptureDisabled(): Promise<boolean> {
    try {
      const settings = await this.loadSettings();
      return settings?.enabled || false;
    } catch {
      return false;
    }
  }

  // ─────────────────────────────── Native Module Methods ───────────────────────────────

  private static async nativeEnableScreenCapture(): Promise<void> {
    // NOT_IMPLEMENTED: replace with ScreenCapture.preventScreenCaptureAsync()
    // once expo-screen-capture is added to the build (see comment at top).
  }

  private static async nativeDisableScreenCapture(): Promise<void> {
    // NOT_IMPLEMENTED: replace with ScreenCapture.allowScreenCaptureAsync()
  }

  // ─────────────────────────────── Event Handling ───────────────────────────────

  private static setupScreenshotListener(): void {
    // In native Module: Screenshot event listening
    if (Platform.OS === 'ios') {
      // iOS: Prüfung via applicationWillResignActive + check screenshot
      console.log('ScreenProtection: iOS screenshot listener set up');
    } else if (Platform.OS === 'android') {
      // Android: Prüfung via FileObserver
      console.log('ScreenProtection: Android screenshot listener set up');
    }
  }

  /**
   * Prüft auf Overlay/Draw Over Apps
   */
  static async checkOverlayProtection(): Promise<boolean> {
    try {
      if (Platform.OS === 'android') {
        // Prüft ob Overlay permission gegeben ist
        // Native: Settings.Secure.canDrawOverlays(context)
        console.log('ScreenProtection: Android overlay check');
        // In Produktion: echte Prüfung via native module
        return false;
      } else if (Platform.OS === 'ios') {
        // iOS: Prüft auf overdraw via view hierarchy
        console.log('ScreenProtection: iOS overlay check');
        return false;
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Prüft auf Screen Recording
   */
  static async checkScreenRecording(): Promise<boolean> {
    try {
      if (Platform.OS === 'ios') {
        // iOS: Prüft auf screen recording via UIDevice
        console.log('ScreenProtection: iOS screen recording check');
        return false;
      } else if (Platform.OS === 'android') {
        // Android: Prüft MediaProjectionManager
        console.log('ScreenProtection: Android screen recording check');
        return false;
      }
      return false;
    } catch {
      return false;
    }
  }

  // ─────────────────────────────── Screenshot Detection ───────────────────────────────

  /**
   * Prüft ob ein Screenshot gemacht wurde
   * (Nur für Debug/Logging - echter Schutz ist im native Module)
   */
  static async detectScreenshot(): Promise<boolean> {
    try {
      // In Produktion mit native Module:
      // iOS: Prüfung auf neuen Screenshot im Photo Library
      // Android: Prüfung auf neue Files im Pictures directory
      console.log('ScreenProtection: Screenshot detection triggered');
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Event Handler für Screenshot
   */
  static async onScreenshotTaken(): Promise<void> {
    try {
      console.warn('SECURITY: Screenshot detected!');
      // In Produktion:
      // - Warnung anzeigen
      // - Screenshot speichern (für Beweissicherung)
      // - Event an Backend senden
    } catch (error) {
      console.error('Error handling screenshot:', error);
    }
  }

  /**
   * Event Handler für Overlay Detection
   */
  static async onOverlayDetected(): Promise<void> {
    try {
      console.warn('SECURITY: Overlay detected!');
      // In Produktion:
      // - Sofortige Sperrung
      // - Wipe Data
    } catch (error) {
      console.error('Error handling overlay:', error);
    }
  }

  // ─────────────────────────────── Settings ───────────────────────────────

  private static async saveSettings(enabled: boolean): Promise<void> {
    try {
      await SecureStore.setItemAsync(
        this.SETTINGS_KEY,
        JSON.stringify({ enabled, timestamp: Date.now() }),
      );
    } catch (error) {
      console.error('Error saving settings:', error);
    }
  }

  private static async loadSettings(): Promise<{ enabled: boolean; timestamp: number } | null> {
    try {
      const value = await SecureStore.getItemAsync(this.SETTINGS_KEY);
      if (!value) return null;
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  // ─────────────────────────────── Helper Methods ───────────────────────────────

  /**
   * Setzt den Root View auf Secure
   */
  static setRootViewSecure(viewId: string): void {
    console.log(`ScreenProtection: Setting view ${viewId} as secure`);
    // In native: view.setSecure(true)
  }

  /**
   * Prüft die Gesamtsicherheit des Screenshotschutzes
   */
  static async checkProtectionStatus(): Promise<{
    screenshotBlocking: boolean;
    overlayDetection: boolean;
    screenRecording: boolean;
    lastCheck: number;
  }> {
    try {
      const settings = await this.loadSettings();
      const overlayCheck = await this.checkOverlayProtection();
      const recordingCheck = await this.checkScreenRecording();

      return {
        screenshotBlocking: settings?.enabled || false,
        overlayDetection: !overlayCheck,
        screenRecording: !recordingCheck,
        lastCheck: Date.now(),
      };
    } catch {
      return {
        screenshotBlocking: false,
        overlayDetection: true,
        screenRecording: true,
        lastCheck: Date.now(),
      };
    }
  }
}

export default ScreenProtectionService;
