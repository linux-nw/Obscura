/**
 * Integrity Service
 * APK/AAB Integrity Prüfung und Anti-Tamper
 *
 * Sicherheitsmerkmale:
 * - APK Signature Verification
 * - File Integrity Check
 * - Debugger Detection
 * - Self-Integrity Check
 */

import * as SecureStore from 'expo-secure-store';

export interface IntegrityStatus {
  isIntact: boolean;
  lastCheck: number;
  checksPassed: number;
  checksFailed: number;
}

export class IntegrityService {
  private static readonly STORAGE_INTEGRITY_RESULT = 'filevault_integrity_result';
  private static readonly STORAGE_LAST_CHECK = 'filevault_last_integrity_check';
  private static readonly STORAGE_APP_HASH = 'filevault_app_hash';
  private static readonly INTEGRITY_ENABLED_KEY = 'filevault_integrity_enabled';

  /**
   * Prüft die App Integrität
   */
  static async checkIntegrity(): Promise<IntegrityStatus> {
    try {
      const results = await Promise.all([
        this.checkSignature(),
        this.checkAppFiles(),
        this.checkDebugger(),
        this.checkIntegrityService(),
      ]);

      const passed = results.filter((r) => r).length;
      const failed = results.length - passed;

      const isIntact = failed === 0;

      // Ergebnisse speichern
      await SecureStore.setItemAsync(
        this.STORAGE_INTEGRITY_RESULT,
        JSON.stringify({ isIntact, timestamp: Date.now() })
      );
      await SecureStore.setItemAsync(this.STORAGE_LAST_CHECK, Date.now().toString());

      console.log(`Integrity: Check complete - Passed: ${passed}/${results.length}`);

      return {
        isIntact,
        lastCheck: Date.now(),
        checksPassed: passed,
        checksFailed: failed,
      };
    } catch (error) {
      console.error('Integrity: Check failed:', error);
      return {
        isIntact: false,
        lastCheck: 0,
        checksPassed: 0,
        checksFailed: 1,
      };
    }
  }

  // ─────────────────────────────── Check Methods ───────────────────────────────

  /**
   * Prüft die APK Signature (Android)
   */
  private static async checkSignature(): Promise<boolean> {
    try {
      // In Produktion: Native Module für PackageInfo
      // Android: getPackageInfo(PACKAGE_NAME_GET_SIGNATURES)
      // iOS: Code signature check via native

      // Fallback: Simulierter Check
      const expectedSignature = await SecureStore.getItemAsync(this.STORAGE_APP_HASH);
      if (!expectedSignature) {
        // Erster Start - Hash speichern
        await this.storeAppHash();
        return true;
      }

      // In Produktion: echte Prüfung
      return true; // Platzhalter
    } catch (error) {
      console.error('Integrity: Signature check failed:', error);
      return false;
    }
  }

  /**
   * Prüft auf Datei-Integrität
   */
  private static async checkAppFiles(): Promise<boolean> {
    try {
      // In Produktion: Prüfung auf verdächtige Dateien
      // - /system/bin/su
      // - /system/xbin/su
      // - /system/app/Superuser.apk
      // - /system/bin/.ext/
      // - /system/bin/sucu

      // Fallback
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Prüft ob Debugger angehängt ist
   */
  private static async checkDebugger(): Promise<boolean> {
    try {
      // In Produktion: native Module für
      // - Android: ActivityManager.isRunningInUserSpace()
      // - Android: /proc/self/status TracerPid
      // - iOS: ptrace(PT_DENY_ATTACH)

      // Fallback
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Prüft die Integritätsdienste
   */
  private static async checkIntegrityService(): Promise<boolean> {
    try {
      // Prüft ob Integritätsdienste noch existieren
      // - DeviceSecurityService
      // - ScreenProtectionService
      // - MemorySafetyService

      return true; // Platzhalter
    } catch {
      return false;
    }
  }

  // ─────────────────────────────── App Hash Management ───────────────────────────────

  /**
   * Speichert den App Hash (Signatur)
   */
  private static async storeAppHash(): Promise<void> {
    try {
      // In Produktion: echte App Hash Berechnung
      // - Android: Signature bytes
      // - iOS: Mach-O header hash
      const appHash = 'expected_app_hash_placeholder';

      await SecureStore.setItemAsync(this.STORAGE_APP_HASH, appHash);
    } catch (error) {
      console.error('Integrity: Failed to store app hash:', error);
    }
  }

  /**
   * Prüft ob App bereits kompromittiert wurde
   */
  static async wasCompromised(): Promise<boolean> {
    try {
      const result = await SecureStore.getItemAsync(this.STORAGE_INTEGRITY_RESULT);
      if (!result) return false;

      const data = JSON.parse(result);
      return !data.isIntact;
    } catch {
      return false;
    }
  }

  /**
   * Führt Tamper Response aus
   */
  static async triggerTamperResponse(): Promise<void> {
    try {
      console.warn('SECURITY: App integrity compromised! Triggering response...');

      // 1. Sensitive Daten löschen
      await SecureStore.deleteItemAsync('filevault_encryption_key');
      await SecureStore.deleteItemAsync('filevault_pin_hash');
      await SecureStore.deleteItemAsync('filevault_pin_salt');
      await SecureStore.deleteItemAsync('filevault_pin_iv');
      await SecureStore.deleteItemAsync('filevault_pin_key');

      // 2. App sperren
      const lockUntil = Date.now() + 365 * 24 * 60 * 60 * 1000; // 1 Jahr
      await SecureStore.setItemAsync('filevault_lock_until', lockUntil.toString());

      // 3. App als nicht initialisiert markieren
      await SecureStore.setItemAsync('filevault_app_initialized', 'false');

      console.log('SECURITY: Tamper response complete');
    } catch (error) {
      console.error('Security: Tamper response failed:', error);
    }
  }

  // ─────────────────────────────── Settings ───────────────────────────────

  /**
   * Aktiviert Integrity Check
   */
  static async enableIntegrityCheck(): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.INTEGRITY_ENABLED_KEY, 'true');
      console.log('Integrity: Check enabled');
    } catch (error) {
      console.error('Error enabling integrity check:', error);
    }
  }

  /**
   * Deaktiviert Integrity Check
   */
  static async disableIntegrityCheck(): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.INTEGRITY_ENABLED_KEY, 'false');
      console.log('Integrity: Check disabled');
    } catch (error) {
      console.error('Error disabling integrity check:', error);
    }
  }

  /**
   * Prüft ob Integrity Check aktiv ist
   */
  static async isIntegrityCheckEnabled(): Promise<boolean> {
    try {
      const value = await SecureStore.getItemAsync(this.INTEGRITY_ENABLED_KEY);
      return value === 'true';
    } catch {
      return true; // Default: enabled
    }
  }

  /**
   * Prüft ob bald erneut geprüft werden sollte
   */
  static async needsRecheck(): Promise<boolean> {
    try {
      const lastCheck = await SecureStore.getItemAsync(this.STORAGE_LAST_CHECK);
      if (!lastCheck) return true;

      const lastCheckTime = parseInt(lastCheck, 10);
      const oneDay = 24 * 60 * 60 * 1000; // 1 Tag

      return Date.now() - lastCheckTime > oneDay;
    } catch {
      return true;
    }
  }

  /**
   * Gibt den letzten Check Status zurück
   */
  static async getLastCheckStatus(): Promise<{
    isIntact: boolean;
    lastCheck: number;
  }> {
    try {
      const result = await SecureStore.getItemAsync(this.STORAGE_INTEGRITY_RESULT);
      if (!result) {
        return { isIntact: false, lastCheck: 0 };
      }

      const data = JSON.parse(result);
      return {
        isIntact: data.isIntact || false,
        lastCheck: data.timestamp || 0,
      };
    } catch {
      return { isIntact: false, lastCheck: 0 };
    }
  }
}

export default IntegrityService;
