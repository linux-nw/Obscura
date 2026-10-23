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
import { NativeModules } from 'react-native';
import { verifyPinnedSignature, type SignatureVerdict } from '../native/IntegrityNative';

export interface IntegrityStatus {
  isIntact: boolean;
  lastCheck: number;
  checksPassed: number;
  checksFailed: number;
}

export class IntegrityService {
  private static readonly STORAGE_INTEGRITY_RESULT = 'filevault_integrity_result';
  private static readonly STORAGE_LAST_CHECK = 'filevault_last_integrity_check';
  private static readonly INTEGRITY_ENABLED_KEY = 'filevault_integrity_enabled';

  /**
   * L7: real APK signing-cert verdict against the build-time-pinned hash.
   *   'valid'        cert matches the compiled-in SIGNING_CERT_SHA256
   *   'invalid'      cert present but mismatched (repackaged / re-signed)
   *   'unverifiable' native module absent, or the build pinned no hash (debug)
   * Only 'invalid' is a positive tamper signal — see checkSignature().
   */
  static async verifyAppSignature(): Promise<SignatureVerdict> {
    return verifyPinnedSignature();
  }

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
   * Prüft die APK Signature (Android) gegen den einkompilierten Pin.
   *
   * Fail-closed, aber NICHT überreagierend: nur ein 'invalid'-Verdikt (App wurde
   * neu gepackt/signiert) lässt den Check durchfallen. 'unverifiable' (Native-Modul
   * fehlt, oder Debug-Build ohne Pin) lässt ihn bestehen — wir können kein Tampering
   * beweisen, und ein False Positive darf einen legitimen Nutzer nie aussperren.
   */
  private static async checkSignature(): Promise<boolean> {
    try {
      const verdict = await this.verifyAppSignature();
      if (verdict === 'invalid') {
        return false;
      }
      return true;
    } catch (error) {
      console.error('Integrity: Signature check failed:', error);
      return false;
    }
  }

  /** Root indicators (su binary / root-manager packages) via the native DeviceSecurity module. */
  private static async checkAppFiles(): Promise<boolean> {
    try {
      const ds = (NativeModules as any).DeviceSecurity;
      if (!ds) return true;
      const su = ds.checkSuBinary ? await ds.checkSuBinary() : false;
      const pkg = ds.checkRootKeysInPackage ? await ds.checkRootKeysInPackage() : false;
      return !(su || pkg);
    } catch {
      return true;
    }
  }

  /** Attached debugger / TracerPid via the native IntegrityNative module. Absent module = pass. */
  private static async checkDebugger(): Promise<boolean> {
    try {
      const n = (NativeModules as any).IntegrityNative;
      if (!n?.checkDebugger) return true;
      return !(await n.checkDebugger());
    } catch {
      return true;
    }
  }

  /** Frida artefacts via the native DeviceSecurity module. Absent module = pass. */
  private static async checkIntegrityService(): Promise<boolean> {
    try {
      const ds = (NativeModules as any).DeviceSecurity;
      if (!ds?.checkFridaModules) return true;
      const found = await ds.checkFridaModules();
      return !(Array.isArray(found) && found.length > 0);
    } catch {
      return true;
    }
  }

  // ─────────────────────────────── Compromise State ───────────────────────────────

  /**
   * Prüft ob App bereits kompromittiert wurde
   */
  static async wasCompromised(): Promise<boolean> {
    try {
      const result = await SecureStore.getItemAsync(this.STORAGE_INTEGRITY_RESULT);
      if (!result) return false;

      const data = JSON.parse(result);
      // Only an explicit boolean true counts as intact; forged/odd shapes read as compromised.
      return !(data && typeof data === 'object' && data.isIntact === true);
    } catch {
      return true; // a present-but-unparseable record is tampering, not "never checked"
    }
  }

  /**
   * Führt Tamper Response aus
   */
  static async triggerTamperResponse(): Promise<void> {
    // Permanent lock FIRST, then each destructive step independently: one throwing step must
    // never leave the vault unlocked or skip the key shred.
    try { await SecureStore.setItemAsync('filevault_lock_until', String(Number.MAX_SAFE_INTEGER)); } catch {}
    let CS: any;
    try {
      // Lazy import: CryptoService owns the real key/lock storage names.
      CS = require('./CryptoService').SecureCryptoService;
    } catch { return; }
    try { CS.clearAllCaches(); } catch {}
    try { await CS.deleteEncryptionKey(); } catch {}
    try { await CS.deletePinData(); } catch {}
    // deletePinData clears the lock flag; re-assert it.
    try { await SecureStore.setItemAsync('filevault_lock_until', String(Number.MAX_SAFE_INTEGER)); } catch {}
    try { await CS.setAppInitialized(false); } catch {}
  }

  // ─────────────────────────────── Settings ───────────────────────────────

  /**
   * Aktiviert Integrity Check
   */
  static async enableIntegrityCheck(): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.INTEGRITY_ENABLED_KEY, 'true');
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
      return value !== 'false';
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
        isIntact: data.isIntact === true,
        lastCheck: typeof data.timestamp === 'number' ? data.timestamp : 0,
      };
    } catch {
      return { isIntact: false, lastCheck: 0 };
    }
  }
}

export default IntegrityService;
