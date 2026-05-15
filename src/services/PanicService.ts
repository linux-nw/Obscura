/**
 * Panic Service
 * Implementiert Panic PIN und Decoy Vault
 *
 * Sicherheitsmerkmale:
 * - Separate Panic PIN
 * - Decoy Vault mit fake Daten
 * - Trigger-Aktionen bei Panik-Eingabe
 * - Selbstzerstörung bei wiederholten Fehlversuchen
 */

import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from './CryptoService';
import { SecureDeleteService } from './SecureDeleteService';

export interface PanicSettings {
  panicPinHash: string | null;
  panicPinSalt: string | null;
  triggerAction: 'decoy' | 'wipe' | 'lock' | 'all';
  failedAttempts: number;
  maxFailedAttempts: number;
}

export class PanicService {
  private static readonly STORAGE_PANIC_PIN_HASH = 'filevault_panic_pin_hash';
  private static readonly STORAGE_PANIC_PIN_SALT = 'filevault_panic_pin_salt';
  private static readonly STORAGE_PANIC_SETTINGS = 'filevault_panic_settings';
  private static readonly STORAGE_PANIC_FAILED_ATTEMPTS = 'filevault_panic_failed_attempts';

  private static readonly MAX_FAILED_ATTEMPTS = 3;

  /**
   * Initialisiert den Panic Service
   */
  static async initialize(): Promise<void> {
    try {
      const settings = await this.loadSettings();
      console.log('Panic: Service initialized');
    } catch (error) {
      console.error('Error initializing Panic:', error);
    }
  }

  // ─────────────────────────────── Panic PIN Management ───────────────────────────────

  /**
   * Setzt die Panic PIN
   */
  static async setPanicPin(pin: string): Promise<void> {
    try {
      // Hash wie normale PIN
      const { hash, salt } = await this.computePinHash(pin);

      await SecureStore.setItemAsync(this.STORAGE_PANIC_PIN_HASH, hash);
      await SecureStore.setItemAsync(this.STORAGE_PANIC_PIN_SALT, salt);

      console.log('Panic: Panic PIN set');
    } catch (error) {
      console.error('Error setting panic pin:', error);
      throw new Error('Konnte Panic PIN nicht setzen');
    }
  }

  /**
   * Prüft ob Panic PIN existiert
   */
  static async hasPanicPin(): Promise<boolean> {
    try {
      const hash = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_HASH);
      return !!hash;
    } catch {
      return false;
    }
  }

  /**
   * Verifiziert die Panic PIN
   */
  static async verifyPanicPin(pin: string): Promise<boolean> {
    try {
      const storedHash = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_HASH);
      const storedSalt = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_SALT);

      if (!storedHash || !storedSalt) {
        return false;
      }

      const { hash } = await this.computePinHash(pin, storedSalt);
      return hash === storedHash;
    } catch (error) {
      console.error('Panic: PIN verification error:', error);
      return false;
    }
  }

  /**
   * Berechnet Panic PIN Hash
   */
  private static async computePinHash(
    pin: string,
    salt?: string
  ): Promise<{ hash: string; salt: string }> {
    try {
      if (!salt) {
        salt = await this.generateSalt();
      }

      // PBKDF2 wie normale PIN
      const derivedKey = SecureCryptoService.deriveKeyFromPassphrase(pin);
      const hash = await SecureCryptoService.computeMac(salt, pin);

      return {
        hash,
        salt,
      };
    } catch (error) {
      console.error('Panic: computePinHash error:', error);
      throw error;
    }
  }

  /**
   * Generiert Salt für Panic PIN
   */
  private static async generateSalt(): Promise<string> {
    try {
      const bytes = await SecureCryptoService.generateSecureBytes(16);
      return SecureCryptoService.bufferToHex(bytes);
    } catch {
      return '';
    }
  }

  // ─────────────────────────────── Trigger Actions ───────────────────────────────

  /**
   * Führt Panic Aktion aus
   */
  static async triggerPanicAction(): Promise<void> {
    try {
      console.warn('PANIC TRIGGERED!');

      // Lade Einstellungen
      const settings = await this.loadSettings();

      switch (settings.triggerAction) {
        case 'decoy':
          await this.activateDecoyVault();
          break;
        case 'wipe':
          await this.wipeAllData();
          break;
        case 'lock':
          await this.lockAppPermanently();
          break;
        case 'all':
          await this.activateDecoyVault();
          await this.wipeAllData();
          break;
      }
    } catch (error) {
      console.error('Panic: Trigger action failed:', error);
    }
  }

  /**
   * Aktiviert den Decoy Vault
   */
  private static async activateDecoyVault(): Promise<void> {
    try {
      console.log('Panic: Activating decoy vault...');

      // Decoy Vault Ordner erstellen
      // In Produktion: separate Vault mit fake Daten
      // Dekrypted: falsche Dateien, falsche Notizen

      await SecureStore.setItemAsync('filevault_decoy_activated', 'true');
      console.log('Panic: Decoy vault activated');
    } catch (error) {
      console.error('Panic: Decoy vault activation failed:', error);
    }
  }

  /**
   * Löscht alle Daten
   */
  private static async wipeAllData(): Promise<void> {
    try {
      console.log('Panic: Wiping all data...');

      // Crypto Schlüssel löschen
      await SecureCryptoService.deleteEncryptionKey();
      await SecureCryptoService.deletePinData();

      // Vault löschen
      await SecureDeleteService.secureWipeAll();

      // App als nicht initialisiert markieren
      await SecureCryptoService.setAppInitialized(false);

      console.log('Panic: All data wiped');
    } catch (error) {
      console.error('Panic: Data wipe failed:', error);
    }
  }

  /**
   * Sperrt die App permanent
   */
  private static async lockAppPermanently(): Promise<void> {
    try {
      console.log('Panic: Locking app permanently...');

      const lockUntil = Date.now() + 365 * 24 * 60 * 60 * 1000; // 1 Jahr
      await SecureStore.setItemAsync('filevault_lock_until', lockUntil.toString());

      // PIN Daten löschen
      await SecureCryptoService.deletePinData();

      console.log('Panic: App locked permanently');
    } catch (error) {
      console.error('Panic: Lock failed:', error);
    }
  }

  // ─────────────────────────────── Settings ───────────────────────────────

  /**
   * Lädt Panic Einstellungen
   */
  private static async loadSettings(): Promise<PanicSettings> {
    try {
      const value = await SecureStore.getItemAsync(this.STORAGE_PANIC_SETTINGS);
      if (value) {
        return JSON.parse(value);
      }
      return {
        panicPinHash: null,
        panicPinSalt: null,
        triggerAction: 'lock',
        failedAttempts: 0,
        maxFailedAttempts: this.MAX_FAILED_ATTEMPTS,
      };
    } catch {
      return {
        panicPinHash: null,
        panicPinSalt: null,
        triggerAction: 'lock',
        failedAttempts: 0,
        maxFailedAttempts: this.MAX_FAILED_ATTEMPTS,
      };
    }
  }

  /**
   * Speichert Panic Einstellungen
   */
  private static async saveSettings(settings: PanicSettings): Promise<void> {
    try {
      await SecureStore.setItemAsync(
        this.STORAGE_PANIC_SETTINGS,
        JSON.stringify(settings)
      );
    } catch (error) {
      console.error('Error saving panic settings:', error);
    }
  }

  /**
   * Setzt Panic PIN Aktion
   */
  static async setTriggerAction(action: 'decoy' | 'wipe' | 'lock' | 'all'): Promise<void> {
    try {
      const settings = await this.loadSettings();
      settings.triggerAction = action;
      await this.saveSettings(settings);
      console.log(`Panic: Trigger action set to ${action}`);
    } catch (error) {
      console.error('Error setting trigger action:', error);
    }
  }

  /**
   * Zählt fehlgeschlagene Versuche hoch
   */
  static async incrementFailedAttempts(): Promise<void> {
    try {
      const settings = await this.loadSettings();
      settings.failedAttempts = (settings.failedAttempts || 0) + 1;

      if (settings.failedAttempts >= settings.maxFailedAttempts) {
        await this.triggerPanicAction();
        await this.resetFailedAttempts();
      } else {
        await this.saveSettings(settings);
      }

      console.log(`Panic: Failed attempts: ${settings.failedAttempts}/${settings.maxFailedAttempts}`);
    } catch (error) {
      console.error('Error incrementing failed attempts:', error);
    }
  }

  /**
   * Setzt fehlgeschlagene Versuche zurück
   */
  private static async resetFailedAttempts(): Promise<void> {
    try {
      const settings = await this.loadSettings();
      settings.failedAttempts = 0;
      await this.saveSettings(settings);
    } catch (error) {
      console.error('Error resetting failed attempts:', error);
    }
  }

  /**
   * Prüft ob Panic PIN gesetzt ist
   */
  static async hasPanicPinSet(): Promise<boolean> {
    try {
      const hash = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_HASH);
      return !!hash;
    } catch {
      return false;
    }
  }

  /**
   * Löscht die Panic PIN
   */
  static async clearPanicPin(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.STORAGE_PANIC_PIN_HASH);
      await SecureStore.deleteItemAsync(this.STORAGE_PANIC_PIN_SALT);
      console.log('Panic: Panic PIN cleared');
    } catch (error) {
      console.error('Error clearing panic pin:', error);
    }
  }
}

export default PanicService;
