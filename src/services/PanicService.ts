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
import { fastPbkdf2 } from './FastPBKDF2';
import { Argon2idService, Argon2Params } from './Argon2idService';

export interface PanicSettings {
  panicPinHash: string | null;
  panicPinSalt: string | null;
  triggerAction: 'wipe' | 'lock';
  failedAttempts: number;
  maxFailedAttempts: number;
}

export class PanicService {
  private static readonly STORAGE_PANIC_PIN_HASH = 'filevault_panic_pin_hash';
  private static readonly STORAGE_PANIC_PIN_SALT = 'filevault_panic_pin_salt';
  // S1: marks which KDF produced the stored hash. 'argon2id' = current; absent = legacy
  // PBKDF2-10k (migrated to Argon2id on the next successful verify).
  private static readonly STORAGE_PANIC_PIN_ALGO = 'filevault_panic_pin_algo';
  private static readonly STORAGE_PANIC_SETTINGS = 'filevault_panic_settings';
  private static readonly STORAGE_PANIC_FAILED_ATTEMPTS = 'filevault_panic_failed_attempts';

  private static readonly MAX_FAILED_ATTEMPTS = 3;

  // S1: Panic PIN is now stretched with Argon2id (memory-hard, same hardness class as the
  // vault KEK), NOT PBKDF2-10k. p=1 matches native libsodium crypto_pwhash (C1); 16-byte
  // salt (crypto_pwhash_SALTBYTES). Native path is used when available, else @noble/hashes
  // argon2id (documented JS fallback) — there is NO silent PBKDF2 downgrade.
  private static readonly PANIC_ARGON2: Argon2Params = {
    version: 0x13, type: 2, memoryKB: 65536, iterations: 3, parallelism: 1, hashLength: 32,
  };
  // Legacy iteration count — only used to VERIFY (and then migrate away) pre-S1 hashes.
  private static readonly LEGACY_PBKDF2_ITERATIONS = 10000;

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
      // S1: Argon2id-stretched, same as the vault passphrase hardness class.
      const { hash, salt } = await this.computePinHash(pin);

      await SecureStore.setItemAsync(this.STORAGE_PANIC_PIN_HASH, hash);
      await SecureStore.setItemAsync(this.STORAGE_PANIC_PIN_SALT, salt);
      await SecureStore.setItemAsync(this.STORAGE_PANIC_PIN_ALGO, 'argon2id');

      console.log('Panic: Panic PIN set (Argon2id)');
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
   * Verifiziert die Panic PIN mit konstantem Zeitverhalten.
   * Gibt false zurück wenn keine Panic PIN gesetzt ist (kein early-return-Timing-Leak
   * gegenüber dem Caller — der Caller (AuthScreen) läuft beide Checks immer).
   */
  static async verifyPanicPin(pin: string): Promise<boolean> {
    try {
      const storedHash = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_HASH);
      const storedSalt = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_SALT);

      if (!storedHash || !storedSalt) {
        return false;
      }

      const algo = await SecureStore.getItemAsync(this.STORAGE_PANIC_PIN_ALGO);

      if (algo === 'argon2id') {
        const { hash } = await this.computePinHash(pin, storedSalt);
        // sodium_memcmp via native, JS constant-time XOR as fallback (R-01).
        return await SecureCryptoService.constantsTimeEquals(hash, storedHash);
      }

      // S1 migration: a hash without the 'argon2id' marker is a legacy PBKDF2-10k hash.
      // Verify it the old way; on success, transparently re-hash with Argon2id (fresh
      // salt) so the weak hash is replaced. The user is never locked out.
      const legacyHash = await this.computePinHashLegacy(pin, storedSalt);
      const match = await SecureCryptoService.constantsTimeEquals(legacyHash, storedHash);
      if (match) {
        try {
          await this.setPanicPin(pin);
        } catch {
          // Keep the legacy hash if the migration write fails — verification still worked.
        }
      }
      return match;
    } catch (error) {
      console.error('Panic: PIN verification error:', error);
      return false;
    }
  }

  /**
   * Berechnet Panic PIN Hash via Argon2id (S1).
   * Memory-hard (m=64 MiB, t=3, p=1) — native libsodium crypto_pwhash bevorzugt,
   * sonst @noble/hashes argon2id. KEIN stiller PBKDF2-Downgrade.
   */
  private static async computePinHash(
    pin: string,
    salt?: string
  ): Promise<{ hash: string; salt: string }> {
    if (!salt) {
      salt = await this.generateSalt(); // 16-byte hex (crypto_pwhash_SALTBYTES)
    }
    const saltBuffer = SecureCryptoService.hexToBuffer(salt);
    const derived = await Argon2idService.deriveKey(pin.normalize('NFC'), saltBuffer, this.PANIC_ARGON2);
    return { hash: SecureCryptoService.bufferToHex(derived), salt };
  }

  /**
   * Legacy-Verifikationspfad: berechnet den alten PBKDF2-10k-Hash, NUR um pre-S1-Hashes
   * zu prüfen und anschließend zu migrieren. Wird nie mehr zum Speichern verwendet.
   */
  private static async computePinHashLegacy(pin: string, salt: string): Promise<string> {
    return fastPbkdf2(pin.normalize('NFC'), salt, this.LEGACY_PBKDF2_ITERATIONS, 32);
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

      // triggerAction ist auf 'wipe' | 'lock' eingeengt; loadSettings() coerced
      // gespeicherte Legacy-Werte ('decoy'/'all') beim Laden auf 'lock'. Der Decoy-Vault
      // wird über die Decoy-PIN beim Entsperren aktiviert, nicht über die Panic-Aktion.
      switch (settings.triggerAction) {
        case 'wipe':
          await this.wipeAllData();
          break;
        case 'lock':
          await this.lockAppPermanently();
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

      await SecureStore.setItemAsync('filevault_lock_until', String(Number.MAX_SAFE_INTEGER));

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
        const parsed = JSON.parse(value);
        // Coerce legacy actions ('decoy', 'all') to 'lock'
        if (parsed.triggerAction !== 'wipe' && parsed.triggerAction !== 'lock') {
          parsed.triggerAction = 'lock';
        }
        return parsed;
      }
      return {
        panicPinHash: null,
        panicPinSalt: null,
        triggerAction: 'lock' as const,
        failedAttempts: 0,
        maxFailedAttempts: this.MAX_FAILED_ATTEMPTS,
      };
    } catch {
      return {
        panicPinHash: null,
        panicPinSalt: null,
        triggerAction: 'lock' as const,
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
  static async setTriggerAction(action: 'wipe' | 'lock'): Promise<void> {
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
   * Gibt die aktuell konfigurierte Trigger-Aktion zurück.
   */
  static async getTriggerAction(): Promise<'wipe' | 'lock'> {
    const s = await this.loadSettings();
    return s.triggerAction;
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
      await SecureStore.deleteItemAsync(this.STORAGE_PANIC_PIN_ALGO);
      console.log('Panic: Panic PIN cleared');
    } catch (error) {
      console.error('Error clearing panic pin:', error);
    }
  }
}

export default PanicService;
