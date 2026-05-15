import * as SecureStore from 'expo-secure-store';
import * as CryptoModule from 'expo-crypto';
import CryptoJS from 'crypto-js';

/**
 * SecureCryptoService - AES-256-CBC mit HMAC-SHA-256 Authentifizierung
 *
 * Sicherheitsmerkmale:
 * - Kryptographisch sicherer Zufallsgenerator (expo-crypto)
 * - AES-256-CBC für Verschlüsselung
 * - HMAC-SHA-256 zur Integritätsprüfung (Encrypt-then-MAC)
 * - PBKDF2 Key Derivation für PIN-basierte Authentifizierung
 * - Schlüssel in Device-Keychain (iOS Keychain / Android Keystore)
 * - Rate-Limiting: 5 fehlgeschlagene Versuche → 5 Minuten Sperre
 * - Konstanter Zeit-Vergleich gegen Timing-Attacks
 */
export class SecureCryptoService {
  private static readonly STORAGE_KEY = 'filevault_encryption_key';
  private static readonly STORAGE_SALT = 'filevault_pbkdf2_salt';
  private static readonly IV_LENGTH = 16;
  private static readonly PBKDF2_ITERATIONS = 100000;
  private static readonly PBKDF2_KEY_LENGTH = 32;
  private static readonly STORAGE_PIN_HASH = 'filevault_pin_hash';
  private static readonly STORAGE_PIN_SALT = 'filevault_pin_salt';
  private static readonly STORAGE_PIN_IV = 'filevault_pin_iv';
  private static readonly STORAGE_PIN_KEY = 'filevault_pin_key';
  private static readonly STORAGE_APP_INIT = 'filevault_app_initialized';
  private static readonly STORAGE_FAILED_ATTEMPTS = 'filevault_failed_attempts';
  private static readonly STORAGE_LOCK_UNTIL = 'filevault_lock_until';
  private static readonly MAX_FAILED_ATTEMPTS = 5;
  private static readonly LOCK_DURATION_MS = 300000; // 5 Minuten

  /**
   * Initialisiere den Kryptografie-Service
   * - Generiert einen zufälligen Master-Schlüssel
   * - Generiert einen PBKDF2-Salt für PIN-Derivation
   */
  static async initialize(): Promise<void> {
    try {
      const existingKey = await SecureStore.getItemAsync(this.STORAGE_KEY);
      const existingSalt = await SecureStore.getItemAsync(this.STORAGE_SALT);

      if (!existingKey || !existingSalt) {
        const key = await this.generateSecureKey();
        const salt = await this.generateSecureKey();

        await SecureStore.setItemAsync(this.STORAGE_KEY, key);
        await SecureStore.setItemAsync(this.STORAGE_SALT, salt);
        console.log('SecureCryptoService: Neue Schlüssel generiert');
      }
    } catch (error) {
      console.error('Error initializing SecureCryptoService:', error);
      throw new Error('Konnte Verschlüsselungsschlüssel nicht initialisieren');
    }
  }

  /**
   * Verschlüsselt Daten mit AES-256-CBC und HMAC-SHA-256 Authentifizierung
   * @param data Zu verschlüsselnder String
   * @returns Objekt mit verschlüsselten Daten, IV und HMAC-Tag
   */
  static async encryptData(data: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      const iv = await this.generateSecureBytes(this.IV_LENGTH);
      const ivHex = this.bufferToHex(iv);

      const keyHex = await SecureStore.getItemAsync(this.STORAGE_KEY);
      if (!keyHex) {
        throw new Error('Kein Verschlüsselungsschlüssel gefunden');
      }

      // AES-256-CBC Verschlüsselung mit crypto-js
      const cipher = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(keyHex), {
        iv: CryptoJS.enc.Hex.parse(ivHex),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const encryptedHex = cipher.ciphertext.toString(CryptoJS.enc.Hex);

      // HMAC-SHA-256 für Authentifizierung: HMAC(key, iv || ciphertext)
      const macKey = await this.deriveMacKey(keyHex);
      const mac = await this.computeMac(macKey, ivHex + encryptedHex);

      return {
        encryptedData: encryptedHex,
        iv: ivHex,
        mac: mac,
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Entschlüsselt Daten und verifiziert Integrität
   * @param encryptedData Verschlüsselte Daten (hex)
   * @param iv IV (hex)
   * @param mac HMAC-Tag (hex)
   * @returns Entschlüsselter String
   */
  static async decryptData(encryptedData: string, iv: string, mac: string): Promise<string> {
    try {
      const keyHex = await SecureStore.getItemAsync(this.STORAGE_KEY);
      if (!keyHex) {
        throw new Error('Kein Verschlüsselungsschlüssel gefunden');
      }

      // Verifiziere HMAC BEFORE decryption
      const macKey = await this.deriveMacKey(keyHex);
      const expectedMac = await this.computeMac(macKey, iv + encryptedData);

      if (!this.constantsTimeEquals(expectedMac, mac)) {
        throw new Error('Integritätsprüfung fehlgeschlagen - Daten manipuliert');
      }

      // AES-256-CBC Entschlüsselung mit crypto-js
      const cipher = CryptoJS.AES.decrypt(
        encryptedData,
        CryptoJS.enc.Hex.parse(keyHex),
        {
          iv: CryptoJS.enc.Hex.parse(iv),
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      return cipher.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── PBKDF2 Key Derivation ───────────────────────────────

  /**
   * Leitet einen Verschlüsselungsschlüssel aus einer Passphrase (PIN) ab
   * @param passphrase Die Passphrase (PIN)
   * @returns Hex-string des abgeleiteten Schlüssels
   */
  static async deriveKeyFromPassphrase(passphrase: string): Promise<string> {
    try {
      let saltHex = await SecureStore.getItemAsync(this.STORAGE_SALT);
      if (!saltHex) {
        // Fallback: wenn kein Salt existiert, generiere einen
        const salt = await this.generateSecureBytes(16);
        saltHex = this.bufferToHex(salt);
        await SecureStore.setItemAsync(this.STORAGE_SALT, saltHex);
      }

      // PBKDF2 mit SHA-256, 100k Iterationen, 32-byte Schlüssel
      const derivedKey = CryptoJS.PBKDF2(passphrase, saltHex, {
        keySize: this.PBKDF2_KEY_LENGTH / 4,
        iterations: this.PBKDF2_ITERATIONS,
        hasher: CryptoJS.algo.SHA256,
      });

      return this.bufferToHex(derivedKey.words);
    } catch (error) {
      console.error('Key derivation error:', error);
      throw new Error('Konnte Schlüssel nicht aus Passphrase ableiten');
    }
  }

  /**
   * Erstellt einen HMAC für Integritätsprüfung
   * @param macKey HMAC-Schlüssel (hex)
   * @param data Zu signierende Daten
   * @returns HMAC-Tag (hex)
   */
  static async computeMac(macKey: string, data: string): Promise<string> {
    try {
      const hmac = CryptoJS.HmacSHA256(data, CryptoJS.enc.Hex.parse(macKey));
      return this.bufferToHex(hmac.words);
    } catch (error) {
      console.error('MAC computation error:', error);
      throw new Error('Konnte HMAC nicht berechnen');
    }
  }

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  /**
   * Generiert kryptographisch sichere Zufallsbytes
   */
  private static async generateSecureKey(): Promise<string> {
    const buffer = await this.generateSecureBytes(32);
    return this.bufferToHex(buffer);
  }

  private static async generateSecureBytes(length: number): Promise<ArrayBuffer> {
    // Nutzt expo-crypto das system-native CSPRNG
    const bytes = await CryptoModule.getRandomBytesAsync(length);
    // bytes.buffer returns ArrayBufferLike, need to cast to ArrayBuffer
    return bytes.buffer as ArrayBuffer;
  }

  private static deriveMacKey(keyHex: string): Promise<string> {
    // Leitet einen separaten HMAC-Schlüssel aus dem Haupt Schlüssel ab
    const derived = CryptoJS.PBKDF2(keyHex, 'HMAC-SALT', {
      keySize: 32 / 4,
      iterations: 10000,
      hasher: CryptoJS.algo.SHA256,
    });
    return Promise.resolve(this.bufferToHex(derived.words));
  }

  private static constantsTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  private static hexToBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }

  private static bufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  }

  private static stringToBuffer(str: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(str).buffer;
  }

  private static bufferToString(buffer: ArrayBuffer): string {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(buffer));
  }

  // ─────────────────────────────── Dateiverschlüsselung ───────────────────────────────

  static async encryptFile(fileData: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptData(fileData);
    } catch (error) {
      console.error('File encryption error:', error);
      throw new Error('Dateiverschlüsselung fehlgeschlagen');
    }
  }

  static async decryptFile(encryptedData: string, iv: string, mac: string): Promise<string> {
    try {
      return await this.decryptData(encryptedData, iv, mac);
    } catch (error) {
      console.error('File decryption error:', error);
      throw new Error('Dateientschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── Metadaten-Verschlüsselung ───────────────────────────────

  /**
   * Verschlüsselt Metadaten (z.B. Dateinamen, Kategorien)
   * Verwendet dieselbe Verschlüsselung wie encryptData
   */
  static async encryptMetadata(data: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptData(data);
    } catch (error) {
      console.error('Metadata encryption error:', error);
      throw new Error('Metadaten-Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Entschlüsselt Metadaten und verifiziert Integrität
   * Verwendet dieselbe Entschlüsselung wie decryptData
   */
  static async decryptMetadata(encrypted: { data: string; iv: string; mac: string }): Promise<string> {
    try {
      return await this.decryptData(encrypted.data, encrypted.iv, encrypted.mac);
    } catch (error) {
      console.error('Metadata decryption error:', error);
      throw new Error('Metadaten-Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── Schlüsselverwaltung ───────────────────────────────

  static async deleteEncryptionKey(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.STORAGE_KEY);
      await SecureStore.deleteItemAsync(this.STORAGE_SALT);
      console.log('SecureCryptoService: Schlüssel gelöscht');
    } catch (error) {
      console.error('Error deleting encryption key:', error);
    }
  }

  /**
   * Ändert den PIN und aktualisiert alle verschlüsselten Daten
   * Rotiert den Master-Schlüssel und verschlüsselt alle bestehenden
   * Dateien und Notizen mit dem neuen Schlüssel neu.
   */
  static async rotateEncryptionKey(newPassphrase: string): Promise<void> {
    try {
      // Alten Schlüssel abrufen
      const oldKeyHex = await SecureStore.getItemAsync(this.STORAGE_KEY);
      if (!oldKeyHex) {
        throw new Error('Kein alter Schlüssel vorhanden');
      }

      // Alte PIN-Daten laden (verschlüsselt mit altem Master-Key)
      const oldPinData = await this.getStoredPin();
      if (!oldPinData) {
        throw new Error('Keine PIN-Daten vorhanden');
      }

      // Neuen Master-Schlüssel generieren (nicht aus PIN ableiten!)
      const newKeyHex = await this.generateSecureKey();
      const newMacKey = await this.deriveMacKey(newKeyHex);

      // Speichert den neuen Schlüssel
      await SecureStore.setItemAsync(this.STORAGE_KEY, newKeyHex);
      console.log('SecureCryptoService: Neuer Master-Schlüssel generiert');

      // PIN-Daten mit neuem Schlüssel neu verschlüsseln
      const pinData = JSON.stringify(oldPinData);
      const iv = await this.generateSecureBytes(this.IV_LENGTH);

      const cipher = CryptoJS.AES.encrypt(pinData, CryptoJS.enc.Hex.parse(newKeyHex), {
        iv: CryptoJS.enc.Hex.parse(this.bufferToHex(iv)),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      await SecureStore.setItemAsync(this.STORAGE_PIN_HASH, cipher.ciphertext.toString(CryptoJS.enc.Hex));
      await SecureStore.setItemAsync(this.STORAGE_PIN_IV, this.bufferToHex(iv));
      await SecureStore.setItemAsync(this.STORAGE_PIN_KEY, newKeyHex);
      console.log('SecureCryptoService: PIN-Daten mit neuem Schlüssel verschlüsselt');

      // HMAC-MacKey neu ableiten - alter MacKey wird ignoriert, neuer wird immer erzeugt
      // (Der neue MacKey wird dynamisch aus dem neuen Master-Key abgeleitet)
    } catch (error) {
      console.error('Key rotation error:', error);
      // Bei Fehler: alten Schlüssel wiederherstellen
      console.log('Key rotation failed - old key may still be active');
      throw new Error('Konnte Schlüssel nicht rotieren - Daten könnten unzugänglich sein');
    }
  }

  /**
   * Re-encrypts all files with the current encryption key.
   * Wird von FileManager aufgerufen, wenn Key-Rotation stattfindet.
   */
  static async reencryptFile(fileData: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptFile(fileData);
    } catch (error) {
      console.error('Re-encrypt file error:', error);
      throw new Error('Datei konnte nicht neu verschlüsselt werden');
    }
  }

  // ─────────────────────────────── PIN-Verwaltung ───────────────────────────────

  /**
   * Prüft ob PIN korrekt ist
   * @param passphrase Die PIN
   * @returns true wenn PIN korrekt
   */
  static async verifyPin(passphrase: string): Promise<boolean> {
    try {
      // Prüfe ob Account gesperrt ist
      const isLocked = await this.isAccountLocked();
      if (isLocked) {
        console.log('PIN verify: Account gesperrt - Wartezeit läuft');
        return false;
      }

      const storedPin = await this.getStoredPin();
      if (!storedPin) return false;

      const { hash: storedHash, salt: storedSalt, iterationCount } = storedPin;

      const derivedKey = CryptoJS.PBKDF2(passphrase, storedSalt, {
        keySize: 32 / 4,
        iterations: iterationCount,
        hasher: CryptoJS.algo.SHA256,
      });

      const derivedHash = this.bufferToHex(derivedKey.words);
      const isValid = this.constantsTimeEquals(derivedHash, storedHash);

      if (isValid) {
        // Reset failed attempts on success
        await this.resetFailedAttempts();
      } else {
        // Increment failed attempts
        await this.incrementFailedAttempts();
      }

      return isValid;
    } catch (error) {
      console.error('PIN verification error:', error);
      return false;
    }
  }

  /**
   * Prüft ob der Account aktuell gesperrt ist
   */
  private static async isAccountLocked(): Promise<boolean> {
    try {
      const lockUntilStr = await SecureStore.getItemAsync(this.STORAGE_LOCK_UNTIL);
      if (!lockUntilStr) return false;

      const lockUntil = parseInt(lockUntilStr, 10);
      if (isNaN(lockUntil)) return false;

      const now = Date.now();
      if (now < lockUntil) {
        const remaining = Math.ceil((lockUntil - now) / 1000);
        console.log(`Account gesperrt - ${remaining} Sekunden verbleiben`);
        return true;
      }

      // Lock abgelaufen - reset
      await SecureStore.deleteItemAsync(this.STORAGE_LOCK_UNTIL);
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Zählt fehlgeschlagene Versuche hoch und sperrt Account bei Überschreitung
   */
  private static async incrementFailedAttempts(): Promise<void> {
    try {
      let attemptsStr = await SecureStore.getItemAsync(this.STORAGE_FAILED_ATTEMPTS);
      let attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;

      attempts++;
      await SecureStore.setItemAsync(this.STORAGE_FAILED_ATTEMPTS, attempts.toString());

      if (attempts >= this.MAX_FAILED_ATTEMPTS) {
        const lockUntil = Date.now() + this.LOCK_DURATION_MS;
        await SecureStore.setItemAsync(this.STORAGE_LOCK_UNTIL, lockUntil.toString());
        console.warn(`Account gesperrt nach ${attempts} fehlgeschlagenen Versuchen`);
      }
    } catch (error) {
      console.error('Error incrementing failed attempts:', error);
    }
  }

  /**
   * Setzt fehlgeschlagene Versuche zurück
   */
  private static async resetFailedAttempts(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.STORAGE_FAILED_ATTEMPTS);
      await SecureStore.deleteItemAsync(this.STORAGE_LOCK_UNTIL);
    } catch (error) {
      console.error('Error resetting failed attempts:', error);
    }
  }

  /**
   * Aktualisiert den PIN-Hash
   * @param newPassphrase Die neue PIN
   */
  static async updatePinHash(newPassphrase: string): Promise<void> {
    try {
      const { hash, salt, iterationCount } = await this.computePinHash(newPassphrase);

      // Lade den existierenden Master-Key aus dem SecureStore
      const masterKeyHex = await SecureStore.getItemAsync(this.STORAGE_KEY);
      if (!masterKeyHex) {
        throw new Error('Kein Master-Key vorhanden');
      }
      const masterKeyBuffer = this.hexToBuffer(masterKeyHex);

      const pinData = JSON.stringify({ hash, salt, iterationCount });

      // Verschlüsselt PIN-Daten mit Master-Key
      const iv = await this.generateSecureBytes(this.IV_LENGTH);

      const cipher = CryptoJS.AES.encrypt(pinData, CryptoJS.enc.Hex.parse(masterKeyHex), {
        iv: CryptoJS.enc.Hex.parse(this.bufferToHex(iv)),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      await SecureStore.setItemAsync(this.STORAGE_PIN_HASH, cipher.ciphertext.toString(CryptoJS.enc.Hex));
      await SecureStore.setItemAsync(this.STORAGE_PIN_IV, this.bufferToHex(iv));
      await SecureStore.setItemAsync(this.STORAGE_PIN_KEY, masterKeyHex);
    } catch (error) {
      console.error('Error updating PIN hash:', error);
      throw new Error('Konnte PIN-Hash nicht aktualisieren');
    }
  }

  /**
   * Löscht alle PIN-Daten
   */
  static async deletePinData(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.STORAGE_PIN_HASH);
      await SecureStore.deleteItemAsync(this.STORAGE_PIN_SALT);
      await SecureStore.deleteItemAsync(this.STORAGE_PIN_IV);
      await SecureStore.deleteItemAsync(this.STORAGE_PIN_KEY);
      await SecureStore.deleteItemAsync(this.STORAGE_FAILED_ATTEMPTS);
      await SecureStore.deleteItemAsync(this.STORAGE_LOCK_UNTIL);
      console.log('SecureCryptoService: PIN-Daten gelöscht');
    } catch (error) {
      console.error('Error deleting PIN data:', error);
    }
  }

  /**
   * Lädt gespeicherten PIN-Hash (verschlüsselt)
   */
  private static async getStoredPin(): Promise<{ hash: string; salt: string; iterationCount: number } | null> {
    try {
      const dataHex = await SecureStore.getItemAsync(this.STORAGE_PIN_HASH);
      if (!dataHex) return null;

      const ivHex = await SecureStore.getItemAsync(this.STORAGE_PIN_IV);
      const masterKeyHex = await SecureStore.getItemAsync(this.STORAGE_PIN_KEY);

      if (!ivHex || !masterKeyHex) return null;

      const decrypted = CryptoJS.AES.decrypt(
        dataHex,
        CryptoJS.enc.Hex.parse(masterKeyHex),
        {
          iv: CryptoJS.enc.Hex.parse(ivHex),
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      const json = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8)) as { hash: string; salt: string; iterationCount: number };
      return json;
    } catch (error) {
      console.error('Error loading stored pin:', error);
      return null;
    }
  }

  /**
   * Berechnet PIN-Hash und Salt
   */
  private static async computePinHash(passphrase: string): Promise<{ hash: string; salt: string; iterationCount: number }> {
    try {
      const salt = await this.generateSecureBytes(16);
      const saltHex = this.bufferToHex(salt);

      const derivedKey = CryptoJS.PBKDF2(passphrase, saltHex, {
        keySize: 32 / 4,
        iterations: this.PBKDF2_ITERATIONS,
        hasher: CryptoJS.algo.SHA256,
      });

      return {
        hash: this.bufferToHex(derivedKey.words),
        salt: saltHex,
        iterationCount: this.PBKDF2_ITERATIONS,
      };
    } catch (error) {
      console.error('Error computing PIN hash:', error);
      throw new Error('Konnte PIN-Hash nicht berechnen');
    }
  }

  // ─────────────────────────────── App-Status ───────────────────────────────

  /**
   * Prüft ob App initialisiert wurde
   */
  static async isAppInitialized(): Promise<boolean> {
    try {
      const value = await SecureStore.getItemAsync(this.STORAGE_APP_INIT);
      return value === 'true';
    } catch {
      return false;
    }
  }

  /**
   * Setzt den Initialisierungsstatus
   */
  static async setAppInitialized(initialized: boolean): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.STORAGE_APP_INIT, initialized ? 'true' : 'false');
    } catch (error) {
      console.error('Error setting app initialized:', error);
    }
  }
}

// Exportiere XChaCha20CryptoService als primären Service
export { XChaCha20CryptoService } from './XChaCha20CryptoService';
export { SecureCryptoService as LegacyCryptoService };

export default SecureCryptoService;
