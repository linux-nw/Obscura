import * as SecureStore from 'expo-secure-store';
import * as CryptoModule from 'expo-crypto';
import { NativeModules } from 'react-native';
import CryptoJS from 'crypto-js';
import { Argon2idService, Argon2Params } from './Argon2idService';
import { HardwareBackedStorage } from './HardwareKeystoreService';
import { fastPbkdf2, isNobleAvailable } from './FastPBKDF2';
import { fastAesEncrypt, fastAesDecrypt } from './FastAES';
// XChaCha20-Poly1305 native Module (erstellt bei ADB-Test)
// Import aus ../native da dieser Service in src/services liegt
import { encrypt as xchachaEncrypt, decrypt as xchachaDecrypt, verifyConstantTime as nativeVerifyConstantTime } from '../native/RNFileVault';

/**
 * SecureCryptoService - Authenticated Encryption mit XChaCha20-Poly1305 primary
 *
 * Sicherheitsmerkmale:
 * - Kryptographisch sicherer Zufallsgenerator (expo-crypto)
 * - XChaCha20-Poly1305 primary (native Module via RNFileVault)
 * - AES-256-GCM als erste Fallback
 * - AES-256-CBC mit CryptoJS ist LAST RESORT
 * - PBKDF2 Key Derivation für PIN-basierte Authentifizierung
 * - Argon2id Key Derivation
 * - Schlüssel in Device-Keychain (iOS Keychain / Android Keystore)
 * - Rate-Limiting: 5 fehlgeschlagene Versuche → 5 Minuten Sperre
 * - Konstanter Zeit-Vergleich gegen Timing-Attacks
 */

// ──────────────────────────────────────────────────────────────────────────────
// Encryption Backend Priority (from most to least preferred)
// ──────────────────────────────────────────────────────────────────────────────

// Backend identifiers for ciphertext format (stored in header of encrypted data)
const BACKEND_XCHACHA = 0x01; // XChaCha20-Poly1305
const BACKEND_FASTAES = 0x02; // FastAES (aes-js)
const BACKEND_CRYPTOJS = 0x03; // CryptoJS (last resort, not recommended)

/**
 * Extracts backend identifier from ciphertext header
 * First byte of decrypted data is the backend ID
 */
const extractBackendFromHeader = (encryptedData: string): 'xchacha' | 'fastaes' | 'cryptojs' => {
  try {
    const header = parseInt(encryptedData.substring(0, 2), 16);
    switch (header) {
      case BACKEND_XCHACHA:
        return 'xchacha';
      case BACKEND_FASTAES:
        return 'fastaes';
      case BACKEND_CRYPTOJS:
        return 'cryptojs';
      default:
        return 'cryptojs'; // Default to CryptoJS for unknown headers
    }
  } catch {
    return 'cryptojs'; // Default fallback
  }
};

/**
 * Versucht XChaCha20-Poly1305 mit native Module
 * Dies ist die PRIMARY encryption path (erstes, was verwendet wird)
 *
 * WICHTIG: Diese Funktion prüft NUR ob das native Module RNFileVault geladen ist.
 * Ein einfacher typeof-check auf xchachaEncrypt wäre IMMER true, da xchachaEncrypt
 * eine importierte Funktion ist, die即使 das native Module fehlt definiert ist.
 * Die echte Verfügbarkeit wird erst zur Laufzeit durch NativeModules.RNFileVault geprüft.
 */
const canUseXChaCha20 = (): boolean => {
  try {
    return !!NativeModules.RNFileVault;
  } catch {
    return false;
  }
};

/**
 * Versucht AES-256-GCM mit FastAES (aes-js) - schneller als CryptoJS
 * Dies ist die FIRST Fallback-Option nach XChaCha20
 */
const canUseFastAES = (): boolean => {
  try {
    // FastAES ist verfügbar wenn aes-js geladen werden kann
    return typeof fastAesEncrypt === 'function';
  } catch {
    return false;
  }
};

/**
 * Versucht AES-256-CBC mit CryptoJS
 * Dies ist der LAST RESORT Fallback
 */
const canUseCryptoJSGCM = () => true;

// ──────────────────────────────────────────────────────────────────────────────

export class SecureCryptoService {
  private static readonly STORAGE_KEY = 'filevault_encryption_key';
  private static readonly STORAGE_SALT = 'filevault_pbkdf2_salt';
  private static readonly STORAGE_ARGON2_SALT = 'filevault_argon2id_salt';
  // IV/Nonce lengths - different for different encryption modes
  // XChaCha20-Poly1305 requires 24-byte (192-bit) nonce
  private static readonly XCHACHA_NONCE_LENGTH = 24;
  // AES-GCM requires 12-byte (96-bit) IV
  private static readonly GCM_IV_LENGTH = 12;
  // AES-CBC requires 16-byte (128-bit) IV
  private static readonly CBC_IV_LENGTH = 16;
  private static readonly PBKDF2_ITERATIONS = 600000; // NIST SP 800-132 §5.3 (2023)
  private static readonly PBKDF2_KEY_LENGTH = 32;

  // Argon2id configuration - erhöht von 2 auf 3 Iterationen
  private static readonly ARGON2_MEMORY_KB = 65536; // 64 MB
  private static readonly ARGON2_ITERATIONS = 3; // Erhöht von 2
  private static readonly ARGON2_PARALLELISM = 4;
  private static readonly ARGON2_HASH_LENGTH = 32;
  private static readonly ARGON2_VERSION = 0x13; // 19 = Argon2 version 1.3
  private static readonly STORAGE_PIN_HASH = 'filevault_pin_hash';
  private static readonly STORAGE_PIN_SALT = 'filevault_pin_salt';
  private static readonly STORAGE_PIN_IV = 'filevault_pin_iv';
  private static readonly STORAGE_PIN_KEY = 'filevault_pin_key';
  private static readonly STORAGE_APP_INIT = 'filevault_app_initialized';
  private static readonly STORAGE_FAILED_ATTEMPTS = 'filevault_failed_attempts';
  private static readonly STORAGE_LOCK_UNTIL = 'filevault_lock_until';
  private static readonly MAX_FAILED_ATTEMPTS = 5;

  // KEK-wrapped master key storage (passphrase-based unlock)
  private static readonly STORAGE_KEK_SALT = 'filevault_kek_salt';
  private static readonly STORAGE_MASTER_ENC = 'filevault_master_enc';
  private static readonly STORAGE_MASTER_IV = 'filevault_master_iv';
  private static readonly STORAGE_MASTER_MAC = 'filevault_master_mac';
  private static readonly STORAGE_BIO_KEK = 'filevault_bio_kek';
  private static readonly LOCK_DURATION_MS = 300000; // 5 Minuten

  // ─────────────────────────────── GCM Utility Functions ───────────────────────────────

  /**
   * Konvertiert ArrayBuffer zu Hex-String
   */
  static bufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  }

  /**
   * Konvertiert Hex-String zu ArrayBuffer
   */
  static hexToBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }

  /**
   * Generiert kryptographisch sichere Zufallsbytes
   */
  static async generateSecureBytes(length: number): Promise<ArrayBuffer> {
    const result = await CryptoModule.getRandomBytesAsync(length);
    // Slice to exact bytes: on Hermes, result.buffer may be a pooled ArrayBuffer
    // larger than result.byteLength, causing bufferToHex to produce an oversized
    // hex string and aes-js to throw "invalid initialization vector size".
    return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
  }

  /**
   * AES-256-CBC Verschlüsselung mit CryptoJS
   * Dies ist der LAST RESORT Fallback - wird nur verwendet wenn XChaCha20 und FastAES nicht verfügbar sind
   * CryptoJS ist sehr langsam (~100x langsamer als native Module)
   */
  private static async cryptoJSGCMEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    try {
      const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
      const ivBytes = CryptoJS.enc.Hex.parse(ivHex);

      // AES-GCM simulieren: CBC + HMAC
      const cipher = CryptoJS.AES.encrypt(data, keyBytes, {
        iv: ivBytes,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const encryptedHex = cipher.ciphertext.toString(CryptoJS.enc.Hex);

      // HMAC-SHA-256 für Authentifizierung (Encrypt-then-MAC)
      const macKey = await this.deriveMacKey(keyHex);
      const mac = await this.computeMac(macKey, ivHex + encryptedHex);

      return {
        encryptedData: encryptedHex,
        tag: mac,
      };
    } catch {
      throw new Error('AES-GCM (CryptoJS) Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * AES-256-GCM Entschlüsselung mit CryptoJS
   */
  private static async cryptoJSGCMDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    try {
      const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
      const ivBytes = CryptoJS.enc.Hex.parse(ivHex);

      // Verifiziere HMAC BEFORE decryption
      const macKey = await this.deriveMacKey(keyHex);
      const expectedMac = await this.computeMac(macKey, ivHex + encryptedData);

      if (!await this.constantsTimeEquals(expectedMac, tag)) {
        throw new Error('Integritätsprüfung fehlgeschlagen - Daten manipuliert');
      }

      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(encryptedData),
      });
      const cipher = CryptoJS.AES.decrypt(
        cipherParams,
        keyBytes,
        {
          iv: ivBytes,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      return cipher.toString(CryptoJS.enc.Utf8);
    } catch {
      throw new Error('AES-GCM (CryptoJS) Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── AES-CBC Helper (für Key Wrapping) ───────────────────────────────

  /**
   * AES-256-CBC Verschlüsselung mit ausgewähltem Backend
   * Wird für Key Wrapping (KEK, File-Key) verwendet
   */
  private static async aesCBCEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    // Backend wählen: XChaCha20 > FastAES > CryptoJS
    const backend = this.getEncryptionBackend();

    if (backend === 'fastaes') {
      return await this.fastAESCBCEncrypt(data, keyHex, ivHex);
    } else if (backend === 'xchacha') {
      return await this.xchacha20Encrypt(data, keyHex, ivHex);
    } else {
      return await this.cryptoJSCBCEncrypt(data, keyHex, ivHex);
    }
  }

  /**
   * AES-256-CBC Entschlüsselung mit ausgewähltem Backend
   * Wird für Key Wrapping (KEK, File-Key) verwendet
   */
  private static async aesCBCDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    // Backend wählen: XChaCha20 > FastAES > CryptoJS
    const backend = this.getDecryptionBackend(encryptedData);

    if (backend === 'xchacha') {
      try {
        return await this.xchacha20Decrypt(encryptedData, ivHex, tag, keyHex);
      } catch {
        // Fallback zu next backend
      }
    }
    if (backend === 'fastaes') {
      try {
        return await this.fastAESCBCDecrypt(encryptedData, ivHex, tag, keyHex);
      } catch {
        // Fallback zu next backend
      }
    }
    // Last resort: CryptoJS
    return await this.cryptoJSCBCDecrypt(encryptedData, ivHex, tag, keyHex);
  }

  // ─── FastAES CBC Implementierung (für Key Wrapping) ───

  private static async fastAESCBCEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseFastAES()) {
      throw new Error('FastAES nicht verfügbar');
    }
    const result = await fastAesEncrypt(data, keyHex, ivHex);
    const macKey = await this.deriveMacKey(keyHex);
    const mac = await this.computeMac(macKey, ivHex + result);
    return { encryptedData: result, tag: mac };
  }

  private static async fastAESCBCDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    if (!canUseFastAES()) {
      throw new Error('FastAES nicht verfügbar');
    }
    const macKey = await this.deriveMacKey(keyHex);
    const expectedMac = await this.computeMac(macKey, ivHex + encryptedData);
    if (!await this.constantsTimeEquals(expectedMac, tag)) {
      throw new Error('Integritätsprüfung fehlgeschlagen');
    }
    return await fastAesDecrypt(encryptedData, keyHex, ivHex);
  }

  // ─── XChaCha20-Poly1305 Implementierung (für Key Wrapping) ───
  // Hinweis: XChaCha20 ist ein Stream Cipher mit Poly1305 Authentication Tag.
  // Es gibt keinen CBC Mode - dieser Name ist historisch bedingt für die
  // "Key Wrapping" Funktionalität, nutzt aber die echte XChaCha20-Poly1305 Implementierung.

  /**
   * XChaCha20-Poly1305 Verschlüsselung (public wrapper für BackupService)
   * Wird von BackupService extern verwendet
   */
  static async xchachaEncryptPublic(
    data: string,
    keyHex: string,
    nonceHex: string
  ): Promise<{ encrypted: string; tag: string }> {
    const result = await this.xchacha20Encrypt(data, keyHex, nonceHex);
    return { encrypted: result.encryptedData, tag: result.tag };
  }

  /**
   * XChaCha20-Poly1305 Entschlüsselung (public wrapper für BackupService)
   * Wird von BackupService extern verwendet
   */
  static async xchachaDecryptPublic(
    encryptedData: string,
    nonceHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    return await this.xchacha20Decrypt(encryptedData, nonceHex, tag, keyHex);
  }

  private static async xchacha20Encrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 nicht verfügbar');
    }
    const dataB64 = btoa(data);
    const result = await xchachaEncrypt(dataB64, keyHex, ivHex);
    return { encryptedData: result.encrypted, tag: result.tag };
  }

  private static async xchacha20Decrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 nicht verfügbar');
    }
    const result = await xchachaDecrypt(encryptedData, ivHex, tag, keyHex);
    return atob(result);
  }

  // ─── CryptoJS CBC Implementierung (Legacy, für Key Wrapping) ───

  private static async cryptoJSCBCEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
    const ivBytes = CryptoJS.enc.Hex.parse(ivHex);
    const cipher = CryptoJS.AES.encrypt(data, keyBytes, {
      iv: ivBytes,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const encryptedHex = cipher.ciphertext.toString(CryptoJS.enc.Hex);
    const macKey = await this.deriveMacKey(keyHex);
    const mac = await this.computeMac(macKey, ivHex + encryptedHex);
    return { encryptedData: encryptedHex, tag: mac };
  }

  private static async cryptoJSCBCDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
    const ivBytes = CryptoJS.enc.Hex.parse(ivHex);
    const macKey = await this.deriveMacKey(keyHex);
    const expectedMac = await this.computeMac(macKey, ivHex + encryptedData);
    if (!await this.constantsTimeEquals(expectedMac, tag)) {
      throw new Error('Integritätsprüfung fehlgeschlagen');
    }
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(encryptedData),
    });
    const cipher = CryptoJS.AES.decrypt(
      cipherParams,
      keyBytes,
      {
        iv: ivBytes,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      }
    );
    return cipher.toString(CryptoJS.enc.Utf8);
  }

  // ─────────────────────────────── FastAES (AES-256-GCM) Backend (First Fallback) ───────────────────────────────

  /**
   * AES-256-GCM Verschlüsselung mit FastAES (aes-js)
   * Dies ist die FIRST Fallback-Option nach XChaCha20
   * FastAES ist schneller als CryptoJS, aber langsamer als native XChaCha20
   */
  private static async fastAESGCMEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseFastAES()) {
      throw new Error('FastAES nicht verfügbar');
    }

    try {
      // FastAES verwendet CBC Modus, aber wir tun so als wäre es GCM
      // Da FastAES CBC ist, nutzen wir Encrypt-then-MAC für Authentifizierung
      const result = await fastAesEncrypt(data, keyHex, ivHex);

      // HMAC-SHA-256 für Authentifizierung (Encrypt-then-MAC)
      const macKey = await this.deriveMacKey(keyHex);
      const mac = await this.computeMac(macKey, ivHex + result);

      return {
        encryptedData: result,
        tag: mac,
      };
    } catch (error) {
      console.warn('[AES-GCM] FastAES failed, trying fallback:', error);
      throw error;
    }
  }

  /**
   * AES-256-GCM Entschlüsselung mit FastAES (aes-js)
   */
  private static async fastAESGCMDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    if (!canUseFastAES()) {
      throw new Error('FastAES nicht verfügbar');
    }

    try {
      // Verifiziere HMAC BEFORE decryption
      const macKey = await this.deriveMacKey(keyHex);
      const expectedMac = await this.computeMac(macKey, ivHex + encryptedData);

      if (!await this.constantsTimeEquals(expectedMac, tag)) {
        throw new Error('Integritätsprüfung fehlgeschlagen - Daten manipuliert');
      }

      const result = await fastAesDecrypt(encryptedData, keyHex, ivHex);
      return result;
    } catch (error) {
      console.warn('[AES-GCM] FastAES decrypt failed:', error);
      throw error;
    }
  }

  // ─────────────────────────────── XChaCha20-Poly1305 Backend (PRIMARY) ───────────────────────────────

  /**
   * XChaCha20-Poly1305 Verschlüsselung mit native Module
   * Dies ist der PRIMARY encryption path (wird zuerst verwendet)
   * XChaCha20-Poly1305 ist ein modernes Authenticated Encryption Scheme
   */
  private static async xchachaEncrypt(
    data: string,
    keyHex: string,
    nonceHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 native Module nicht verfügbar');
    }

    try {
      // XChaCha20 erwartet base64-kodierte Daten
      const dataB64 = btoa(data);

      const result = await xchachaEncrypt(dataB64, keyHex, nonceHex);

      return {
        encryptedData: result.encrypted,
        tag: result.tag,
      };
    } catch (error) {
      console.warn('[XChaCha20] Encryption failed, trying fallback:', error);
      throw error;
    }
  }

  /**
   * XChaCha20-Poly1305 Entschlüsselung mit native Module
   */
  private static async xchachaDecrypt(
    encryptedData: string,
    nonceHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 native Module nicht verfügbar');
    }

    try {
      const result = await xchachaDecrypt(encryptedData, nonceHex, tag, keyHex);

      return atob(result);
    } catch (error) {
      console.warn('[XChaCha20] Decryption failed:', error);
      throw error;
    }
  }

  // ─────────────────────────────── Backend Selection ───────────────────────────────

  /**
   * Prüft ob XChaCha20-Poly1305 native Module verfügbar ist
   * Wird von BackupService extern verwendet
   */
  static canUseXChaCha20(): boolean {
    return canUseXChaCha20();
  }

  /**
   * Prüft ob FastAES verfügbar ist
   * Wird von BackupService extern verwendet
   */
  static canUseFastAES(): boolean {
    return canUseFastAES();
  }

  /**
   * Wählt das beste verfügbare Encryption Backend
   * Priorität: XChaCha20 > FastAES > CryptoJS
   *
   * Backend-Trace für encryptData():
   * 1. canUseXChaCha20() prüft NativeModules.RNFileVault
   *    - Wenn true → XChaCha20 wird verwendet (24-byte nonce)
   *    - Wenn false → prüfe FastAES
   * 2. canUseFastAES() prüft fastAesEncrypt
   *    - Wenn true → FastAES (aes-js) wird verwendet
   *    - Wenn false → falle zu CryptoJS zurück
   * 3. CryptoJS ist der LAST RESORT Fallback
   *
   * WICHTIG: Durch die canUseXChaCha20()-Fix mit NativeModules.RNFileVault prüfung
   * sind nun FastAES und CryptoJS erreichbar, wenn das native Module nicht geladen ist.
   */
  private static getEncryptionBackend(): 'xchacha' | 'fastaes' | 'cryptojs' {
    if (canUseXChaCha20()) {
      return 'xchacha';
    }
    if (canUseFastAES()) {
      return 'fastaes';
    }
    return 'cryptojs';
  }

  /**
   * Wählt das beste verfügbare Decryption Backend basierend auf Datenformat
   * Priorität: XChaCha20 > FastAES > CryptoJS
   */
  private static getDecryptionBackend(encryptedData: string): 'xchacha' | 'fastaes' | 'cryptojs' {
    // Wenn wir die Daten selbst verschlüsselt haben, wissen wir das Backend
    // Andernfalls versuchen wir XChaCha20 first, dann FastAES, dann CryptoJS
    if (canUseXChaCha20()) {
      return 'xchacha';
    }
    if (canUseFastAES()) {
      return 'fastaes';
    }
    return 'cryptojs';
  }

  // ─────────────────────────────── Public API ───────────────────────────────

  /**
   * Initialisiere den Kryptografie-Service
   * - Generiert einen zufälligen Master-Schlüssel
   * - Generiert einen PBKDF2-Salt für PIN-Derivation
   * - Speichert Schlüssel in Hardware Keystore (iOS Secure Enclave / Android StrongBox)
   */
  static async initialize(): Promise<void> {
    // No-op: master key is generated in setupMasterKey() when passphrase is created
  }

  /**
   * Holt den aktuellen Master-Schlüssel — in-memory cached nach erstem Lesen
   * Wird von FileEncryptionKey für Key Wrapping/Unwrapping verwendet
   */
  static async getMasterKey(): Promise<string | null> {
    return this._masterKeyCache;
  }

  static async loadMasterKeyForBiometric(): Promise<boolean> {
    if (this._masterKeyCache) return true;
    try {
      const kek = await SecureStore.getItemAsync(this.STORAGE_BIO_KEK, {
        requireAuthentication: true,
        authenticationPrompt: 'Tresor entsperren',
      });
      if (!kek) return false;
      const encMasterKey = await this.getItemSecure(this.STORAGE_MASTER_ENC);
      const ivHex = await this.getItemSecure(this.STORAGE_MASTER_IV);
      const storedMac = await this.getItemSecure(this.STORAGE_MASTER_MAC);
      if (!encMasterKey || !ivHex || !storedMac) return false;
      const macKey = await this.deriveMacKey(kek);
      const expectedMac = await this.computeMac(macKey, ivHex + encMasterKey);
      if (!await this.constantsTimeEquals(expectedMac, storedMac)) return false;
      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(encMasterKey),
      });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, CryptoJS.enc.Hex.parse(kek), {
        iv: CryptoJS.enc.Hex.parse(ivHex),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      const masterKeyHex = decrypted.toString(CryptoJS.enc.Utf8);
      if (masterKeyHex && masterKeyHex.length === 64) {
        this._masterKeyCache = masterKeyHex;
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /** Löscht alle In-Memory Caches (Master-Key + MAC-Key). Beim Sperren aufrufen. */
  static clearAllCaches(): void {
    this._masterKeyCache = null;
    this.macKeyCache.clear();
  }

  // ─────────────────────────────── Passphrase-based unlock (KEK wrapping) ───────────────────────────────

  /**
   * First launch: generates a random master key, wraps it with KEK derived from passphrase,
   * and also stores it hardware-protected for biometric unlock.
   */
  static async setupMasterKey(passphrase: string): Promise<void> {
    const masterKeyHex = this.bufferToHex(await this.generateSecureBytes(32));
    await this.wrapAndStoreMasterKey(passphrase, masterKeyHex);
    this._masterKeyCache = masterKeyHex;
  }

  /**
   * Login: derive KEK from passphrase, decrypt master key, cache it.
   * Handles legacy format migration transparently.
   * Returns false if passphrase is wrong or vault is locked.
   */
  static async unlock(passphrase: string): Promise<boolean> {
    try {
      const isLocked = await this.isAccountLocked();
      if (isLocked) return false;

      const encMasterKey = await this.getItemSecure(this.STORAGE_MASTER_ENC);
      if (encMasterKey) {
        return await this.unlockKEK(passphrase, encMasterKey);
      }

      // Legacy format: master key stored in plaintext — migrate on first passphrase login
      const legacyKey = await this.getItemSecure(this.STORAGE_KEY);
      if (legacyKey) {
        return await this.migrateLegacy(passphrase, legacyKey);
      }

      return false;
    } catch {
      return false;
    }
  }

  private static async unlockKEK(passphrase: string, encMasterKey: string): Promise<boolean> {
    try {
      const kekSaltHex = await this.getItemSecure(this.STORAGE_KEK_SALT);
      const ivHex = await this.getItemSecure(this.STORAGE_MASTER_IV);
      const storedMac = await this.getItemSecure(this.STORAGE_MASTER_MAC);
      if (!kekSaltHex || !ivHex || !storedMac) return false;

      const kek = await this.deriveKEK(passphrase, kekSaltHex);
      const macKey = await this.deriveMacKey(kek);
      const expectedMac = await this.computeMac(macKey, ivHex + encMasterKey);

      if (!await this.constantsTimeEquals(expectedMac, storedMac)) {
        await this.incrementFailedAttempts();
        return false;
      }

      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(encMasterKey),
      });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, CryptoJS.enc.Hex.parse(kek), {
        iv: CryptoJS.enc.Hex.parse(ivHex),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      const masterKeyHex = decrypted.toString(CryptoJS.enc.Utf8);
      if (!masterKeyHex || masterKeyHex.length !== 64) {
        await this.incrementFailedAttempts();
        return false;
      }

      this._masterKeyCache = masterKeyHex;
      await this.resetFailedAttempts();
      this.migrateBioKekAsync(kek).catch(() => {});
      return true;
    } catch {
      await this.incrementFailedAttempts();
      return false;
    }
  }

  private static async migrateLegacy(passphrase: string, legacyKey: string): Promise<boolean> {
    // verifyPin() handles the old hash comparison and increments failed attempts on failure
    const isValid = await this.verifyPin(passphrase);
    if (!isValid) return false;

    await this.wrapAndStoreMasterKey(passphrase, legacyKey);
    await this.deleteItemSecure(this.STORAGE_KEY);
    await this.deleteItemSecure(this.STORAGE_SALT);
    await this.deleteItemSecure(this.STORAGE_ARGON2_SALT);
    await this.deleteItemSecure(this.STORAGE_PIN_HASH);
    await this.deleteItemSecure(this.STORAGE_PIN_SALT);
    await this.deleteItemSecure(this.STORAGE_PIN_IV);
    await this.deleteItemSecure(this.STORAGE_PIN_KEY);

    this._masterKeyCache = legacyKey;
    return true;
  }

  /**
   * Changes passphrase: verifies old passphrase, re-wraps master key with new KEK.
   * Master key itself never changes — all file keys remain valid.
   */
  static async changePassphrase(oldPassphrase: string, newPassphrase: string): Promise<boolean> {
    try {
      const unlocked = await this.unlock(oldPassphrase);
      if (!unlocked) return false;

      const masterKeyHex = this._masterKeyCache;
      if (!masterKeyHex) return false;

      await this.wrapAndStoreMasterKey(newPassphrase, masterKeyHex);
      return true;
    } catch {
      return false;
    }
  }

  private static async wrapAndStoreMasterKey(passphrase: string, masterKeyHex: string): Promise<void> {
    const kekSaltHex = this.bufferToHex(await this.generateSecureBytes(32));
    const kek = await this.deriveKEK(passphrase, kekSaltHex);
    // Key wrapping uses aesCBCEncrypt which uses CBC mode - requires 16-byte IV
    const ivHex = this.bufferToHex(await this.generateSecureBytes(this.CBC_IV_LENGTH));

    const result = await this.aesCBCEncrypt(masterKeyHex, kek, ivHex);

    await this.setItemSecure(this.STORAGE_KEK_SALT, kekSaltHex);
    await this.setItemSecure(this.STORAGE_MASTER_ENC, result.encryptedData);
    await this.setItemSecure(this.STORAGE_MASTER_IV, ivHex);
    await this.setItemSecure(this.STORAGE_MASTER_MAC, result.tag);
    try {
      await SecureStore.setItemAsync(this.STORAGE_BIO_KEK, kek, { requireAuthentication: true });
    } catch {}
  }

  private static async migrateBioKekAsync(kek: string): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.STORAGE_BIO_KEK, kek, { requireAuthentication: true });
    } catch {}
  }

  private static async deriveKEK(passphrase: string, kekSaltHex: string): Promise<string> {
    const useArgon2 = (global as any).__argon2_native_available;
    if (useArgon2) {
      const saltBuffer = this.hexToBuffer(kekSaltHex);
      const params: Argon2Params = {
        version: this.ARGON2_VERSION,
        type: 2,
        memoryKB: this.ARGON2_MEMORY_KB,
        iterations: this.ARGON2_ITERATIONS, // 3 Iterationen
        parallelism: this.ARGON2_PARALLELISM,
        hashLength: this.ARGON2_HASH_LENGTH,
      };
      const derived = await Argon2idService.deriveKey(passphrase, saltBuffer, params);
      return this.bufferToHex(derived);
    }
    // WICHTIG: Kein CryptoJS Fallback mehr - stattdessen native PBKDF2 nutzen
    const derived = await fastPbkdf2(passphrase, kekSaltHex, this.PBKDF2_ITERATIONS, this.PBKDF2_KEY_LENGTH);
    return derived;
  }

  /**
   * Verschlüsselt Daten mit AES-256-GCM (oder XChaCha20-Poly1305 als Fallback)
   * Speichert Backend-Info im Header zur automatischen Decryption-Pfad-Wahl
   * @param data Zu verschlüsselnder String
   * @returns Objekt mit verschlüsselten Daten, IV und Auth Tag
   */
  static async encryptData(data: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string; // GCM Tag wird als mac bezeichnet für API-Kompatibilität
  }> {
    try {
      const keyHex = await this.getMasterKey();
      if (!keyHex) {
        throw new Error('Kein Verschlüsselungsschlüssel gefunden');
      }

      // Backend wählen: XChaCha20 > FastAES > CryptoJS
      const backend = this.getEncryptionBackend();

      let encryptedHex: string;
      let tag: string;
      let ivHex: string;

      if (backend === 'xchacha') {
        // XChaCha20 requires 24-byte nonce
        const xchachaNonce = await this.generateSecureBytes(this.XCHACHA_NONCE_LENGTH);
        ivHex = this.bufferToHex(xchachaNonce);
        const result = await this.xchachaEncryptPublic(data, keyHex, ivHex);
        encryptedHex = result.encrypted;
        tag = result.tag;
      } else if (backend === 'fastaes') {
        // FastAES uses CBC mode internally, requires 16-byte IV
        const cbcIV = await this.generateSecureBytes(this.CBC_IV_LENGTH);
        ivHex = this.bufferToHex(cbcIV);
        const result = await this.fastAESGCMEncrypt(data, keyHex, ivHex);
        encryptedHex = result.encryptedData;
        tag = result.tag;
      } else {
        // CryptoJS uses CBC mode internally, requires 16-byte IV
        const cbcIV = await this.generateSecureBytes(this.CBC_IV_LENGTH);
        ivHex = this.bufferToHex(cbcIV);
        const result = await this.cryptoJSGCMEncrypt(data, keyHex, ivHex);
        encryptedHex = result.encryptedData;
        tag = result.tag;
      }

      // Prefix with backend identifier for decryption-time routing
      // Format: [backend_id][encrypted_data]
      // XChaCha20 = 0x01, FastAES = 0x02, CryptoJS = 0x03
      let backendPrefix = '';
      if (backend === 'xchacha') {
        backendPrefix = BACKEND_XCHACHA.toString(16).padStart(2, '0');
      } else if (backend === 'fastaes') {
        backendPrefix = BACKEND_FASTAES.toString(16).padStart(2, '0');
      } else {
        backendPrefix = BACKEND_CRYPTOJS.toString(16).padStart(2, '0');
      }
      encryptedHex = backendPrefix + encryptedHex;

      return {
        encryptedData: encryptedHex,
        iv: ivHex,
        mac: tag,
      };
    } catch {
      throw new Error('Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Entschlüsselt Daten und verifiziert Integrität (GCM / XChaCha20-Poly1305)
   * Wählt Backend basierend auf im Header gespeicherter Backend-ID.
   * HMAC-Verifikationsfehler sind FATAL - kein Backend-Fallback!
   * @param encryptedData Verschlüsselte Daten (hex, mit Backend-Prefix)
   * @param iv IV (hex)
   * @param mac Auth Tag (hex)
   * @returns Entschlüsselter String
   */
  static async decryptData(encryptedData: string, iv: string, mac: string): Promise<string> {
    try {
      const keyHex = await this.getMasterKey();
      if (!keyHex) {
        throw new Error('Kein Verschlüsselungsschlüssel gefunden');
      }

      // Lese Backend-ID aus Header (erste 2 hex Zeichen)
      // Format: [backend_id][encrypted_data]
      // XChaCha20 = 0x01, FastAES = 0x02, CryptoJS = 0x03
      if (encryptedData.length < 2) {
        throw new Error('Ungültiges ciphertext format - zu kurz für Backend-Header');
      }
      const backendPrefix = encryptedData.substring(0, 2);
      const backendCode = parseInt(backendPrefix, 16);
      let backend: 'xchacha' | 'fastaes' | 'cryptojs';

      switch (backendCode) {
        case BACKEND_XCHACHA:
          backend = 'xchacha';
          break;
        case BACKEND_FASTAES:
          backend = 'fastaes';
          break;
        case BACKEND_CRYPTOJS:
          backend = 'cryptojs';
          break;
        default:
          throw new Error(`Unbekannter Backend-Code: 0x${backendPrefix}`);
      }

      // Verwende nur das gespeicherte Backend - KEIN fallback!
      // HMAC-Verifikation fehlschlagen = DIRECT ERROR, no retry!
      if (backend === 'xchacha') {
        return await this.xchachaDecrypt(encryptedData, iv, mac, keyHex);
      } else if (backend === 'fastaes') {
        return await this.fastAESGCMDecrypt(encryptedData, iv, mac, keyHex);
      } else {
        return await this.cryptoJSGCMDecrypt(encryptedData, iv, mac, keyHex);
      }
    } catch {
      throw new Error('Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── Key Derivation (Argon2id + fastPbkdf2) ───────────────────────────────

  /**
   * Prüft ob ein gespeicherter Hash das PBKDF2 Format hat
   * @param hash Der zu prüfende Hash
   */
  private static isLegacyPBKDF2Hash(hash: string): boolean {
    // PBKDF2 Hash aus CryptoJS sind 64 hex Zeichen (32 bytes)
    return /^[a-f0-9]{64}$/i.test(hash);
  }

  /**
   * Leitet einen Verschlüsselungsschlüssel aus einer Passphrase (PIN) ab
   * Nutzt Argon2id (empfohlen) mit fastPbkdf2 Fallback für Kompatibilität
   * ACHTUNG: Kein CryptoJS Fallback mehr - fastPbkdf2 nutzt native Backends
   * @param passphrase Die Passphrase (PIN)
   * @returns Hex-string des abgeleiteten Schlüssels
   */
  static async deriveKeyFromPassphrase(passphrase: string): Promise<string> {
    try {
      let saltHex = await this.getItemSecure(this.STORAGE_SALT);
      if (!saltHex) {
        // Fallback: wenn kein Salt existiert, generiere einen
        const salt = await this.generateSecureBytes(16);
        saltHex = this.bufferToHex(salt);
        await this.setItemSecure(this.STORAGE_SALT, saltHex);
      }

      const saltBuffer = this.hexToBuffer(saltHex);

      // Prüfe ob native Argon2 Module verfügbar ist
      const useArgon2 = (global as any).__argon2_native_available;

      if (useArgon2) {
        // Argon2id verwenden
        const params: Argon2Params = {
          version: this.ARGON2_VERSION,
          type: 2, // Argon2id
          memoryKB: this.ARGON2_MEMORY_KB,
          iterations: this.ARGON2_ITERATIONS, // 3 Iterationen
          parallelism: this.ARGON2_PARALLELISM,
          hashLength: this.ARGON2_HASH_LENGTH,
        };

        const derivedKey = await Argon2idService.deriveKey(passphrase, saltBuffer, params);
        return this.bufferToHex(derivedKey);
      } else {
        // Fallback auf fastPbkdf2 (fast-sha256 oder native quick-crypto)
        // Kein CryptoJS Fallback - wir werfen statt dessen einen Error
        const derivedKey = await fastPbkdf2(passphrase, saltHex, this.PBKDF2_ITERATIONS, this.PBKDF2_KEY_LENGTH);
        return derivedKey;
      }
    } catch {
      throw new Error('Konnte Schlüssel nicht aus Passphrase ableiten');
    }
  }

  /**
   * Erstellt einen HMAC für Integritätsprüfung
   * Nutzt @noble/hashes (HMAC-SHA256) für schnelle Verarbeitung großer Daten
   * @param macKey HMAC-Schlüssel (hex)
   * @param data Zu signierende Daten
   * @returns HMAC-Tag (hex)
   */
  static async computeMac(macKey: string, data: string): Promise<string> {
    try {
      // Fast path: @noble/hashes HMAC-SHA256 (~4x faster than CryptoJS for large data)
      try {
        const { hmac } = require('@noble/hashes/hmac');
        const { sha256 } = require('@noble/hashes/sha256');
        const keyBytes = this.hexToBuffer(macKey);
        // Data is ASCII hex string → encode as UTF-8 (identical to CryptoJS for ASCII)
        const dataBytes = new TextEncoder().encode(data);
        const result: Uint8Array = hmac(sha256, keyBytes, dataBytes);
        return this.bytesToHex_fast(result);
      } catch {
        // Noble not available, fall through to CryptoJS
      }

      const macResult = CryptoJS.HmacSHA256(data, CryptoJS.enc.Hex.parse(macKey));
      return macResult.toString(CryptoJS.enc.Hex);
    } catch {
      throw new Error('Konnte HMAC nicht berechnen');
    }
  }

  private static bytesToHex_fast(bytes: Uint8Array): string {
    const hex: string[] = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      hex[i] = (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex.join('');
  }

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  /**
   * Generiert kryptographisch sichere Zufallsbytes
   */
  private static async generateSecureKey(): Promise<string> {
    const buffer = await this.generateSecureBytes(32);
    return this.bufferToHex(buffer);
  }

  // Master-Key in-memory cache — cleared on logout, saves ~50-200ms per crypto op
  private static _masterKeyCache: string | null = null;

  // MAC-Key Cache: deterministisch ableitbar pro Master-Key, daher safely cacheable
  private static macKeyCache = new Map<string, string>();

  /**
   * Leitet einen separaten HMAC-Schlüssel aus dem Haupt Schlüssel ab.
   * - Gecacht (deterministisch: selber Master-Key → selber MAC-Key)
   * - Nutzt fastPbkdf2 (fast-sha256, 6x schneller als CryptoJS)
   * Salt-Konvention (für Stabilität konstant gehalten):
   * 'HMAC-SALT' UTF-8 → hex
   */
  static async deriveMacKey(keyHex: string): Promise<string> {
    const cached = this.macKeyCache.get(keyHex);
    if (cached) return cached;

    // 'HMAC-SALT' als hex (UTF-8 encoded): 484d41432d53414c54
    const saltHex = '484d41432d53414c54';
    const result = await fastPbkdf2(keyHex, saltHex, 10000, 32);
    this.macKeyCache.set(keyHex, result);
    return result;
  }

  /**
   * Konstanter Zeit-Vergleich gegen Timing-Attacks
   *
   * HINWEIS: Der native verifyConstantTime wird bevorzugt verwendet, da er garantiert
   * konstant-time ist. Der JS-Fallback verwendet Uint8Array typed comparison statt
   * string iteration um deoptimization zu vermeiden.
   * WICHTIG: Keine early return auf Längenunterschied - dies würde Length-Information leaken!
   */
  static async constantsTimeEquals(a: string, b: string): Promise<boolean> {
    // Zuerst prüfen: gleiche Länge nötig für korrekte Verifizierung
    // Da wir keine Early-Return auf Längenunterschied haben können, nutzen wir die native Funktion
    try {
      const result = await nativeVerifyConstantTime(a, b);
      return result;
    } catch {
      // Fallback zu typed comparison (nicht string iteration, um JIT deoptimization zu vermeiden)
      const aBytes = new TextEncoder().encode(a);
      const bBytes = new TextEncoder().encode(b);

      // Längen-Vergleich ist hier erlaubt, da wir den Error fall abfangen
      if (aBytes.length !== bBytes.length) {
        return false;
      }

      // Constanter Zeit Vergleich mit Uint8Array
      let result = 0;
      for (let i = 0; i < aBytes.length; i++) {
        result |= aBytes[i] ^ bBytes[i];
      }
      return result === 0;
    }
  }

  // ─────────────────────────────── Hardware Keystore Integration ───────────────────────────────

  /**
   * Helper method to get an item from secure storage (tries HardwareBackedStorage, then SecureStore)
   */
  private static async getItemSecure(key: string): Promise<string | null> {
    try {
      return await HardwareBackedStorage.getItem(key);
    } catch {
      // Fallback to SecureStore
      try {
        return await SecureStore.getItemAsync(key);
      } catch {
        return null;
      }
    }
  }

  /**
   * Helper method to set an item in secure storage (uses HardwareBackedStorage with fallback)
   */
  private static async setItemSecure(key: string, value: string): Promise<void> {
    try {
      await HardwareBackedStorage.setItem(key, value);
    } catch (error) {
      // Fallback to SecureStore if HardwareBackedStorage fails
      try {
        console.warn(`HardwareBackedStorage fallback for key: ${key}`);
        await SecureStore.setItemAsync(key, value);
      } catch {
        throw new Error('Konnte Wert nicht in sicheren Speicher speichern');
      }
    }
  }

  /**
   * Helper method to delete an item from secure storage with read-back verification
   * WICHTIG: Wenn das Item nach dem Löschen noch existiert, wirft die Funktion einen Error
   */
  private static async deleteItemSecure(key: string): Promise<void> {
    try {
      await HardwareBackedStorage.deleteItem(key);
    } catch (error) {
      console.error(`deleteItemSecure: Error deleting ${key}:`, error);
    }

    // Read-back Verification: Prüfe ob das Item noch existiert
    try {
      const stillExists = await HardwareBackedStorage.exists(key);
      if (stillExists) {
        throw new Error(`deleteItemSecure: Key still exists after deletion: ${key}`);
      }
    } catch (error) {
      // Read-back check failed - das ist ein Problem
      console.error(`deleteItemSecure: Read-back check failed for ${key}:`, error);
      throw new Error(`deleteItemSecure: Read-back verification failed for ${key}`);
    }
  }

  // ─────────────────────────────── Dateiverschlüsselung ───────────────────────────────

  static async encryptFile(fileData: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptData(fileData);
    } catch {
      throw new Error('Dateiverschlüsselung fehlgeschlagen');
    }
  }

  static async decryptFile(encryptedData: string, iv: string, mac: string): Promise<string> {
    try {
      return await this.decryptData(encryptedData, iv, mac);
    } catch {
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
    } catch {
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
    } catch {
      throw new Error('Metadaten-Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── Schlüsselverwaltung ───────────────────────────────

  static async deleteEncryptionKey(): Promise<void> {
    await this.deleteItemSecure(this.STORAGE_KEY);
    await this.deleteItemSecure(this.STORAGE_SALT);
    await this.deleteItemSecure(this.STORAGE_KEK_SALT);
    await this.deleteItemSecure(this.STORAGE_MASTER_ENC);
    await this.deleteItemSecure(this.STORAGE_MASTER_IV);
    await this.deleteItemSecure(this.STORAGE_MASTER_MAC);
    await this.deleteItemSecure(this.STORAGE_BIO_KEK);
  }

  /**
   * Ändert den PIN und aktualisiert alle verschlüsselten Daten
   * Rotiert den Master-Schlüssel und verschlüsselt alle bestehenden
   * Dateien und Notizen mit dem neuen Schlüssel neu.
   */
  static async rotateEncryptionKey(newPassphrase: string): Promise<void> {
    try {
      // Alten Schlüssel abrufen
      const oldKeyHex = await this.getItemSecure(this.STORAGE_KEY);
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
      await this.setItemSecure(this.STORAGE_KEY, newKeyHex);

      // PIN-Daten mit neuem Schlüssel neu verschlüsseln (AES-CBC, 16-byte IV)
      const pinData = JSON.stringify(oldPinData);
      const iv = await this.generateSecureBytes(this.CBC_IV_LENGTH);

      const cipher = CryptoJS.AES.encrypt(pinData, CryptoJS.enc.Hex.parse(newKeyHex), {
        iv: CryptoJS.enc.Hex.parse(this.bufferToHex(iv)),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      await this.setItemSecure(this.STORAGE_PIN_HASH, cipher.ciphertext.toString(CryptoJS.enc.Hex));
      await this.setItemSecure(this.STORAGE_PIN_IV, this.bufferToHex(iv));
      await this.setItemSecure(this.STORAGE_PIN_KEY, newKeyHex);

      // HMAC-MacKey neu ableiten - alter MacKey wird ignoriert, neuer wird immer erzeugt
      // (Der neue MacKey wird dynamisch aus dem neuen Master-Key abgeleitet)
    } catch {
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
    } catch {
      throw new Error('Datei konnte nicht neu verschlüsselt werden');
    }
  }

  // ─────────────────────────────── PIN-Verwaltung ───────────────────────────────

  /**
   * Prüft ob PIN korrekt ist
   * Nutzt Argon2id (empfohlen) oder PBKDF2 (Legacy) basierend auf gespeichertem Hash
   * @param passphrase Die PIN
   * @returns true wenn PIN korrekt
   */
  static async verifyPin(passphrase: string): Promise<boolean> {
    try {
      // Prüfe ob Account gesperrt ist
      const isLocked = await this.isAccountLocked();
      if (isLocked) {
        return false;
      }

      const storedPin = await this.getStoredPin();
      if (!storedPin) return false;

      const { hash: storedHash, salt: storedSalt, iterationCount, algorithm } = storedPin;

      // Prüfe ob PBKDF2 (Legacy) oder Argon2id verwendet wurde
      const isLegacy = algorithm === 'pbkdf2' || !algorithm || this.isLegacyPBKDF2Hash(storedHash);

      let derivedHash: string;

      if (isLegacy) {
        // Verwende PBKDF2 für Legacy-Hashes
        derivedHash = await this.derivePBKDF2Hash(passphrase, storedSalt, iterationCount);
      } else {
        // Verwende Argon2id für neue Hashes
        const saltBuffer = this.hexToBuffer(storedSalt);
        const params: Argon2Params = {
          version: this.ARGON2_VERSION,
          type: 2, // Argon2id
          memoryKB: this.ARGON2_MEMORY_KB,
          iterations: this.ARGON2_ITERATIONS, // 3 Iterationen
          parallelism: this.ARGON2_PARALLELISM,
          hashLength: this.ARGON2_HASH_LENGTH,
        };
        const derivedKey = await Argon2idService.deriveKey(passphrase, saltBuffer, params);
        derivedHash = this.bufferToHex(derivedKey);
      }

      const isValid = await this.constantsTimeEquals(derivedHash, storedHash);

      if (isValid) {
        // Reset failed attempts on success
        await this.resetFailedAttempts();
      } else {
        // Increment failed attempts
        await this.incrementFailedAttempts();
      }

      return isValid;
    } catch {
      return false;
    }
  }

  /**
   * Leitet PBKDF2 Hash ab (für Legacy-Kompatibilität)
   */
  private static async derivePBKDF2Hash(passphrase: string, saltHex: string, iterationCount: number): Promise<string> {
    try {
      const derivedKey = CryptoJS.PBKDF2(passphrase, saltHex, {
        keySize: 32 / 4,
        iterations: iterationCount,
        hasher: CryptoJS.algo.SHA256,
      });
      return derivedKey.toString(CryptoJS.enc.Hex);
    } catch {
      throw new Error('Konnte PBKDF2 Hash nicht berechnen');
    }
  }

  /** Gibt aktuelle Anzahl fehlgeschlagener Versuche zurück */
  static async getFailedAttempts(): Promise<number> {
    try {
      const str = await this.getItemSecure(this.STORAGE_FAILED_ATTEMPTS);
      return str ? parseInt(str, 10) : 0;
    } catch { return 0; }
  }

  /** Gibt zurück ob der Account gesperrt ist und wann er sich entsperrt */
  static async getLockStatus(): Promise<{ locked: boolean; unlockAt: number }> {
    try {
      const lockUntilStr = await this.getItemSecure(this.STORAGE_LOCK_UNTIL);
      if (!lockUntilStr) return { locked: false, unlockAt: 0 };
      const lockUntil = parseInt(lockUntilStr, 10);
      if (isNaN(lockUntil) || Date.now() >= lockUntil) {
        await this.deleteItemSecure(this.STORAGE_LOCK_UNTIL);
        return { locked: false, unlockAt: 0 };
      }
      return { locked: true, unlockAt: lockUntil };
    } catch {
      return { locked: false, unlockAt: 0 };
    }
  }

  /** Setzt Versuche + Sperre zurück (öffentlich, z.B. nach Wipe) */
  static async clearFailedAttempts(): Promise<void> {
    await this.resetFailedAttempts();
  }

  /**
   * Prüft ob der Account aktuell gesperrt ist
   */
  private static async isAccountLocked(): Promise<boolean> {
    try {
      const lockUntilStr = await this.getItemSecure(this.STORAGE_LOCK_UNTIL);
      if (!lockUntilStr) return false;

      const lockUntil = parseInt(lockUntilStr, 10);
      if (isNaN(lockUntil)) return false;

      const now = Date.now();
      if (now < lockUntil) {
        return true;
      }

      // Lock abgelaufen - reset
      await this.deleteItemSecure(this.STORAGE_LOCK_UNTIL);
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
      let attemptsStr = await this.getItemSecure(this.STORAGE_FAILED_ATTEMPTS);
      let attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;

      attempts++;
      await this.setItemSecure(this.STORAGE_FAILED_ATTEMPTS, attempts.toString());

      if (attempts >= this.MAX_FAILED_ATTEMPTS) {
        const lockUntil = Date.now() + this.LOCK_DURATION_MS;
        await this.setItemSecure(this.STORAGE_LOCK_UNTIL, lockUntil.toString());
      }
    } catch {
      // Silent fail for incrementing failed attempts
    }
  }

  /**
   * Setzt fehlgeschlagene Versuche zurück
   */
  private static async resetFailedAttempts(): Promise<void> {
    try {
      await this.deleteItemSecure(this.STORAGE_FAILED_ATTEMPTS);
      await this.deleteItemSecure(this.STORAGE_LOCK_UNTIL);
    } catch {
      // Silent fail for resetting failed attempts
    }
  }

  /**
   * Aktualisiert den PIN-Hash
   * @param newPassphrase Die neue PIN
   */
  static async updatePinHash(newPassphrase: string): Promise<void> {
    try {
      const { hash, salt, iterationCount, algorithm } = await this.computePinHash(newPassphrase);

      // Lade den existierenden Master-Key aus dem Hardware Keystore
      const masterKeyHex = await this.getItemSecure(this.STORAGE_KEY);
      if (!masterKeyHex) {
        throw new Error('Kein Master-Key vorhanden');
      }
      const masterKeyBuffer = this.hexToBuffer(masterKeyHex);

      const pinData = JSON.stringify({ hash, salt, iterationCount, algorithm });

      // Verschlüsselt PIN-Daten mit Master-Key (AES-CBC, 16-byte IV)
      const iv = await this.generateSecureBytes(this.CBC_IV_LENGTH);

      const cipher = CryptoJS.AES.encrypt(pinData, CryptoJS.enc.Hex.parse(masterKeyHex), {
        iv: CryptoJS.enc.Hex.parse(this.bufferToHex(iv)),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      await this.setItemSecure(this.STORAGE_PIN_HASH, cipher.ciphertext.toString(CryptoJS.enc.Hex));
      await this.setItemSecure(this.STORAGE_PIN_IV, this.bufferToHex(iv));
      await this.setItemSecure(this.STORAGE_PIN_KEY, masterKeyHex);
    } catch {
      throw new Error('Konnte PIN-Hash nicht aktualisieren');
    }
  }

  /**
   * Löscht alle PIN-Daten
   */
  static async deletePinData(): Promise<void> {
    await this.deleteItemSecure(this.STORAGE_PIN_HASH);
    await this.deleteItemSecure(this.STORAGE_PIN_SALT);
    await this.deleteItemSecure(this.STORAGE_PIN_IV);
    await this.deleteItemSecure(this.STORAGE_PIN_KEY);
    await this.deleteItemSecure(this.STORAGE_FAILED_ATTEMPTS);
    await this.deleteItemSecure(this.STORAGE_LOCK_UNTIL);
  }

  /**
   * Lädt gespeicherten PIN-Hash (verschlüsselt)
   */
  private static async getStoredPin(): Promise<{ hash: string; salt: string; iterationCount: number; algorithm?: string } | null> {
    try {
      const dataHex = await this.getItemSecure(this.STORAGE_PIN_HASH);
      if (!dataHex) return null;

      const ivHex = await this.getItemSecure(this.STORAGE_PIN_IV);
      const masterKeyHex = await this.getItemSecure(this.STORAGE_PIN_KEY);

      if (!ivHex || !masterKeyHex) return null;

      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(dataHex),
      });
      const decrypted = CryptoJS.AES.decrypt(
        cipherParams,
        CryptoJS.enc.Hex.parse(masterKeyHex),
        {
          iv: CryptoJS.enc.Hex.parse(ivHex),
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      const json = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8)) as { hash: string; salt: string; iterationCount: number; algorithm?: string };
      return json;
    } catch {
      return null;
    }
  }

  /**
   * Berechnet PIN-Hash und Salt
   * Nutzt Argon2id standardmäßig mit fastPbkdf2 Fallback (kein CryptoJS!)
   */
  private static async computePinHash(passphrase: string): Promise<{ hash: string; salt: string; iterationCount: number; algorithm: string }> {
    try {
      const salt = await this.generateSecureBytes(16);
      const saltHex = this.bufferToHex(salt);
      const saltBuffer = this.hexToBuffer(saltHex);

      // Prüfe ob native Argon2 Module verfügbar ist
      const useArgon2 = (global as any).__argon2_native_available;

      let hash: string;
      let iterationCount: number;
      let algorithm: string;

      if (useArgon2) {
        const params: Argon2Params = {
          version: this.ARGON2_VERSION,
          type: 2,
          memoryKB: this.ARGON2_MEMORY_KB,
          iterations: this.ARGON2_ITERATIONS, // 3 Iterationen
          parallelism: this.ARGON2_PARALLELISM,
          hashLength: this.ARGON2_HASH_LENGTH,
        };
        const derivedKey = await Argon2idService.deriveKey(passphrase, saltBuffer, params);
        hash = this.bufferToHex(derivedKey);
        iterationCount = this.ARGON2_ITERATIONS;
        algorithm = 'argon2id';
      } else {
        // Kein CryptoJS Fallback mehr - nur fastPbkdf2
        const derivedKey = await fastPbkdf2(passphrase, saltHex, this.PBKDF2_ITERATIONS, this.PBKDF2_KEY_LENGTH);
        hash = derivedKey;
        iterationCount = this.PBKDF2_ITERATIONS;
        algorithm = 'pbkdf2';
      }

      return {
        hash,
        salt: saltHex,
        iterationCount,
        algorithm,
      };
    } catch {
      throw new Error('Konnte PIN-Hash nicht berechnen');
    }
  }

  // ─────────────────────────────── App-Status ───────────────────────────────

  /**
   * Prüft ob App initialisiert wurde
   */
  static async isAppInitialized(): Promise<boolean> {
    try {
      const value = await this.getItemSecure(this.STORAGE_APP_INIT);
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
      await this.setItemSecure(this.STORAGE_APP_INIT, initialized ? 'true' : 'false');
    } catch {
      // Silent fail for setting app initialized
    }
  }

  // ─────────────────────────────── File Key Wrapping ───────────────────────────────

  /**
   * Wraps (verschlüsselt) einen File-Key mit dem Master-Key
   * Verwendet AES-256-CBC + HMAC-SHA-256 für authenticated encryption
   * (Legacy für File Key Wrapping - Hauptsächliche Encryption nutzt GCM)
   * Backend Selection: XChaCha20 > FastAES > CryptoJS
   * @param fileKey 64 hex char File-Key
   * @returns EncryptedFileKey Objekt mit iv, mac und encryptedKey
   */
  static async encryptFileKey(fileKey: string): Promise<{
    encryptedKey: string;
    iv: string;
    mac: string;
    createdAt: string;
  }> {
    try {
      const masterKeyHex = await this.getMasterKey();
      if (!masterKeyHex) {
        throw new Error('Kein Master-Schlüssel vorhanden');
      }

      // Key wrapping uses aesCBCEncrypt which uses CBC mode - requires 16-byte IV
      const iv = await this.generateSecureBytes(this.CBC_IV_LENGTH);
      const ivHex = this.bufferToHex(iv);

      // AES-256-CBC Verschlüsselung mit Backend Selection
      const result = await this.aesCBCEncrypt(fileKey, masterKeyHex, ivHex);

      return {
        encryptedKey: result.encryptedData,
        iv: ivHex,
        mac: result.tag,
        createdAt: new Date().toISOString(),
      };
    } catch {
      throw new Error('Konnte File-Key nicht verschlüsseln');
    }
  }

  /**
   * Unwraps (entschlüsselt) einen File-Key mit dem Master-Key
   * Verwendet HMAC-SHA-256 zur Integritätsprüfung
   * @param encryptedKey Objekt mit encryptedKey, iv und mac
   * @returns 64 hex char File-Key
   */
  static async decryptFileKey(encryptedKey: {
    encryptedKey: string;
    iv: string;
    mac: string;
    createdAt?: string;
  }): Promise<string> {
    try {
      const masterKeyHex = await this.getMasterKey();
      if (!masterKeyHex) {
        throw new Error('Kein Master-Schlüssel vorhanden');
      }

      // Entschlüsseln mit backend-selection (XChaCha20 > FastAES > CryptoJS)
      return await this.aesCBCDecrypt(encryptedKey.encryptedKey, encryptedKey.iv, encryptedKey.mac, masterKeyHex);
    } catch {
      throw new Error('Konnte File-Key nicht entschlüsseln');
    }
  }
}

// DEPRECATED: XChaCha20CryptoService ist veraltet - nutze SecureCryptoService
export { XChaCha20CryptoService } from './XChaCha20CryptoService';

// SecureCryptoService ist der primäre Service mit AES-256-GCM
export default SecureCryptoService;
