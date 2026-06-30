import * as SecureStore from 'expo-secure-store';
import * as CryptoModule from 'expo-crypto';
import { NativeModules } from 'react-native';
import CryptoJS from 'crypto-js';
import { Argon2idService, Argon2Params } from './Argon2idService';
import { HardwareBackedStorage } from './HardwareKeystoreService';
import { fastPbkdf2, hkdfSha256, isNobleAvailable } from './FastPBKDF2';
import { aesCbcEncryptRaw, aesCbcDecryptRaw } from './AesCbcHmac';
import { keyCustody } from './KeyCustody';
// XChaCha20-Poly1305 native Module (erstellt bei ADB-Test)
// Import aus ../native da dieser Service in src/services liegt
import { encrypt as xchachaEncrypt, decrypt as xchachaDecrypt, verifyConstantTime as nativeVerifyConstantTime } from '../native/RNFileVault';

/**
 * SecureCryptoService - Authenticated Encryption mit XChaCha20-Poly1305 primary
 *
 * Sicherheitsmerkmale:
 * - Kryptographisch sicherer Zufallsgenerator (expo-crypto)
 * - XChaCha20-Poly1305 primary (native Module via RNFileVault)
 * - AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) als erster Fallback
 * - AES-256-CBC + HMAC mit CryptoJS ist LAST RESORT (Legacy-Lesepfad, Backend 0x03)
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
const BACKEND_AESCBCHMAC = 0x02; // AES-256-CBC + HMAC-SHA256 (pure-JS fallback, formerly "FastAES")
const BACKEND_CRYPTOJS = 0x03; // CryptoJS (last resort, not recommended)

/**
 * Extracts backend identifier from ciphertext header
 * First byte of decrypted data is the backend ID
 */
const extractBackendFromHeader = (encryptedData: string): 'xchacha' | 'aescbchmac' | 'cryptojs' => {
  try {
    const header = parseInt(encryptedData.substring(0, 2), 16);
    switch (header) {
      case BACKEND_XCHACHA:
        return 'xchacha';
      case BACKEND_AESCBCHMAC:
        return 'aescbchmac';
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

// AES-CBC+HMAC (CryptoJS) is always available since it is a static import.
// The old canUseFastAES check was typeof fastAesEncrypt === 'function' which is
// trivially always true. Simplified to a constant.
const canUseAesCbcHmac = (): boolean => true;

// ──────────────────────────────────────────────────────────────────────────────
// S3: JS-only crypto fallback policy (content write path)
// ──────────────────────────────────────────────────────────────────────────────
//
// getEncryptionBackend() picks XChaCha20-Poly1305 (native libsodium) when the native
// module is present, else the pure-JS AES-256-CBC+HMAC fallback (backend 0x02). An
// attacker who strips or blocks the native module would otherwise SILENTLY downgrade
// every NEW content write to JS crypto (no constant-time guarantees, much larger trusted
// JS surface). S3 forbids that silent downgrade.
//
// Policy — a non-XChaCha backend may be used to WRITE content only if:
//   - running under Jest (NODE_ENV==='test') — no native module exists there and the JS
//     fallback is itself the unit under test; OR
//   - a developer has explicitly opted in via `global.__filevault_allow_js_crypto = true`
//     (e.g. Expo Go / a dev build without the native module) — logged loudly, once.
// Otherwise the write THROWS. The READ path for existing 0x02/0x03 blobs is never gated
// (backward compatibility). Key-wrapping (aesCBCEncrypt) is a separate, by-design
// AES-CBC path and is intentionally NOT affected.
const jsCryptoWriteAllowed = (): boolean => {
  try {
    if (typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'test') {
      return true;
    }
  } catch { /* process not available — fall through */ }
  return (global as any).__filevault_allow_js_crypto === true;
};

let _jsCryptoDowngradeWarned = false;
const warnJsCryptoDowngradeOnce = (): void => {
  if (_jsCryptoDowngradeWarned) return;
  _jsCryptoDowngradeWarned = true;
  console.warn(
    '[crypto][S3] Native crypto module unavailable — writing content with the pure-JS ' +
    'AES-256-CBC+HMAC fallback (backend 0x02). This is an EXPLICITLY ENABLED downgrade ' +
    '(__filevault_allow_js_crypto or test env). Do NOT ship a production release in this state.'
  );
};

// ──────────────────────────────────────────────────────────────────────────────

export class SecureCryptoService {
  private static readonly STORAGE_KEY = 'filevault_encryption_key';
  private static readonly STORAGE_SALT = 'filevault_pbkdf2_salt';
  private static readonly STORAGE_ARGON2_SALT = 'filevault_argon2id_salt';
  // IV/Nonce lengths - different for different encryption modes
  // XChaCha20-Poly1305 requires 24-byte (192-bit) nonce
  private static readonly XCHACHA_NONCE_LENGTH = 24;
  // AES-CBC requires 16-byte (128-bit) IV
  private static readonly CBC_IV_LENGTH = 16;
  private static readonly PBKDF2_ITERATIONS = 600000; // NIST SP 800-132 §5.3 (2023)
  private static readonly PBKDF2_KEY_LENGTH = 32;

  // Argon2id configuration - erhöht von 2 auf 3 Iterationen
  private static readonly ARGON2_MEMORY_KB = 65536; // 64 MB
  private static readonly ARGON2_ITERATIONS = 3; // Erhöht von 2
  // C1: p=1 — native libsodium crypto_pwhash forces lanes=1; fallback must match.
  private static readonly ARGON2_PARALLELISM = 1;
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
  // C1: records how the KEK salt is fed to the KDF, so a future encoding change
  // can be detected instead of silently deriving a wrong (divergent) KEK.
  private static readonly STORAGE_KDF_META = 'filevault_kdf_meta';
  private static readonly KDF_META_CURRENT = JSON.stringify({ kdf: 'argon2id', version: 1, saltEncoding: 'raw' });
  private static readonly STORAGE_MASTER_ENC = 'filevault_master_enc';
  private static readonly STORAGE_MASTER_IV = 'filevault_master_iv';
  private static readonly STORAGE_MASTER_MAC = 'filevault_master_mac';
  private static readonly STORAGE_BIO_KEK = 'filevault_bio_kek';
  private static readonly LOCK_DURATION_MS = 300000; // 5 Minuten

  // ─────────────────────────────── Encoding Utility Functions ───────────────────────────────

  /**
   * Konvertiert ArrayBuffer zu Hex-String
   */
  static bufferToHex(buffer: ArrayBuffer): string {
    // O(n) via array-join. The previous `hex += ...` per byte is O(n^2) in Hermes and
    // HANGS on tens-of-KB inputs (surfaced by L6 decoy content). Output is byte-identical.
    const bytes = new Uint8Array(buffer);
    const out = new Array<string>(bytes.byteLength);
    for (let i = 0; i < bytes.byteLength; i++) {
      out[i] = (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out.join('');
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
   * UTF-8-safe Base64-Kodierung eines Strings.
   *
   * WICHTIG: `btoa(str)` interpretiert jedes Zeichen als einzelnes Latin1-Byte
   * und wirft für Code Points > 0xFF (Emoji, CJK, Kyrillisch …). Für die
   * XChaCha20-Brücke (native Module erwartet Base64 der Klartext-Bytes) müssen
   * wir den String zuerst als UTF-8 in Bytes kodieren. Andernfalls schlägt die
   * Verschlüsselung von Notizen mit Nicht-Latin1-Zeichen auf dem Gerät fehl.
   */
  private static utf8ToBase64(str: string): string {
    // O(n) chunked. Per-byte `binary += String.fromCharCode(...)` is O(n^2) in Hermes and
    // HANGS on tens-of-KB inputs (surfaced by L6 decoy content). Output is byte-identical.
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
    }
    return btoa(binary);
  }

  /**
   * UTF-8-Bytes eines Strings als Hex. Für H2: bindet einen Kontext (fileId:role,
   * noteId:role) als Additional Authenticated Data in den Auth-Tag, damit Blobs
   * nicht zwischen Objekten/Rollen vertauscht werden können.
   */
  private static utf8ToHex(s: string): string {
    // O(n) via array-join (same identical-output rationale as bufferToHex).
    const bytes = new TextEncoder().encode(s);
    const out = new Array<string>(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      out[i] = (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out.join('');
  }

  /**
   * Symmetrischer Gegenpart zu utf8ToBase64: Base64 → UTF-8-String.
   */
  private static base64ToUtf8(b64: string): string {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }

  /**
   * Generiert kryptographisch sichere Zufallsbytes
   */
  static async generateSecureBytes(length: number): Promise<ArrayBuffer> {
    const result = await CryptoModule.getRandomBytesAsync(length);
    // Slice to exact bytes: on Hermes, result.buffer may be a pooled ArrayBuffer
    // larger than result.byteLength, causing bufferToHex to produce an oversized
    // hex string and aes-js to throw "invalid initialization vector size".
    return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength) as ArrayBuffer;
  }

  /**
   * Legacy AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) mit CryptoJS — Backend 0x03.
   * NICHT GCM (der alte Name "cryptoJSGCM*" war irreführend): es ist AES-CBC + HMAC.
   * Reiner JS-Pfad, LAST RESORT. Im aktiven Schreibpfad tot (0x02 ist immer verfügbar) —
   * nur als Lesepfad für historische 0x03-Altdaten erhalten. CryptoJS ist sehr langsam.
   */
  private static async legacyCryptoJsCbcHmacEncrypt(
    data: string,
    keyHex: string,
    ivHex: string,
    aadHex: string = ''
  ): Promise<{ encryptedData: string; tag: string }> {
    try {
      const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
      const ivBytes = CryptoJS.enc.Hex.parse(ivHex);

      // AES-256-CBC + Encrypt-then-MAC (kein GCM).
      const cipher = CryptoJS.AES.encrypt(data, keyBytes, {
        iv: ivBytes,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const encryptedHex = cipher.ciphertext.toString(CryptoJS.enc.Hex);

      // HMAC-SHA-256 (Encrypt-then-MAC). W-03: aadHex (backend prefix) bound in.
      const macKey = await this.deriveMacKey(keyHex);
      const mac = await this.computeMac(macKey, aadHex + ivHex + encryptedHex);

      return {
        encryptedData: encryptedHex,
        tag: mac,
      };
    } catch {
      throw new Error('AES-CBC+HMAC (CryptoJS Legacy) Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Legacy AES-256-CBC + HMAC-SHA256 Entschlüsselung mit CryptoJS — Backend-0x03-Lesepfad.
   */
  private static async legacyCryptoJsCbcHmacDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string,
    aadHex: string = ''
  ): Promise<string> {
    try {
      const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
      const ivBytes = CryptoJS.enc.Hex.parse(ivHex);

      // Verifiziere HMAC BEFORE decryption. W-03: aadHex (backend prefix) bound in.
      const macKey = await this.deriveMacKey(keyHex);
      const expectedMac = await this.computeMac(macKey, aadHex + ivHex + encryptedData);

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
      throw new Error('AES-CBC+HMAC (CryptoJS Legacy) Entschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── AES-CBC Helper (für Key Wrapping) ───────────────────────────────

  /**
   * AES-256-CBC Verschlüsselung mit ausgewähltem Backend
   * Wird für Key Wrapping (KEK, File-Key) verwendet
   */
  // Key wrapping ALWAYS uses AES-256-CBC — never XChaCha20.
  // XChaCha20 requires a 24-byte nonce; key wrapping uses a 16-byte IV for CBC.
  // Dispatching to XChaCha20 here would cause "Nonce must be 24 bytes (got 16)".
  private static async aesCBCEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    return await this.aesCbcHmacWrapEncrypt(data, keyHex, ivHex);
  }

  // Key unwrapping mirrors aesCBCEncrypt: always AES-256-CBC, no silent fallback.
  private static async aesCBCDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    return await this.aesCbcHmacWrapDecrypt(encryptedData, ivHex, tag, keyHex);
  }

  // ─── AES-256-CBC + HMAC Implementierung (für Key Wrapping) ───

  private static async aesCbcHmacWrapEncrypt(
    data: string,
    keyHex: string,
    ivHex: string
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseAesCbcHmac()) {
      throw new Error('AES-CBC+HMAC nicht verfügbar');
    }
    const result = await aesCbcEncryptRaw(data, keyHex, ivHex);
    const macKey = await this.deriveMacKey(keyHex);
    const mac = await this.computeMac(macKey, ivHex + result);
    return { encryptedData: result, tag: mac };
  }

  private static async aesCbcHmacWrapDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string
  ): Promise<string> {
    if (!canUseAesCbcHmac()) {
      throw new Error('AES-CBC+HMAC nicht verfügbar');
    }
    const macKey = await this.deriveMacKey(keyHex);
    const expectedMac = await this.computeMac(macKey, ivHex + encryptedData);
    if (!await this.constantsTimeEquals(expectedMac, tag)) {
      throw new Error('Integritätsprüfung fehlgeschlagen');
    }
    return await aesCbcDecryptRaw(encryptedData, keyHex, ivHex);
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
    nonceHex: string,
    aadHex: string = ''
  ): Promise<{ encrypted: string; tag: string }> {
    const result = await this.xchacha20Encrypt(data, keyHex, nonceHex, aadHex);
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
    keyHex: string,
    aadHex: string = ''
  ): Promise<string> {
    return await this.xchacha20Decrypt(encryptedData, nonceHex, tag, keyHex, aadHex);
  }

  private static async xchacha20Encrypt(
    data: string,
    keyHex: string,
    ivHex: string,
    aadHex: string = ''
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 nicht verfügbar');
    }
    const dataB64 = this.utf8ToBase64(data);
    // W-03: aadHex (backend prefix) bound into the Poly1305 tag as AAD.
    const result = await xchachaEncrypt(dataB64, keyHex, ivHex, aadHex || undefined);
    return { encryptedData: result.encrypted, tag: result.tag };
  }

  private static async xchacha20Decrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string,
    aadHex: string = ''
  ): Promise<string> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 nicht verfügbar');
    }
    const result = await xchachaDecrypt(encryptedData, ivHex, tag, keyHex, aadHex || undefined);
    return this.base64ToUtf8(result);
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

  // ─────────────────────────────── AES-256-CBC + HMAC Backend (First Fallback) ───────────────────────────────

  /**
   * AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) content encryption.
   * First fallback after native XChaCha20-Poly1305 (backend prefix 0x02).
   * Formerly named fastAESGCMEncrypt — it is NOT GCM; the "GCM" label was wrong.
   */
  private static async aesCbcHmacEncrypt(
    data: string,
    keyHex: string,
    ivHex: string,
    aadHex: string = ''
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseAesCbcHmac()) {
      throw new Error('AES-CBC+HMAC nicht verfügbar');
    }

    try {
      // AES-256-CBC ciphertext, authenticated separately via Encrypt-then-MAC.
      const result = await aesCbcEncryptRaw(data, keyHex, ivHex);

      // HMAC-SHA-256 (Encrypt-then-MAC). W-03: aadHex (the unauthenticated backend
      // prefix byte) is bound into the MAC so a flipped prefix is detected.
      const macKey = await this.deriveMacKey(keyHex);
      const mac = await this.computeMac(macKey, aadHex + ivHex + result);

      return {
        encryptedData: result,
        tag: mac,
      };
    } catch (error) {
      console.warn('[AES-CBC+HMAC] encryption failed:', error);
      throw error;
    }
  }

  /**
   * AES-256-CBC + HMAC-SHA256 content decryption (verifies the MAC first).
   * Formerly named fastAESGCMDecrypt.
   */
  private static async aesCbcHmacDecrypt(
    encryptedData: string,
    ivHex: string,
    tag: string,
    keyHex: string,
    aadHex: string = ''
  ): Promise<string> {
    if (!canUseAesCbcHmac()) {
      throw new Error('AES-CBC+HMAC nicht verfügbar');
    }

    try {
      // Verifiziere HMAC BEFORE decryption. W-03: aadHex (backend prefix) is part of
      // the MAC input — a flipped prefix produces a different tag and is rejected.
      const macKey = await this.deriveMacKey(keyHex);
      const expectedMac = await this.computeMac(macKey, aadHex + ivHex + encryptedData);

      if (!await this.constantsTimeEquals(expectedMac, tag)) {
        throw new Error('Integritätsprüfung fehlgeschlagen - Daten manipuliert');
      }

      const result = await aesCbcDecryptRaw(encryptedData, keyHex, ivHex);
      return result;
    } catch (error) {
      console.warn('[AES-CBC+HMAC] decryption failed:', error);
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
    nonceHex: string,
    aadHex: string = ''
  ): Promise<{ encryptedData: string; tag: string }> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 native Module nicht verfügbar');
    }

    try {
      // XChaCha20 erwartet base64-kodierte Daten (UTF-8-sicher, siehe utf8ToBase64)
      const dataB64 = this.utf8ToBase64(data);

      const result = await xchachaEncrypt(dataB64, keyHex, nonceHex, aadHex || undefined);

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
    keyHex: string,
    aadHex: string = ''
  ): Promise<string> {
    if (!canUseXChaCha20()) {
      throw new Error('XChaCha20 native Module nicht verfügbar');
    }

    try {
      const result = await xchachaDecrypt(encryptedData, nonceHex, tag, keyHex, aadHex || undefined);

      return this.base64ToUtf8(result);
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
   * Prüft ob der AES-CBC+HMAC Fallback verfügbar ist
   * Wird von BackupService extern verwendet
   */
  static canUseAesCbcHmac(): boolean {
    return canUseAesCbcHmac();
  }

  /**
   * Wählt das beste verfügbare Encryption Backend
   * Priorität: XChaCha20 > AES-CBC+HMAC > CryptoJS
   *
   * Backend-Trace für encryptData():
   * 1. canUseXChaCha20() prüft NativeModules.RNFileVault
   *    - Wenn true → XChaCha20 wird verwendet (24-byte nonce)
   *    - Wenn false → prüfe AES-CBC+HMAC
   * 2. canUseAesCbcHmac() ist konstant true (CryptoJS statisch importiert)
   *    - Wenn true → AES-256-CBC + HMAC Fallback wird verwendet
   *    - Wenn false → falle zu CryptoJS zurück
   * 3. CryptoJS ist der LAST RESORT Fallback
   *
   * WICHTIG: Durch die canUseXChaCha20()-Fix mit NativeModules.RNFileVault prüfung
   * sind nun der AES-CBC+HMAC-Fallback und CryptoJS erreichbar, wenn das native Module
   * nicht geladen ist.
   */
  private static getEncryptionBackend(): 'xchacha' | 'aescbchmac' | 'cryptojs' {
    if (canUseXChaCha20()) {
      return 'xchacha';
    }
    if (canUseAesCbcHmac()) {
      return 'aescbchmac';
    }
    return 'cryptojs';
  }

  /**
   * Wählt das beste verfügbare Decryption Backend basierend auf Datenformat
   * Priorität: XChaCha20 > AES-CBC+HMAC > CryptoJS
   */
  private static getDecryptionBackend(encryptedData: string): 'xchacha' | 'aescbchmac' | 'cryptojs' {
    // Wenn wir die Daten selbst verschlüsselt haben, wissen wir das Backend
    // Andernfalls versuchen wir XChaCha20 first, dann AES-CBC+HMAC, dann CryptoJS
    if (canUseXChaCha20()) {
      return 'xchacha';
    }
    if (canUseAesCbcHmac()) {
      return 'aescbchmac';
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
   * L3 Phase 2: REMOVED. The raw master key is never handed back to JS as a value — all
   * crypto runs through an opaque custody handle (see KeyCustody). Kept as a hard throw so
   * any stale caller fails loudly instead of silently receiving a raw key.
   *
   * Production callers were rewired to the handle path:
   *   - content:   encryptData / decryptData (use the live master handle internally)
   *   - file keys: encryptFileKey / decryptFileKey, encryptFileKeyWith(handle) / decryptFileKeyWith(handle)
   *   - rotation:  KeyRotationService threads old/new handles
   */
  static async getMasterKey(): Promise<string | null> {
    throw new Error('getMasterKey() wurde in L3 Phase 2 entfernt — Krypto läuft über Custody-Handles (encryptData/decryptData/encryptFileKey).');
  }

  /** The live master-key custody handle, or throw if the vault is locked. */
  static currentMasterHandle(): string {
    if (!this.__masterHandle || !keyCustody.has(this.__masterHandle)) {
      throw new Error('Tresor gesperrt — kein Master-Key-Handle vorhanden');
    }
    return this.__masterHandle;
  }

  /** Register a raw key into custody, returning its handle (key rotation, decoy, tests). */
  static registerKeyHandle(keyHex: string): string {
    return keyCustody.registerRawKey(keyHex);
  }

  /** Close a custody handle (zero + drop). Idempotent. */
  static closeKeyHandle(handle: string): boolean {
    return keyCustody.close(handle);
  }

  /**
   * TEST-ONLY: resolve the current master key hex from custody, or null if locked. Exists so
   * host tests can assert key identity / rotation without a production getMasterKey(). NEVER
   * call from production code — it defeats the custody seam, and in 2b (native key custody)
   * the key is not resolvable in JS at all.
   */
  static __masterKeyHexForTest(): string | null {
    // Under native key custody the master is not resolvable in JS at all — return null.
    if (keyCustody.isNative) return null;
    return this.__masterHandle && keyCustody.has(this.__masterHandle)
      ? keyCustody.resolve(this.__masterHandle)
      : null;
  }

  static async loadMasterKeyForBiometric(): Promise<boolean> {
    if (this.__masterHandle && keyCustody.has(this.__masterHandle)) return true;
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

      // R3 (audit B3): under native custody the master is EtM-unwrapped in secure memory and never
      // returns to JS — pass the hardware-stored KEK to the native module and adopt the handle.
      if (keyCustody.isNative) {
        const handle = await keyCustody.unwrapVaultWithKekInstall({
          kekHex: kek, ivHex, ctHex: encMasterKey, macHex: storedMac,
        });
        this.setMasterHandle(handle);
        return true;
      }

      // JS-backed (Jest / dev): verify the EtM tag, then CryptoJS-decrypt the master in JS.
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

      // C1: verify the KDF/salt-encoding tag. A mismatch means the stored vault was
      // created with a different KDF contract — deriving here would produce a wrong
      // KEK and silently fail the MAC check (indistinguishable from a wrong password).
      // Surface it explicitly instead. Absent tag = pre-tag vault → proceed (legacy).
      const kdfMeta = await this.getItemSecure(this.STORAGE_KDF_META);
      if (kdfMeta && kdfMeta !== this.KDF_META_CURRENT) {
        console.error('[KDF] kdf_meta mismatch — vault was created with a different KDF/salt encoding. Refusing to derive a divergent KEK.', kdfMeta);
        return false;
      }

      // R3 (audit B2): under native custody the KEK is derived (Argon2id, NFC native) and the master
      // is EtM-unwrapped, both in secure memory — the master never materialises as a JS value. A
      // wrong passphrase surfaces as an EtM tag mismatch (native throw) → counted as a failed attempt.
      if (keyCustody.isNative) {
        let handle: string;
        try {
          handle = await keyCustody.openVaultInstall({
            password: passphrase,
            kekSaltHex,
            opslimit: this.ARGON2_ITERATIONS,
            memlimitKB: this.ARGON2_MEMORY_KB,
            ivHex,
            ctHex: encMasterKey,
            macHex: storedMac,
          });
        } catch {
          await this.incrementFailedAttempts();
          return false;
        }
        this.setMasterHandle(handle);
        await this.resetFailedAttempts();
        return true;
      }

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

      // R3: same master key, new KEK wrap. Under native custody the master is re-wrapped in secure
      // memory (rewrapVault) and never returns to JS; the JS-backed path resolves it to re-wrap.
      if (keyCustody.isNative) {
        const handle = this.currentMasterHandle();
        const newSaltHex = this.bufferToHex(await this.generateSecureBytes(16)); // 16-byte Argon2id salt
        const newIvHex = this.bufferToHex(await this.generateSecureBytes(this.CBC_IV_LENGTH));
        const blob = await keyCustody.rewrapVault(handle, {
          newPassword: newPassphrase,
          newSaltHex,
          opslimit: this.ARGON2_ITERATIONS,
          memlimitKB: this.ARGON2_MEMORY_KB,
          newIvHex,
        });
        await this.storeWrappedMaster(newSaltHex, blob.ivHex, blob.ctHex, blob.macHex);
        return true;
      }

      const masterKeyHex = keyCustody.resolve(this.currentMasterHandle());
      await this.wrapAndStoreMasterKey(newPassphrase, masterKeyHex);
      return true;
    } catch {
      return false;
    }
  }

  private static async wrapAndStoreMasterKey(passphrase: string, masterKeyHex: string): Promise<void> {
    // F1: 16-byte salt — libsodium crypto_pwhash requires exactly 16 bytes (Argon2id).
    const kekSaltHex = this.bufferToHex(await this.generateSecureBytes(16));
    const kek = await this.deriveKEK(passphrase, kekSaltHex);
    // Key wrapping uses aesCBCEncrypt which uses CBC mode - requires 16-byte IV
    const ivHex = this.bufferToHex(await this.generateSecureBytes(this.CBC_IV_LENGTH));

    const result = await this.aesCBCEncrypt(masterKeyHex, kek, ivHex);

    await this.storeWrappedMaster(kekSaltHex, ivHex, result.encryptedData, result.tag);
  }

  /** Persists the wrapped-master blob (audit B2 storage shape). Shared by the JS wrap path and the
   *  native rewrapVault path so both write the identical KEK-salt / KDF-meta / enc / iv / mac set. */
  private static async storeWrappedMaster(
    kekSaltHex: string, ivHex: string, ctHex: string, macHex: string
  ): Promise<void> {
    await this.setItemSecure(this.STORAGE_KEK_SALT, kekSaltHex);
    await this.setItemSecure(this.STORAGE_KDF_META, this.KDF_META_CURRENT); // C1
    await this.setItemSecure(this.STORAGE_MASTER_ENC, ctHex);
    await this.setItemSecure(this.STORAGE_MASTER_IV, ivHex);
    await this.setItemSecure(this.STORAGE_MASTER_MAC, macHex);
  }

  /**
   * Enables biometric unlock: verifies passphrase, re-derives KEK, stores it
   * with requireAuthentication=true (triggers one intentional biometric prompt).
   * Only call this when the user explicitly enables biometrics in settings.
   */
  static async enableBioUnlock(passphrase: string): Promise<boolean> {
    try {
      const ok = await this.unlock(passphrase);
      if (!ok) return false;
      const kekSaltHex = await this.getItemSecure(this.STORAGE_KEK_SALT);
      if (!kekSaltHex) return false;
      const kek = await this.deriveKEK(passphrase, kekSaltHex);
      await SecureStore.setItemAsync(this.STORAGE_BIO_KEK, kek, {
        requireAuthentication: true,
        authenticationPrompt: 'Biometrie aktivieren',
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Removes bio KEK — no biometric prompt, called when user disables biometrics. */
  static async disableBioUnlock(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.STORAGE_BIO_KEK);
    } catch {}
  }

  // F1: Tracks whether the first KEK derivation has been logged (one-shot proof log).
  private static _kdfLogged = false;

  /**
   * Derives the Key-Encryption-Key from the passphrase.
   *
   * F1: ALWAYS uses Argon2id (memory-hard, GPU/ASIC-resistant). The old PBKDF2
   * fallback is removed entirely — there is no downgrade path. Argon2idService
   * routes to native libsodium crypto_pwhash when available, else hash-wasm.
   *
   * NOTE: the KEK salt MUST be 16 bytes — libsodium crypto_pwhash requires
   * exactly crypto_pwhash_SALTBYTES (16). See wrapAndStoreMasterKey.
   */
  private static async deriveKEK(passphrase: string, kekSaltHex: string): Promise<string> {
    // R-03: NFC-normalise so NFD and NFC representations derive the same key.
    passphrase = passphrase.normalize('NFC');

    const nativeArgon2 = (global as any).__argon2_native_available;
    if (!this._kdfLogged) {
      console.log(`[KDF] deriveKEK using ${nativeArgon2 ? 'Argon2id (native libsodium)' : 'Argon2id (@noble/hashes JS fallback)'}`);
      this._kdfLogged = true;
    }

    const saltBuffer = this.hexToBuffer(kekSaltHex);
    const params: Argon2Params = {
      version: this.ARGON2_VERSION,
      type: 2, // Argon2id
      memoryKB: this.ARGON2_MEMORY_KB,
      iterations: this.ARGON2_ITERATIONS,
      parallelism: this.ARGON2_PARALLELISM,
      hashLength: this.ARGON2_HASH_LENGTH,
    };
    const derived = await Argon2idService.deriveKey(passphrase, saltBuffer, params);
    return this.bufferToHex(derived);
  }

  /**
   * Verschlüsselt Daten mit XChaCha20-Poly1305 (primary) bzw. AES-256-CBC+HMAC (Fallback)
   * Speichert Backend-Info im Header zur automatischen Decryption-Pfad-Wahl
   * @param data Zu verschlüsselnder String
   * @returns Objekt mit verschlüsselten Daten, IV und Auth Tag
   */
  static async encryptData(data: string, aadContext: string = ''): Promise<{
    encryptedData: string;
    iv: string;
    mac: string; // AEAD-/HMAC-Tag wird als mac bezeichnet für API-Kompatibilität
  }> {
    return this.encryptDataWithHandle(data, this.currentMasterHandle(), aadContext);
  }

  /**
   * Wie encryptData, aber adressiert den Schlüssel über ein Custody-HANDLE statt über den
   * Master-Cache. Genutzt von Key-Rotation (alter/neuer Handle) und vom Decoy-Pfad (eigener
   * Content-Handle). L3 Phase 2a: das Handle wird JS-seitig über KeyCustody.resolve() in den
   * rohen Key aufgelöst, der dann durch dieselben Krypto-Primitive läuft wie bisher — kein
   * Ciphertext-Byte ändert sich. 2b ersetzt resolve() durch den nativen Handle-Pfad.
   *
   * H2: aadContext (z.B. "fileId:content") wird in den Auth-Tag gebunden. Beim
   * Entschlüsseln muss derselbe Kontext angegeben werden, sonst schlägt die
   * Verifikation fehl — verhindert Blob-Swap zwischen Objekten/Rollen.
   */
  static async encryptDataWithHandle(data: string, handle: string, aadContext: string = ''): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    // R1 (native custody): content is encrypted by handle in secure memory — XChaCha20-Poly1305 ONLY,
    // backend prefix 0x01. The pure-JS AES-CBC / 0x02 downgrade does NOT exist on this path: if the
    // native op throws it is a HARD error, never a silent fallback to weaker JS crypto (non-negotiable).
    if (keyCustody.isNative) {
      const ivHex = this.bufferToHex(await this.generateSecureBytes(this.XCHACHA_NONCE_LENGTH));
      const backendPrefix = BACKEND_XCHACHA.toString(16).padStart(2, '0');
      // W-03 + H2: AAD = backendPrefix || hex(utf8(aadContext)), bound into the Poly1305 tag.
      const aadHex = backendPrefix + this.utf8ToHex(aadContext);
      const dataB64 = this.utf8ToBase64(data);
      let result: { cipherHex: string; tagHex: string };
      try {
        result = await keyCustody.encryptContent(handle, dataB64, ivHex, aadHex);
      } catch (e) {
        throw new Error(`Native-Inhalts-Verschlüsselung fehlgeschlagen (kein JS-Fallback unter nativer Key-Custody): ${(e as Error)?.message ?? e}`);
      }
      return {
        encryptedData: backendPrefix + result.cipherHex,
        iv: ivHex,
        mac: result.tagHex,
      };
    }

    const keyHex = keyCustody.resolve(handle);
    // Backend wählen: XChaCha20 (native) > AES-CBC+HMAC (pure-JS fallback).
    // S3: a non-XChaCha backend means the native module is absent → silent JS-crypto
    // downgrade. Refuse to write unless explicitly permitted (test env / dev opt-in).
    // Checked BEFORE the try so the specific reason is not masked by the generic catch.
    const backend = this.getEncryptionBackend();
    if (backend !== 'xchacha') {
      if (!jsCryptoWriteAllowed()) {
        throw new Error(
          'Native-Krypto-Modul nicht verfügbar — Schreiben mit reinem-JS-Fallback ist ' +
          'deaktiviert (S3): kein stiller Downgrade auf schwächere Krypto.'
        );
      }
      warnJsCryptoDowngradeOnce();
    }

    try {
      // Prefix: 0x01 = XChaCha20, 0x02 = AES-CBC+HMAC.
      // W-03: the prefix is bound into the auth tag (Poly1305 AAD for XChaCha20, HMAC
      // input for AES). H2: the aadContext is appended so the blob is also bound to its
      // object+role. AAD = backendPrefix || hex(utf8(aadContext)).
      const backendPrefix = (backend === 'xchacha')
        ? BACKEND_XCHACHA.toString(16).padStart(2, '0')
        : BACKEND_AESCBCHMAC.toString(16).padStart(2, '0');
      const aadHex = backendPrefix + this.utf8ToHex(aadContext);

      let encryptedHex: string;
      let tag: string;
      let ivHex: string;

      if (backend === 'xchacha') {
        // XChaCha20-Poly1305: 24-byte nonce, AEAD tag from libsodium
        const xchachaNonce = await this.generateSecureBytes(this.XCHACHA_NONCE_LENGTH);
        ivHex = this.bufferToHex(xchachaNonce);
        const result = await this.xchachaEncryptPublic(data, keyHex, ivHex, aadHex);
        encryptedHex = result.encrypted;
        tag = result.tag;
      } else {
        // AES-256-CBC + HMAC-SHA256: 16-byte IV.
        // Backend 0x03 (CryptoJS) is dead write-path since canUseAesCbcHmac() is
        // always true. 0x03 read-path is kept in decryptData for historical compat.
        const cbcIV = await this.generateSecureBytes(this.CBC_IV_LENGTH);
        ivHex = this.bufferToHex(cbcIV);
        const result = await this.aesCbcHmacEncrypt(data, keyHex, ivHex, aadHex);
        encryptedHex = result.encryptedData;
        tag = result.tag;
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
   * Entschlüsselt Daten und verifiziert Integrität (XChaCha20-Poly1305 / AES-CBC+HMAC)
   * Wählt Backend basierend auf im Header gespeicherter Backend-ID.
   * HMAC-Verifikationsfehler sind FATAL - kein Backend-Fallback!
   * @param encryptedData Verschlüsselte Daten (hex, mit Backend-Prefix)
   * @param iv IV (hex)
   * @param mac Auth Tag (hex)
   * @returns Entschlüsselter String
   */
  static async decryptData(encryptedData: string, iv: string, mac: string, aadContext: string = ''): Promise<string> {
    return this.decryptDataWithHandle(encryptedData, iv, mac, this.currentMasterHandle(), aadContext);
  }

  /**
   * Wie decryptData, aber adressiert den Schlüssel über ein Custody-HANDLE. Genutzt von
   * Key-Rotation (alter Handle zum Entschlüsseln vor dem Re-Wrap) und vom Decoy-Pfad.
   * L3 Phase 2a: Handle -> roher Key via KeyCustody.resolve(); identische Krypto, identisches
   * Wire-Format. 2b ersetzt den Resolve durch den nativen decryptWithHandle.
   *
   * H2: aadContext muss exakt dem beim Verschlüsseln verwendeten Kontext entsprechen.
   */
  static async decryptDataWithHandle(encryptedData: string, iv: string, mac: string, handle: string, aadContext: string = ''): Promise<string> {
    // R1 (native custody): decrypt by handle in secure memory. Only XChaCha20 (0x01) is readable —
    // on a real device every content blob is 0x01 (the JS AES-CBC/0x02 and legacy 0x03 paths can only
    // be WRITTEN under the JS backing, which never runs on device). A non-0x01 prefix is rejected
    // rather than silently routed back into JS crypto with a raw key. A failed AEAD throws (recryptBlob
    // relies on that to detect "not under this key").
    if (keyCustody.isNative) {
      if (encryptedData.length < 2) {
        throw new Error('Entschlüsselung fehlgeschlagen');
      }
      const prefix = encryptedData.substring(0, 2);
      if (parseInt(prefix, 16) !== BACKEND_XCHACHA) {
        throw new Error('Native Key-Custody liest nur XChaCha20-Inhalte (0x01); Legacy-0x02/0x03-Inhalte sind auf dem Gerät nicht lesbar.');
      }
      const rawCiphertext = encryptedData.substring(2);
      const aadHex = prefix + this.utf8ToHex(aadContext);
      try {
        const b64 = await keyCustody.decryptContent(handle, rawCiphertext, iv, mac, aadHex);
        return this.base64ToUtf8(b64);
      } catch {
        throw new Error('Entschlüsselung fehlgeschlagen');
      }
    }

    const keyHex = keyCustody.resolve(handle);
    try {
      // Lese Backend-ID aus Header (erste 2 hex Zeichen)
      // Format: [backend_id][encrypted_data]
      // XChaCha20 = 0x01, AES-CBC+HMAC = 0x02, CryptoJS = 0x03
      if (encryptedData.length < 2) {
        throw new Error('Ungültiges ciphertext format - zu kurz für Backend-Header');
      }
      const backendPrefix = encryptedData.substring(0, 2);
      const backendCode = parseInt(backendPrefix, 16);
      let backend: 'xchacha' | 'aescbchmac' | 'cryptojs';

      switch (backendCode) {
        case BACKEND_XCHACHA:
          backend = 'xchacha';
          break;
        case BACKEND_AESCBCHMAC:
          backend = 'aescbchmac';
          break;
        case BACKEND_CRYPTOJS:
          backend = 'cryptojs';
          break;
        default:
          throw new Error(`Unbekannter Backend-Code: 0x${backendPrefix}`);
      }

      // Strip the 2-hex-char backend prefix before passing the ciphertext to the
      // backend. AAD = prefix || hex(utf8(aadContext)) — re-supplied so the auth tag
      // covers both the backend byte (W-03) and the object/role context (H2).
      const rawCiphertext = encryptedData.substring(2);
      const aadHex = backendPrefix + this.utf8ToHex(aadContext);

      // Verwende nur das gespeicherte Backend - KEIN fallback!
      // HMAC-Verifikation fehlschlagen = DIRECT ERROR, no retry!
      if (backend === 'xchacha') {
        return await this.xchachaDecrypt(rawCiphertext, iv, mac, keyHex, aadHex);
      } else if (backend === 'aescbchmac') {
        return await this.aesCbcHmacDecrypt(rawCiphertext, iv, mac, keyHex, aadHex);
      } else {
        return await this.legacyCryptoJsCbcHmacDecrypt(rawCiphertext, iv, mac, keyHex, aadHex);
      }
    } catch {
      throw new Error('Entschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Re-verschlüsselt einen einzelnen Daten-Blob {data, iv, mac} vom alten auf den
   * neuen Schlüssel — IDEMPOTENT und crash-sicher für die Key-Rotation.
   *
   * Da jeder Blob seinen eigenen HMAC/AEAD-Tag trägt, erkennen wir am
   * Entschlüsselungserfolg, unter welchem Schlüssel er liegt:
   *   - Entschlüsselt der Blob bereits mit newKey → schon migriert, unverändert zurück.
   *   - Sonst mit oldKey entschlüsseln und mit newKey neu verschlüsseln.
   * Dadurch darf die Rotation an beliebiger Stelle abbrechen und beim nächsten
   * Durchlauf gefahrlos fortgesetzt werden (kein Mischzustand verfälscht Daten).
   */
  static async recryptBlob(
    blob: { data: string; iv: string; mac: string },
    oldHandle: string,
    newHandle: string,
    aadContext: string = ''
  ): Promise<{ data: string; iv: string; mac: string }> {
    try {
      // Schon mit dem neuen Schlüssel verschlüsselt? Dann nichts tun.
      await this.decryptDataWithHandle(blob.data, blob.iv, blob.mac, newHandle, aadContext);
      return blob;
    } catch {
      // Noch unter dem alten Schlüssel — migrieren.
    }
    const plain = await this.decryptDataWithHandle(blob.data, blob.iv, blob.mac, oldHandle, aadContext);
    const re = await this.encryptDataWithHandle(plain, newHandle, aadContext);
    return { data: re.encryptedData, iv: re.iv, mac: re.mac };
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
        const { hmac } = require('@noble/hashes/hmac.js');
        const { sha256 } = require('@noble/hashes/sha2.js');
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

  // L3 Phase 2: the master key is addressed by an opaque custody HANDLE, never held as raw
  // bytes on the service. `__masterHandle` indexes KeyCustody (JS-backed in 2a — the raw key
  // still lives in the JS heap inside KeyCustody; 2b moves it to native secure memory).
  //
  // `_masterKeyCache` is kept as the WRITE-ONLY install/clear channel used by every unlock
  // path (setupMasterKey, unlockKEK, migrateLegacy, loadMasterKeyForBiometric, installMasterKey):
  // the setter registers the key into custody (or closes the current handle on null) and
  // stores the resulting handle. There is no getter — code that needs the key resolves the
  // handle through KeyCustody, and getMasterKey() throws.
  private static __masterHandle: string | null = null;

  private static set _masterKeyCache(hex: string | null) {
    if (this.__masterHandle) {
      keyCustody.close(this.__masterHandle); // zero + drop the previous key material
      this.__masterHandle = null;
    }
    // Documented one-time raw-key touch (audit B1/B5): vault creation / migration / rotation hand a
    // freshly generated or just-decrypted master to custody. On the native backing this is the only
    // place a raw key crosses the bridge; in steady state the key never re-enters JS.
    if (hex) this.__masterHandle = keyCustody.registerRawKey(hex);
  }

  /**
   * Adopt a master handle that custody already minted natively (openVault / unwrapVaultWithKek) —
   * the master was unwrapped in secure memory and never materialised as a JS value (audit R3).
   * Closes the previous handle. Used only on the native backing.
   */
  private static setMasterHandle(handle: string | null): void {
    if (this.__masterHandle && this.__masterHandle !== handle) {
      keyCustody.close(this.__masterHandle);
    }
    this.__masterHandle = handle;
  }

  // MAC-Key Cache: deterministisch ableitbar pro Master-Key, daher safely cacheable
  private static macKeyCache = new Map<string, string>();

  /**
   * Derives a separate HMAC subkey from a strong key using HKDF-SHA256 (RFC 5869).
   *
   * PBKDF2 was the wrong primitive here: it is designed for stretching weak
   * passwords, not for deriving subkeys from already-strong 256-bit keys.
   * HKDF with a domain-separation label is the correct tool.
   *
   * Cached: deterministic, same key → same MAC key.
   */
  static async deriveMacKey(keyHex: string): Promise<string> {
    const cached = this.macKeyCache.get(keyHex);
    if (cached) return cached;

    const result = hkdfSha256(keyHex, 'filevault-mac-v1', 32);
    this.macKeyCache.set(keyHex, result);
    return result;
  }

  // M4: one-shot flag so the non-constant-time warning is logged at most once.
  private static _ctFallbackWarned = false;

  /**
   * Constant-time string comparison for auth tags / hashes.
   *
   * M4 — TIMING GUARANTEE CAVEAT: Only the native `sodium_memcmp` path
   * (`verifyConstantTime`) is guaranteed constant-time. The JS fallback below uses a
   * branchless Uint8Array XOR-accumulate, but JavaScript/Hermes gives NO guarantee of
   * constant-time execution (JIT, bounds checks, deopt, GC) — treat it as best-effort,
   * not timing-safe. It is only reached when the native module is absent. Exploitability
   * here is low (the compared values are high-entropy hashes the attacker cannot iterate
   * a byte-oracle against), but do not rely on it for timing-sensitive secrets.
   */
  static async constantsTimeEquals(a: string, b: string): Promise<boolean> {
    try {
      const result = await nativeVerifyConstantTime(a, b);
      return result;
    } catch {
      if (!this._ctFallbackWarned) {
        console.warn('[crypto] constantsTimeEquals: native sodium_memcmp unavailable — using best-effort JS fallback (NOT guaranteed constant-time).');
        this._ctFallbackWarned = true;
      }
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

  static async encryptFile(fileData: string, aadContext: string = ''): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptData(fileData, aadContext);
    } catch {
      throw new Error('Dateiverschlüsselung fehlgeschlagen');
    }
  }

  static async decryptFile(encryptedData: string, iv: string, mac: string, aadContext: string = ''): Promise<string> {
    try {
      return await this.decryptData(encryptedData, iv, mac, aadContext);
    } catch {
      throw new Error('Dateientschlüsselung fehlgeschlagen');
    }
  }

  // ─────────────────────────────── Metadaten-Verschlüsselung ───────────────────────────────

  /**
   * Verschlüsselt Metadaten (z.B. Dateinamen, Kategorien)
   * Verwendet dieselbe Verschlüsselung wie encryptData. H2: aadContext bindet die
   * Metadaten an ihr Objekt+Rolle (z.B. "fileId:name").
   */
  static async encryptMetadata(data: string, aadContext: string = ''): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    try {
      return await this.encryptData(data, aadContext);
    } catch {
      throw new Error('Metadaten-Verschlüsselung fehlgeschlagen');
    }
  }

  /**
   * Entschlüsselt Metadaten und verifiziert Integrität
   * Verwendet dieselbe Entschlüsselung wie decryptData
   */
  static async decryptMetadata(encrypted: { data: string; iv: string; mac: string }, aadContext: string = ''): Promise<string> {
    try {
      return await this.decryptData(encrypted.data, encrypted.iv, encrypted.mac, aadContext);
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
      passphrase = passphrase.normalize('NFC'); // R-03
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

  // ─── Key Rotation helpers (R-02) ────────────────────────────────────────────

  /**
   * Wraps a file key with an EXPLICITLY provided master key.
   * Used by KeyRotationService to rewrap file keys during WAL-based rotation
   * without relying on the in-memory cache.
   */
  static async encryptFileKeyWith(
    fileKey: string,
    masterHandle: string
  ): Promise<{ encryptedKey: string; iv: string; mac: string; createdAt: string }> {
    const iv = await this.generateSecureBytes(this.CBC_IV_LENGTH);
    const ivHex = this.bufferToHex(iv);
    // R2 (native custody): EtM-wrap the file key under the master handle in secure memory. The CBC
    // plaintext bytes are the ASCII of the file-key hex string (matches aesCbcEncryptRaw's CryptoJS
    // UTF-8 treatment) — passed as hex(utf8(fileKey)). Byte-identical wire format.
    if (keyCustody.isNative) {
      const w = await keyCustody.wrapKey(masterHandle, ivHex, this.utf8ToHex(fileKey));
      return { encryptedKey: w.ctHex, iv: ivHex, mac: w.macHex, createdAt: new Date().toISOString() };
    }
    const masterKeyHex = keyCustody.resolve(masterHandle);
    const result = await this.aesCBCEncrypt(fileKey, masterKeyHex, ivHex);
    return {
      encryptedKey: result.encryptedData,
      iv: ivHex,
      mac: result.tag,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Unwraps a file key using an EXPLICITLY provided master key.
   * Symmetric counterpart of encryptFileKeyWith.
   */
  static async decryptFileKeyWith(
    encryptedKey: { encryptedKey: string; iv: string; mac: string; createdAt?: string },
    masterHandle: string
  ): Promise<string> {
    // R2 (native custody): EtM-unwrap the file key under the master handle; returns the file-key string.
    if (keyCustody.isNative) {
      return keyCustody.unwrapKey(masterHandle, encryptedKey.iv, encryptedKey.encryptedKey, encryptedKey.mac);
    }
    return this.aesCBCDecrypt(
      encryptedKey.encryptedKey,
      encryptedKey.iv,
      encryptedKey.mac,
      keyCustody.resolve(masterHandle)
    );
  }

  /**
   * Installs a specific master key (e.g. after key rotation).
   * Wraps it with the given passphrase and caches it.
   */
  static async installMasterKey(masterKeyHex: string, passphrase: string): Promise<void> {
    await this.wrapAndStoreMasterKey(passphrase, masterKeyHex);
    this._masterKeyCache = masterKeyHex;
  }

  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Wraps (verschlüsselt) einen File-Key mit dem Master-Key
   * Verwendet AES-256-CBC + HMAC-SHA-256 für authenticated encryption
   * (Key Wrapping nutzt immer AES-CBC+HMAC; Inhalts-Encryption nutzt primär XChaCha20-Poly1305)
   * Backend Selection: XChaCha20 > AES-CBC+HMAC > CryptoJS
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
      // Key wrapping uses CBC mode - requires 16-byte IV
      const iv = await this.generateSecureBytes(this.CBC_IV_LENGTH);
      const ivHex = this.bufferToHex(iv);

      // R2 (native custody): EtM-wrap by handle in secure memory; else JS AES-CBC. Same wire format.
      if (keyCustody.isNative) {
        const w = await keyCustody.wrapKey(this.currentMasterHandle(), ivHex, this.utf8ToHex(fileKey));
        return { encryptedKey: w.ctHex, iv: ivHex, mac: w.macHex, createdAt: new Date().toISOString() };
      }

      const masterKeyHex = keyCustody.resolve(this.currentMasterHandle());
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
      // R2 (native custody): EtM-unwrap by handle; else JS AES-CBC. Returns the file-key string.
      if (keyCustody.isNative) {
        return await keyCustody.unwrapKey(
          this.currentMasterHandle(), encryptedKey.iv, encryptedKey.encryptedKey, encryptedKey.mac
        );
      }

      const masterKeyHex = keyCustody.resolve(this.currentMasterHandle());
      return await this.aesCBCDecrypt(encryptedKey.encryptedKey, encryptedKey.iv, encryptedKey.mac, masterKeyHex);
    } catch {
      throw new Error('Konnte File-Key nicht entschlüsseln');
    }
  }
}

// DEPRECATED: XChaCha20CryptoService ist veraltet - nutze SecureCryptoService
export { XChaCha20CryptoService } from './XChaCha20CryptoService';

// SecureCryptoService ist der primäre Service mit XChaCha20-Poly1305 (AES-CBC+HMAC als Fallback)
export default SecureCryptoService;
