/**
 * Argon2id Service - Memory-hard Key Derivation Function
 *
 * Sicherheitsmerkmale:
 * - Argon2id (hybrid mode: resistant to both GPU and side-channel attacks)
 * - Configurable memory (64MB default), iterations (3), parallelism (4)
 * - Version 1.3 (latest stable)
 * - 32-byte hash output
 *
 * Hinweis: Für Produktion sollte ein Native Module verwendet werden:
 * - iOS: argon2 via CocoaPods (libargon2)
 * - Android: argon2 via Gradle (java-argon2)
 */

import * as CryptoModule from 'expo-crypto';
import { argon2id as hashWasmArgon2id } from 'hash-wasm';
import { NativeModules } from 'react-native';
import { argon2id as nativeArgon2id } from '../native/RNFileVault';

// ─────────────────────────────── Typedefinitionen ───────────────────────────────

export interface Argon2Params {
  version: number;
  type: Argon2Type;
  memoryKB: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
}

export type Argon2Type = 0 | 1 | 2; // 0=Argon2d, 1=Argon2i, 2=Argon2id

// ─────────────────────────────── Standard Parameter ───────────────────────────────

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  version: 0x13, // 19 = Argon2 version 1.3
  type: 2, // Argon2id (hybrid)
  memoryKB: 65536, // 64 MB
  iterations: 3, // Erhöht von 2 auf 3 für besseren Schutz gegen GPU-Attacken
  parallelism: 4,
  hashLength: 32, // 32 bytes
};

// ─────────────────────────────── Argon2idService ───────────────────────────────

/**
 * Argon2id Key Derivation Service
 *
 * Dieser Service bietet sichere Key Derivation mit Argon2id,
 * einer memory-hard Funktion, die resistent gegenüber GPU/ASIC Angriffen ist.
 *
 * Implementierung:
 * - Primary: Native Module (RNFileVault argon2id)
 * - Fallback: hash-wasm (WebAssembly)
 * - Kein CryptoJS Fallback - die App weigert sich, Keys abzuleiten, wenn kein
 *   echter Argon2id verfügbar ist
 */
export class Argon2idService {
  /**
   * Leitet einen kryptographischen Schlüssel aus einer Passphrase ab
   * @param password Die Passphrase (z.B. PIN)
   * @param salt Ein kryptographisch sicheres Salt (mind. 16 bytes empfohlen)
   * @param params Argon2 Parameter
   * @returns Der abgeleitete Schlüssel als ArrayBuffer
   */
  static async deriveKey(
    password: string,
    salt: ArrayBuffer,
    params: Argon2Params = DEFAULT_ARGON2_PARAMS
  ): Promise<ArrayBuffer> {
    // Prüfe auf native Module
    const nativeAvailable = (global as any).__argon2_native_available;
    if (nativeAvailable) {
      return this.deriveKeyNative(password, salt, params);
    }

    // Fallback zu hash-wasm (WebAssembly)
    try {
      const options = {
        password: password,
        salt: this.bufferToBase64(salt),
        type: params.type,
        version: params.version,
        memorySize: params.memoryKB, // hash-wasm uses memorySize in KB
        iterations: params.iterations,
        parallelism: params.parallelism,
        hashLength: params.hashLength,
        outputType: 'hex' as const,
      };
      const hash = await hashWasmArgon2id(options);
      return this.hexToBuffer(hash);
    } catch {
      throw new Error('No secure Argon2id implementation available');
    }
  }

  /**
   * Verifiziert eine Passphrase gegen einen gespeicherten Hash
   * @param password Die Passphrase zur Verifizierung
   * @param hash Der gespeicherte Hash
   * @param params Argon2 Parameter
   * @returns true wenn die Passphrase korrekt ist
   */
  static async verify(
    password: string,
    hash: ArrayBuffer,
    params: Argon2Params = DEFAULT_ARGON2_PARAMS
  ): Promise<boolean> {
    try {
      const derivedKey = await this.deriveKey(password, hash, params);
      return this.constantTimeEquals(derivedKey, hash);
    } catch (error) {
      console.error('Argon2id verification error:', error);
      return false;
    }
  }

  /**
   * Generiert ein kryptographisch sicheres Salt
   * @param length Länge des Salt in Bytes (16-64 empfohlen)
   * @returns Das generierte Salt als ArrayBuffer
   */
  static async generateSalt(length: number = 16): Promise<ArrayBuffer> {
    try {
      const bytes = await CryptoModule.getRandomBytesAsync(length);
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    } catch (error) {
      console.error('Error generating salt:', error);
      throw new Error('Konnte Salt nicht generieren');
    }
  }

  /**
   * Konstantzeit-Vergleich zweier Buffer (gegen Timing-Attacks)
   */
  private static constantTimeEquals(a: ArrayBuffer, b: ArrayBuffer): boolean {
    if (a.byteLength !== b.byteLength) return false;

    const aBytes = new Uint8Array(a);
    const bBytes = new Uint8Array(b);
    let result = 0;

    for (let i = 0; i < aBytes.length; i++) {
      result |= aBytes[i] ^ bBytes[i];
    }

    return result === 0;
  }

  // ─────────────────────────────── Native Module Helper ───────────────────────────────

  /**
   * Native deriveKey Aufruf
   * Wenn __argon2_native_available = true, wird RNFileVaultNative.argon2id() aufgerufen.
   */
  private static async deriveKeyNative(
    password: string,
    salt: ArrayBuffer,
    params: Argon2Params
  ): Promise<ArrayBuffer> {
    // Prüfe ob native Module verfügbar ist
    if (!NativeModules.RNFileVault) {
      throw new Error('Native Argon2 Module nicht verfügbar');
    }

    try {
      // Konvertiere ArrayBuffer zu Base64 für native API
      const saltB64 = this.bufferToBase64(salt);
      const hash = await nativeArgon2id(
        password,
        saltB64,
        params.iterations,
        params.memoryKB,
        params.hashLength
      );
      return this.base64ToBuffer(hash);
    } catch (error) {
      console.error('Native Argon2id failed:', error);
      throw new Error('Native Argon2 Module fehlgeschlagen - ' + (error instanceof Error ? error.message : 'unknown error'));
    }
  }

  // ─────────────────────────────── Backward Compatibility ───────────────────────────────

  /**
   * Prüft ob ein Hash PBKDF2 oder Argon2id Format ist
   * @param hash Der zu prüfende Hash
   * @returns true wenn es ein PBKDF2 Hash ist
   */
  static isLegacyHash(hash: string): boolean {
    // PBKDF2 Hash aus CryptoJS sind 64 hex Zeichen (32 bytes)
    // Argon2id Hash werden länger sein (64+ hex Zeichen)
    // Wir prüfen auf das Format
    return /^[a-f0-9]{64}$/i.test(hash);
  }

  /**
   * Leitet einen Schlüssel aus Passphrase ab (auto-detect Format)
   * Unterstützt sowohl PBKDF2 (Legacy) als auch Argon2id
   */
  static async deriveKeyAutoDetect(
    password: string,
    salt: ArrayBuffer,
    iterationCount?: number
  ): Promise<ArrayBuffer> {
    // Wenn iterationCount angegeben ist, nutze PBKDF2 für Kompatibilität
    if (iterationCount !== undefined) {
      // Import CryptoJS dynamisch
      const CryptoJS = require('crypto-js');
      const saltHex = this.bufferToHex(salt);
      const derivedKey = CryptoJS.PBKDF2(password, saltHex, {
        keySize: 32 / 4,
        iterations: iterationCount,
        hasher: CryptoJS.algo.SHA256,
      });
      // .words is a plain JS Array, not a TypedArray — use hex conversion
      return this.hexToBuffer(derivedKey.toString(CryptoJS.enc.Hex));
    }

    // Standard: Argon2id - wir werfen Error wenn kein echtes Argon2id verfügbar ist
    return await this.deriveKey(password, salt);
  }

  /**
   * Konvertiere ArrayBuffer zu Hex-String
   */
  private static bufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  }

  /**
   * Konvertiere Hex-String zu ArrayBuffer
   */
  private static hexToBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }

  // ─────────────────────────────── Utility Functions ───────────────────────────────

  /**
   * Konvertiere ArrayBuffer zu Base64
   */
  private static bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Konvertiere Base64 zu ArrayBuffer
   */
  private static base64ToBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Konvertiere Argon2Params zu hash-wasm Options
   */
  private static paramsToHashWasmOptions(params: Argon2Params): {
    type: number;
    version: number;
    memoryKB: number;
    iterations: number;
    parallelism: number;
    hashLength: number;
  } {
    return {
      type: params.type,
      version: params.version,
      memoryKB: params.memoryKB,
      iterations: params.iterations,
      parallelism: params.parallelism,
      hashLength: params.hashLength,
    };
  }
}

export default Argon2idService;
