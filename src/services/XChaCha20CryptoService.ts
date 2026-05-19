/**
 * DEPRECATED - XChaCha20CryptoService
 * ACHTUNG: Dieser Service ist VERALTET!
 * Alle Verschlüsselung erfolgt nun über SecureCryptoService (AES-256-CBC)
 *
 * Diese Datei existiert nur für Kompatibilität mit altem Code.
 * WICHTIG: AES-256-CBC ist die VERBINDLICHE Verschlüsselungsmethode!
 */

import * as SecureStore from 'expo-secure-store';
import * as CryptoModule from 'expo-crypto';
import CryptoJS from 'crypto-js';

/**
 * Hex utility functions
 */
function hexToBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  }
  return hex;
}

/**
 * ACHTUNG: Diese Klasse ist veraltet!
 * Alle Funktionen degressieren auf SecureCryptoService (AES-256-CBC)
 */
export class XChaCha20CryptoService {
  private static readonly STORAGE_KEY = 'filevault_xchacha20_key';

  /**
   * DEPRECATED - Nutze SecureCryptoService.initialize()
   */
  static async initialize(): Promise<void> {
    console.warn('XChaCha20CryptoService.initialize() ist veraltet! Nutze SecureCryptoService.');
  }

  /**
   * DEPRECATED - AES-256 verwendet keinen separaten Storage Key
   */
  static getStorageKey(): string {
    console.warn('XChaCha20CryptoService.getStorageKey() ist veraltet!');
    return this.STORAGE_KEY;
  }

  /**
   * DEPRECATED - Generiert einen AES-256 Schlüssel über SecureCryptoService
   */
  static async generateSecureKey(): Promise<string> {
    console.warn('XChaCha20CryptoService.generateSecureKey() ist veraltet!');
    try {
      const bytes = await CryptoModule.getRandomBytesAsync(32);
      return bufferToHex(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    } catch (error) {
      throw new Error('AES-256 Key Generierung fehlgeschlagen');
    }
  }

  /**
   * DEPRECATED - Nutze SecureCryptoService.encryptData()
   * ACHTUNG: Gibt iv/mac statt nonce/tag zurück für Kompatibilität mit SecureCryptoService
   */
  static async encrypt(data: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    console.warn('XChaCha20CryptoService.encrypt() ist veraltet! Nutze SecureCryptoService.encryptData().');
    // Import hier für Cyclic dependency
    const { SecureCryptoService } = await import('./CryptoService');
    const result = await SecureCryptoService.encryptData(data);
    return {
      encryptedData: result.encryptedData,
      iv: result.iv,
      mac: result.mac,
    };
  }

  /**
   * DEPRECATED - Nutze SecureCryptoService.decryptData()
   */
  static async decrypt(encryptedData: string, nonce: string, tag: string): Promise<string> {
    console.warn('XChaCha20CryptoService.decrypt() ist veraltet! Nutze SecureCryptoService.decryptData().');
    const { SecureCryptoService } = await import('./CryptoService');
    return await SecureCryptoService.decryptData(encryptedData, nonce, tag);
  }

  /**
   * DEPRECATED - ComputeMAC über SecureCryptoService
   */
  static async computeMac(macKey: string, data: string): Promise<string> {
    console.warn('XChaCha20CryptoService.computeMac() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    return await SecureCryptoService.computeMac(macKey, data);
  }

  /**
   * DEPRECATED - Nutze SecureCryptoService.deriveKeyFromPassphrase()
   */
  static async deriveKeyFromPassphrase(
    password: string,
    saltBase64?: string,
    iterations = 2,
    memory = 65536
  ): Promise<string> {
    console.warn('XChaCha20CryptoService.deriveKeyFromPassphrase() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    return await SecureCryptoService.deriveKeyFromPassphrase(password);
  }

  // ─────────────────────────────── Dateiverschlüsselung ───────────────────────────────

  static async encryptFile(fileData: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    console.warn('XChaCha20CryptoService.encryptFile() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    const result = await SecureCryptoService.encryptFile(fileData);
    return {
      encryptedData: result.encryptedData,
      iv: result.iv,
      mac: result.mac,
    };
  }

  static async decryptFile(encryptedData: string, iv: string, mac: string): Promise<string> {
    console.warn('XChaCha20CryptoService.decryptFile() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    return await SecureCryptoService.decryptFile(encryptedData, iv, mac);
  }

  // ─────────────────────────────── Metadaten-Verschlüsselung ───────────────────────────────

  static async encryptMetadata(data: string): Promise<{
    encryptedData: string;
    iv: string;
    mac: string;
  }> {
    console.warn('XChaCha20CryptoService.encryptMetadata() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    const result = await SecureCryptoService.encryptMetadata(data);
    return {
      encryptedData: result.encryptedData,
      iv: result.iv,
      mac: result.mac,
    };
  }

  static async decryptMetadata(encrypted: { data: string; iv: string; mac: string }): Promise<string> {
    console.warn('XChaCha20CryptoService.decryptMetadata() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    return await SecureCryptoService.decryptMetadata({
      data: encrypted.data,
      iv: encrypted.iv,
      mac: encrypted.mac,
    });
  }

  // ─────────────────────────────── Schlüsselverwaltung ───────────────────────────────

  static async deleteEncryptionKey(): Promise<void> {
    console.warn('XChaCha20CryptoService.deleteEncryptionKey() ist veraltet!');
    const { SecureCryptoService } = await import('./CryptoService');
    await SecureCryptoService.deleteEncryptionKey();
  }

  /**
   * DEPRECATED - Nutze SecureCryptoService.constantsTimeEquals()
   */
  static async verifyConstantTime(a: string, b: string): Promise<boolean> {
    const { SecureCryptoService } = require('./CryptoService');
    return SecureCryptoService.constantsTimeEquals(a, b);
  }
}

// Export helper function für Argon2id mit AES-256
export async function generateArgon2Salt(): Promise<string> {
  const bytes = await CryptoModule.getRandomBytesAsync(16);
  return bufferToHex(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

export default XChaCha20CryptoService;
