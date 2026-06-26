/**
 * FileEncryptionKey - Manages unique encryption keys for individual files
 *
 * Sicherheitsmerkmale:
 * - 256-bit kryptographisch sichere Zufallsschlüssel pro Datei
 * - Key Wrapping mit SecureCryptoService (XChaCha20/AES-CBC+HMAC/CryptoJS)
 * - HMAC-SHA-256 für Integritätsprüfung
 * - Secure Store Integration für verschlüsselte Schlüsselspeicherung
 * - Key Rotation Support (Re-encrypt mit Master-Key)
 *
 * HINWEIS: Alle CryptoJS Aufrufe wurden durch SecureCryptoService ersetzt.
 * Dies verhindert ReferenceError und nutzt das korrekte Backend.
 */

import * as SecureStore from 'expo-secure-store';
import * as CryptoModule from 'expo-crypto';
import { SecureCryptoService } from './CryptoService';

/**
 * Interface für verschlüsselte File-Key Metadaten
 * Verwendet AES-256-CBC + HMAC-SHA-256 für authenticated encryption
 */
export interface EncryptedFileKey {
  fileId?: string;
  encryptedKey: string;  // AES-256-CBC verschlüsselter Schlüssel
  iv: string;            // IV für AES-256-CBC
  mac: string;           // HMAC-SHA-256 Tag für Integrität (auch als tag bezeichnet)
  createdAt: string;     // ISO Timestamp für Key Rotation
}

/**
 * Interface mit fileId (nach dem Wrapping)
 */
export interface EncryptedFileKeyWithId extends EncryptedFileKey {
  fileId: string;
}

/**
 * Interface für dekodierten File-Key (nur im Speicher)
 */
export interface FileKey {
  id: string;
  key: string;  // 64 hex Zeichen = 256 bit
  createdAt: number;
}

/**
 * Prefix für SecureStore Key Wrapper Schlüssel
 */
const KEY_WRAPPED_PREFIX = 'filevault_filekey_';

/**
 * Generate a unique 256-bit encryption key for a file
 * @returns 64-character hex string (256 bits)
 */
export async function generateFileKey(): Promise<string> {
  try {
    const bytes = await CryptoModule.getRandomBytesAsync(32);
    // Slice to exact bytes (same fix as CryptoService.generateSecureBytes)
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    return SecureCryptoService.bufferToHex(buffer);
  } catch (error) {
    console.error('Error generating file key:', error);
    throw new Error('Konnte Dateischlüssel nicht generieren');
  }
}

/**
 * Wraps (encrypts) a file key with the master key
 * Delegiert an SecureCryptoService.encryptFileKey() für Backend-Selektion
 * (XChaCha20 > AES-CBC+HMAC > CryptoJS)
 * @param fileKey - 64 hex char file key to wrap
 * @returns EncryptedFileKey with iv, mac, and encryptedKey
 */
export async function wrapFileKey(fileKey: string): Promise<EncryptedFileKey> {
  return SecureCryptoService.encryptFileKey(fileKey);
}

/**
 * Unwraps (decrypts) a file key with the master key
 * Delegiert an SecureCryptoService.decryptFileKey() für Backend-Selektion
 * (XChaCha20 > AES-CBC+HMAC > CryptoJS)
 * @param encryptedKey - EncryptedFileKey object
 * @returns 64 hex char file key
 */
export async function unwrapFileKey(encryptedKey: EncryptedFileKey): Promise<string> {
  return SecureCryptoService.decryptFileKey(encryptedKey);
}

/**
 * Stores an encrypted file key in SecureStore
 * @param fileId - ID of the file
 * @param encryptedKey - EncryptedFileKey to store
 */
export async function storeEncryptedFileKey(
  fileId: string,
  encryptedKey: EncryptedFileKey
): Promise<void> {
  try {
    const keyStorageName = `${KEY_WRAPPED_PREFIX}${fileId}`;
    await SecureStore.setItemAsync(keyStorageName, JSON.stringify(encryptedKey));
  } catch (error) {
    console.error('Error storing encrypted file key:', error);
    throw new Error('Konnte verschlüsselten Dateischlüssel nicht speichern');
  }
}

/**
 * Loads an encrypted file key from SecureStore
 * @param fileId - ID of the file
 * @returns EncryptedFileKey or null if not found
 */
export async function loadEncryptedFileKey(fileId: string): Promise<EncryptedFileKey | null> {
  try {
    const keyStorageName = `${KEY_WRAPPED_PREFIX}${fileId}`;
    const storedData = await SecureStore.getItemAsync(keyStorageName);

    if (!storedData) {
      return null;
    }

    return JSON.parse(storedData) as EncryptedFileKey;
  } catch (error) {
    console.error('Error loading encrypted file key:', error);
    throw new Error('Konnte verschlüsselten Dateischlüssel nicht laden');
  }
}

/**
 * Deletes an encrypted file key from SecureStore
 * @param fileId - ID of the file
 */
export async function deleteEncryptedFileKey(fileId: string): Promise<void> {
  try {
    const keyStorageName = `${KEY_WRAPPED_PREFIX}${fileId}`;
    await SecureStore.deleteItemAsync(keyStorageName);
  } catch (error) {
    console.error('Error deleting encrypted file key:', error);
    throw new Error('Konnte verschlüsselten Dateischlüssel nicht löschen');
  }
}

/**
 * Re-encrypts a file key with a new master key (for key rotation)
 * @param fileId - ID of the file
 * @param oldEncryptedKey - Current encrypted key
 * @returns New encrypted key wrapped with new master key
 */
export async function rewrapFileKey(
  fileId: string,
  oldEncryptedKey: EncryptedFileKey
): Promise<EncryptedFileKey> {
  try {
    // Unwrap with current master key
    const fileKey = await unwrapFileKey(oldEncryptedKey);

    // Wrap with new master key
    const newEncryptedKey = await wrapFileKey(fileKey);
    newEncryptedKey.fileId = oldEncryptedKey.fileId; // Keep original fileId

    // Store new encrypted key
    await storeEncryptedFileKey(fileId, newEncryptedKey);

    return newEncryptedKey;
  } catch (error) {
    console.error('Error rewrapping file key:', error);
    throw new Error('Konnte Dateischlüssel nicht neu wrappen');
  }
}

/**
 * Generates the SecureStore key name for a file's encrypted key
 * @param fileId - ID of the file
 * @returns Storage key name
 */
export function getFileKeyStorageName(fileId: string): string {
  return `${KEY_WRAPPED_PREFIX}${fileId}`;
}
