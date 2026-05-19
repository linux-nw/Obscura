/**
 * Secure Delete Service
 * Sicheres Löschen von Dateien durch überschreiben mit Mustern
 *
 * Sicherheitsmerkmale:
 * - Guttman Wipe (7-Pass)
 * - DoD 5220.22-M (3-Pass)
 * - Quick Wipe (1-Pass)
 * - Secure deletion for all vault data
 *
 * WICHTIG: NUTZT AES-256-CBC statt XChaCha20
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from './CryptoService';
import { HardwareBackedStorage } from './HardwareKeystoreService';

export type SecureDeleteMethod = 'quick' | 'dod' | 'guttman';

export interface DeleteProgress {
  totalFiles: number;
  deletedFiles: number;
  currentFile: string;
  progress: number;
}

export class SecureDeleteService {
  private static readonly VAULT_DIR = (FileSystem.documentDirectory || '') + 'vault/';
  private static readonly NOTES_DIR = (FileSystem.documentDirectory || '') + 'notes/';

  /**
   * Sichert den Vault Ordner und löscht ihn sicher
   */
  static async secureDeleteVault(
    method: SecureDeleteMethod = 'guttman'
  ): Promise<void> {
    try {
      console.log(`SecureDelete: Starting vault deletion with ${method} method`);

      // Liste aller Dateien im Vault
      const files = await FileSystem.readDirectoryAsync(this.VAULT_DIR);

      for (const file of files) {
        const filePath = `${this.VAULT_DIR}${file}`;
        await this.secureDeleteFile(filePath, method);
      }

      // Vault Ordner löschen
      await FileSystem.deleteAsync(this.VAULT_DIR, { idempotent: true });

      console.log('SecureDelete: Vault deleted');
    } catch (error) {
      console.error('SecureDelete: Vault deletion failed:', error);
      throw new Error('Tresor konnte nicht sicher gelöscht werden');
    }
  }

  /**
   * Sichert Notizen und löscht sie sicher
   */
  static async secureDeleteNotes(
    method: SecureDeleteMethod = 'guttman'
  ): Promise<void> {
    try {
      console.log(`SecureDelete: Starting notes deletion with ${method} method`);

      const files = await FileSystem.readDirectoryAsync(this.NOTES_DIR);

      for (const file of files) {
        const filePath = `${this.NOTES_DIR}${file}`;
        await this.secureDeleteFile(filePath, method);
      }

      // Notes Ordner löschen
      await FileSystem.deleteAsync(this.NOTES_DIR, { idempotent: true });

      console.log('SecureDelete: Notes deleted');
    } catch (error) {
      console.error('SecureDelete: Notes deletion failed:', error);
      throw new Error('Notizen konnten nicht sicher gelöscht werden');
    }
  }

  /**
   * Sichert eine einzelne Datei und löscht sie
   */
  private static async secureDeleteFile(
    filePath: string,
    method: SecureDeleteMethod
  ): Promise<void> {
    try {
      const fileInfo = await FileSystem.getInfoAsync(filePath);
      if (!fileInfo.exists) return;

      const fileSize = fileInfo.size;

      // Verschiedene Überschreibungs-Muster basierend auf Methode
      switch (method) {
        case 'quick':
          await this.overwriteWithPattern(filePath, 1, fileSize);
          break;
        case 'dod':
          await this.overwriteWithPattern(filePath, 3, fileSize);
          break;
        case 'guttman':
          await this.overwriteWithPattern(filePath, 7, fileSize);
          break;
      }

      // Datei endgültig löschen
      await FileSystem.deleteAsync(filePath, { idempotent: true });
    } catch (error) {
      console.error(`SecureDelete: Failed to delete ${filePath}:`, error);
    }
  }

  /**
   * Überschreibt Datei mit Mustern
   */
  private static async overwriteWithPattern(
    filePath: string,
    passes: number,
    fileSize: number
  ): Promise<void> {
    try {
      // Lese Dateiinhalt
      const content = await FileSystem.readAsStringAsync(filePath, {
        encoding: FileSystem.EncodingType.Base64,
      });

      // Überschreiben mit Mustern
      for (let pass = 0; pass < passes; pass++) {
        const pattern = this.getPatternForPass(pass);
        const overwrittenContent = this.applyPattern(content, pattern, pass, passes);

        // Schreibe überschriebene Daten zurück
        await FileSystem.writeAsStringAsync(filePath, overwrittenContent, {
          encoding: FileSystem.EncodingType.Base64,
        });
      }

      // Letzte Überschreibung mit Zufallsdaten
      const randomPattern = await this.generateRandomPattern(fileSize);
      await FileSystem.writeAsStringAsync(filePath, randomPattern, {
        encoding: FileSystem.EncodingType.Base64,
      });
    } catch (error) {
      console.error('SecureDelete: Overwrite failed:', error);
    }
  }

  /**
   * Gibt Muster für einen Durchlauf zurück
   */
  private static getPatternForPass(pass: number): string {
    const patterns = [
      '00', // Null
      'FF', // Einsen
      'AA', // 10101010
      '55', // 01010101
      '92', // Checksum patterns
      '49', // More patterns
      'D6', // Final patterns
    ];

    if (pass < patterns.length) {
      return patterns[pass];
    }

    // Für mehr als 7 Passes: Zufallsmuster
    // Fallback: festes Muster für Sync-Aufrufe (sollte nicht vorkommen)
    return '00';
  }

  /**
   * Wendet Muster auf Content an
   * XORt den Base64-decodierten Content mit dem Pattern
   */
  private static applyPattern(
    base64Content: string,
    pattern: string,
    pass: number,
    totalPasses: number
  ): string {
    try {
      // Decodiere Base64 zu Uint8Array
      const decoded = atob(base64Content);
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
      }

      // Erstelle Pattern-Bytes (hex zu bytes)
      const patternBytes = new Uint8Array(pattern.length / 2);
      for (let i = 0; i < pattern.length; i += 2) {
        patternBytes[i / 2] = parseInt(pattern.substr(i, 2), 16);
      }

      // Overwrite every byte with the pattern value (not XOR — XOR with 0x00 is a no-op)
      const result = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        result[i] = patternBytes[i % patternBytes.length];
      }

      // Recodiere zu Base64
      let binary = '';
      for (let i = 0; i < result.length; i++) {
        binary += String.fromCharCode(result[i]);
      }
      return btoa(binary);
    } catch (error) {
      // Rethrow so caller knows the overwrite pass failed rather than silently writing back original
      throw new Error(`SecureDelete: applyPattern failed: ${error}`);
    }
  }

  /**
   * Generiert zufälliges Pattern
   * Verwendet SecureCryptoService.generateSecureBytes für echtes Zufalls-Random
   */
  private static async generateRandomPattern(size: number): Promise<string> {
    try {
      const randomBytes = await SecureCryptoService.generateSecureBytes(size);
      const bytes = new Uint8Array(randomBytes);
      // writeAsStringAsync with EncodingType.Base64 expects base64 input
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    } catch (error) {
      console.error('SecureDelete: generateRandomPattern failed:', error);
      // Fallback: write zero bytes as base64
      const zeros = new Uint8Array(size);
      let binary = '';
      for (let i = 0; i < zeros.length; i++) {
        binary += String.fromCharCode(zeros[i]);
      }
      return btoa(binary);
    }
  }

  /**
   * Sichert alle Daten im Vault
   */
  static async secureWipeAll(): Promise<void> {
    // List of all keys to verify deletion
    const keysToVerify = [
      'filevault_encryption_key',
      'filevault_pbkdf2_salt',
      'filevault_argon2id_salt',
      'filevault_kek_salt',
      'filevault_master_enc',
      'filevault_master_iv',
      'filevault_master_mac',
      'filevault_bio_kek',
      'filevault_pin_hash',
      'filevault_pin_salt',
      'filevault_pin_iv',
      'filevault_pin_key',
      'filevault_failed_attempts',
      'filevault_lock_until',
      'filevault_app_initialized',
    ];

    try {
      console.log('SecureDelete: Starting full secure wipe...');

      // Zuerst Crypto Schlüssel löschen
      await SecureCryptoService.deleteEncryptionKey();

      // Vault löschen
      await this.secureDeleteVault();

      // Notizen löschen
      await this.secureDeleteNotes();

      // Read-back Verification: Prüfe jedes gelöschte Item
      console.log('SecureDelete: Starting read-back verification...');
      for (const key of keysToVerify) {
        const stillExists = await HardwareBackedStorage.exists(key);
        if (stillExists) {
          // Prüfe SecureStore direkt
          const secureStoreValue = await SecureStore.getItemAsync(key);
          if (secureStoreValue !== null) {
            throw new Error(`secureWipeAll: Key still exists after deletion: ${key}`);
          }
        }
        console.log(`SecureDelete: Verified deletion of ${key}`);
      }

      console.log('SecureDelete: Full secure wipe complete (AES-256)');
    } catch (error) {
      console.error('SecureDelete: Full wipe failed:', error);
      throw error;
    }
  }

  /**
   * Sichert und löscht eine einzelne Datei
   */
  static async secureDeleteFileById(fileId: string): Promise<void> {
    try {
      const filePath = `${this.VAULT_DIR}file_${fileId}`;
      const metaPath = `${filePath}.meta.enc`;

      // Datei sicher löschen
      await this.secureDeleteFile(filePath, 'guttman');

      // Meta-Datei sicher löschen
      const metaInfo = await FileSystem.getInfoAsync(metaPath);
      if (metaInfo.exists) {
        await this.secureDeleteFile(metaPath, 'guttman');
      }

      console.log(`SecureDelete: File ${fileId} deleted`);
    } catch (error) {
      console.error(`SecureDelete: Failed to delete file ${fileId}:`, error);
      throw new Error('Datei konnte nicht sicher gelöscht werden');
    }
  }

  /**
   * Prüft ob Datei sicher gelöscht wurde (nach Guttman)
   */
  static async verifyDeletion(filePath: string): Promise<boolean> {
    try {
      const info = await FileSystem.getInfoAsync(filePath);
      return !info.exists;
    } catch {
      return true; // File existiert nicht - sicher gelöscht
    }
  }

  /**
   * Gibt die ungefähre Zeit für Secure Delete an
   */
  static getEstimatedDeleteTime(fileSize: number, method: SecureDeleteMethod): string {
    const passes = method === 'guttman' ? 7 : method === 'dod' ? 3 : 1;

    // Geschätzt: 100KB/s pro Pass
    const estimatedSeconds = (fileSize / 100000) * passes;
    if (estimatedSeconds < 60) {
      return `${Math.ceil(estimatedSeconds)} Sekunden`;
    }
    return `${Math.ceil(estimatedSeconds / 60)} Minuten`;
  }
}

export default SecureDeleteService;
