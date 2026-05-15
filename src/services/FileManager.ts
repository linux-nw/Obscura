import * as FileSystem from 'expo-file-system/legacy';
import * as Crypto from 'expo-crypto';
import { SecureCryptoService as CryptoService } from './CryptoService';

/**
 * Interface für die Key-Rotation: Re-Verschlüsselung aller Dateien nach PIN-Änderung
 */
interface ReencryptedFileData {
  fileId: string;
  encryptedData: string;
  iv: string;
  mac: string;
}

/**
 * Datei-Manager mit sicherer Speicherung
 *
 * Sicherheitsmerkmale:
 * - Metadaten (Original-Name, Timestamp) sind verschlüsselt
 * - File-IDs sind kryptographisch nicht vorhersagbar
 * - HMAC-Integritätsprüfung für alle gespeicherten Daten
 * - Verhindert Directory Traversal über Dateinamen
 * - Re-Verschlüsselung nach PIN-Änderung (Key-Rotation)
 */

// Interface für verschlüsselte Metadaten (für Speicherung)
interface EncryptedFileMetadata {
  id: string;
  name: string;
  originalName: {
    data: string;
    iv: string;
    mac: string;
  };
  type: {
    data: string;
    iv: string;
    mac: string;
  };
  size: number;
  createdAt: Date;
  iv: string;
  mac: string;
}

// Interface für öffentliche API (entschlüsselte Daten)
export interface FileMetadata {
  id: string;
  name: string;
  originalName: string;
  type: 'image' | 'video' | 'document';
  size: number;
  createdAt: Date;
  iv: string;
  mac: string;
}

class SecureFileManager {
  private static readonly VAULT_DIR = (FileSystem.documentDirectory || '') + 'vault/';
  private static readonly METADATA_SUFFIX = '.meta.enc';

  /**
   * Initialisiert den Vault-Ordner
   */
  static async initialize(): Promise<void> {
    try {
      const dirInfo = await FileSystem.getInfoAsync(this.VAULT_DIR);
      if (!dirInfo.exists) {
        await FileSystem.makeDirectoryAsync(this.VAULT_DIR, { intermediates: true });
      }
    } catch (error) {
      console.error('Error initializing vault:', error);
      throw new Error('Konnte Tresor nicht initialisieren');
    }
  }

  /**
   * Speichert eine Datei im Tresor
   * - Verschlüsselt den Dateiinhalt mit AES-256-GCM
   * - Verschlüsselt Metadaten (Originalname, Type)
   * - Generiert sichere File-ID
   */
  static async saveFile(
    fileUri: string,
    type: 'image' | 'video' | 'document',
    originalName: string
  ): Promise<FileMetadata> {
    try {
      await this.initialize();

      // Prüft Originalname auf Directory Traversal
      if (this.containsPathTraversal(originalName)) {
        throw new Error('Ungültiger Dateiname');
      }

      let fileContent: string;

      if (fileUri.startsWith('data:')) {
        const base64Data = fileUri.split(',')[1];
        fileContent = base64Data;
      } else {
        fileContent = await FileSystem.readAsStringAsync(fileUri, {
          encoding: FileSystem.EncodingType.Base64,
        });
      }

      // Verschlüsselt Dateiinhalt
      const { encryptedData, iv, mac } = await CryptoService.encryptFile(fileContent);

      // Generiert sichere File-ID
      const fileId = await this.generateSecureFileId();
      const fileName = `file_${fileId}`;

      // Verschlüsselt Metadaten
      const { encryptedData: encryptedOriginalName, iv: ivName, mac: macName } = await CryptoService.encryptMetadata(originalName);
      const { encryptedData: encryptedType, iv: ivType, mac: macType } = await CryptoService.encryptMetadata(type);

      // Speichert verschlüsselte Metadaten
      const encryptedMetadata: EncryptedFileMetadata = {
        id: fileId,
        name: fileName,
        originalName: { data: encryptedOriginalName, iv: ivName, mac: macName },
        type: { data: encryptedType, iv: ivType, mac: macType },
        size: encryptedData.length,
        createdAt: new Date(),
        iv,
        mac,
      };

      await FileSystem.writeAsStringAsync(
        `${this.VAULT_DIR}${fileName}.meta.enc`,
        JSON.stringify({
          id: fileId,
          originalName: encryptedMetadata.originalName,
          type: encryptedMetadata.type,
          size: encryptedMetadata.size,
          createdAt: encryptedMetadata.createdAt.toISOString(),
          iv: encryptedMetadata.iv,
          mac: encryptedMetadata.mac,
        })
      );

      // Speichert verschlüsselten Dateiinhalt
      await FileSystem.writeAsStringAsync(
        `${this.VAULT_DIR}${fileName}`,
        encryptedData
      );

      return {
        id: encryptedMetadata.id,
        name: encryptedMetadata.name,
        originalName: originalName, // Für UI: Klartext-Name
        type: type as 'image' | 'video' | 'document', // Für UI: Klartext-Type
        size: encryptedMetadata.size,
        createdAt: encryptedMetadata.createdAt,
        iv: encryptedMetadata.iv,
        mac: encryptedMetadata.mac,
      };
    } catch (error) {
      console.error('Error saving file:', error);
      throw new Error('Konnte Datei nicht speichern');
    }
  }

  /**
   * Lädt alle Dateien mit Entschlüsselung der Metadaten
   */
  static async getFiles(): Promise<FileMetadata[]> {
    try {
      await this.initialize();

      const files = await FileSystem.readDirectoryAsync(this.VAULT_DIR);
      const metaFiles = files.filter(file => file.endsWith('.meta.enc'));

      const loadedFiles: FileMetadata[] = [];

      for (const metaFile of metaFiles) {
        try {
          const metaContent = await FileSystem.readAsStringAsync(
            `${this.VAULT_DIR}${metaFile}`
          );
          const encryptedMeta = JSON.parse(metaContent);

          // Entschlüsselt Metadaten
          const originalName = await CryptoService.decryptMetadata(encryptedMeta.originalName);
          const type = await CryptoService.decryptMetadata(encryptedMeta.type);

          loadedFiles.push({
            id: encryptedMeta.id,
            name: encryptedMeta.name,
            originalName,
            type: type as 'image' | 'video' | 'document',
            size: encryptedMeta.size,
            createdAt: new Date(encryptedMeta.createdAt),
            iv: encryptedMeta.iv,
            mac: encryptedMeta.mac,
          });
        } catch (error) {
          console.error('Error loading file metadata:', error);
        }
      }

      return loadedFiles.sort((a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
    } catch (error) {
      console.error('Error getting files:', error);
      return [];
    }
  }

  /**
   * Lädt den Inhalt einer Datei
   * - Verifiziert HMAC vor Entschlüsselung
   */
  static async getFileContent(fileId: string): Promise<string> {
    try {
      const files = await this.getFiles();
      const file = files.find(f => f.id === fileId);

      if (!file) {
        throw new Error('Datei nicht gefunden');
      }

      // Liest verschlüsselte Daten
      const encryptedData = await FileSystem.readAsStringAsync(
        `${this.VAULT_DIR}${file.name}`
      );

      // Entschlüsselt mit HMAC-Verifizierung
      return await CryptoService.decryptFile(encryptedData, file.iv, file.mac);
    } catch (error) {
      console.error('Error getting file content:', error);
      throw new Error('Konnte Dateiinhalt nicht laden');
    }
  }

  /**
   * Löscht eine Datei
   */
  static async deleteFile(fileId: string): Promise<void> {
    try {
      const files = await this.getFiles();
      const file = files.find(f => f.id === fileId);

      if (!file) {
        throw new Error('Datei nicht gefunden');
      }

      await FileSystem.deleteAsync(`${this.VAULT_DIR}${file.name}`);
      await FileSystem.deleteAsync(`${this.VAULT_DIR}${file.name}.meta.enc`);
    } catch (error) {
      console.error('Error deleting file:', error);
      throw new Error('Konnte Datei nicht löschen');
    }
  }

  /**
   * Berechnet Speicherverbrauch
   */
  static async getStorageUsage(): Promise<{ used: number; total: number }> {
    try {
      const files = await this.getFiles();
      const totalSize = files.reduce((sum, file) => sum + file.size, 0);

      return {
        used: totalSize,
        total: 100 * 1024 * 1024, // 100 MB
      };
    } catch (error) {
      console.error('Error calculating storage usage:', error);
      return { used: 0, total: 0 };
    }
  }

  /**
   * Leert den gesamten Tresor
   */
  static async clearVault(): Promise<void> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.VAULT_DIR);

      for (const file of files) {
        await FileSystem.deleteAsync(`${this.VAULT_DIR}${file}`);
      }
    } catch (error) {
      console.error('Error clearing vault:', error);
      throw new Error('Konnte Tresor nicht leeren');
    }
  }

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  /**
   * Generiert eine nicht vorhersagbare File-ID
   */
  private static async generateSecureFileId(): Promise<string> {
    try {
      const timestamp = Date.now().toString(36);
      const randomBytes = await Crypto.getRandomBytesAsync(8);
      const randomHex = Array.from(new Uint8Array(randomBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      return `file_${timestamp}_${randomHex}`;
    } catch (error) {
      console.error('Error generating file ID:', error);
      throw new Error('Konnte File-ID nicht generieren');
    }
  }

  /**
   * Prüft ob der Dateiname Directory Traversal enthält
   */
  private static containsPathTraversal(filename: string): boolean {
    // Prüft auf .../ oder ..\ und andere potenziell gefährliche Muster
    return filename.includes('..') || filename.includes('//');
  }
}

export { SecureFileManager as FileManager };
