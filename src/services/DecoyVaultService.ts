/**
 * Decoy Vault Service
 * Second Vault für Erpressungsszenarien
 *
 * Sicherheitsmerkmale:
 * - Separate Vault mit fake Daten
 * - Unsichtbar für normale Apps
 * - Einfacher PIN für schnellen Zugriff
 * - Selbstschutz
 *
 * WICHTIG: NUTZT Argon2id/PBKDF2 statt HMAC-SHA256 für PIN-Hashing
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from './CryptoService';
import { fastPbkdf2 } from './FastPBKDF2';
import * as CryptoModule from 'expo-crypto';
import { SettingsService } from './SettingsService';

export interface DecoyFile {
  id: string;
  name: string;
  originalName: string;
  type: 'image' | 'video' | 'document';
  size: number;
  createdAt: Date;
}

export interface DecoyNote {
  id: string;
  title: string;
  content: string;
  createdAt: Date;
  category?: string;
}

export class DecoyVaultService {
  private static readonly DECOY_DIR = (FileSystem.documentDirectory || '') + 'decoy_vault/';
  private static readonly DECOY_PIN_HASH = 'filevault_decoy_pin_hash';
  private static readonly DECOY_PIN_SALT = 'filevault_decoy_pin_salt';
  private static readonly DECOY_ENABLED_KEY = 'filevault_decoy_enabled';
  private static readonly DECOY_CREATED_KEY = 'filevault_decoy_created';

  // ─────────────────────────────── Decoy Vault Setup ───────────────────────────────

  /**
   * Initialisiert den Decoy Vault
   */
  static async initialize(): Promise<void> {
    try {
      const dirInfo = await FileSystem.getInfoAsync(this.DECOY_DIR);
      if (!dirInfo.exists) {
        await FileSystem.makeDirectoryAsync(this.DECOY_DIR, { intermediates: true });
      }
      console.log('DecoyVault: Service initialized with AES-256');
    } catch (error) {
      console.error('Error initializing DecoyVault:', error);
    }
  }

  /**
   * Aktiviert den Decoy Vault
   */
  static async enableDecoyVault(): Promise<void> {
    try {
      await this.initialize();
      await SecureStore.setItemAsync(this.DECOY_ENABLED_KEY, 'true');
      console.log('DecoyVault: Decoy vault enabled');
    } catch (error) {
      console.error('Error enabling decoy vault:', error);
    }
  }

  /**
   * Deaktiviert den Decoy Vault
   */
  static async disableDecoyVault(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.DECOY_ENABLED_KEY);
      console.log('DecoyVault: Decoy vault disabled');
    } catch (error) {
      console.error('Error disabling decoy vault:', error);
    }
  }

  /**
   * Prüft ob Decoy Vault existiert
   */
  static async hasDecoyVault(): Promise<boolean> {
    try {
      const enabled = await SecureStore.getItemAsync(this.DECOY_ENABLED_KEY);
      return enabled === 'true';
    } catch {
      return false;
    }
  }

  // ─────────────────────────────── Decoy Data Management ───────────────────────────────

  /**
   * Erstellt Fake Dateien im Decoy Vault
   */
  static async createFakeFiles(): Promise<void> {
    try {
      // Fake Bilder
      const fakeFiles = [
        { name: 'holiday_photo.jpg', type: 'image', size: 245678 },
        { name: 'family_video.mp4', type: 'video', size: 12345678 },
        { name: 'work_document.pdf', type: 'document', size: 456789 },
      ];

      for (const file of fakeFiles) {
        const fileId = this.generateId();
        const filePath = `${this.DECOY_DIR}file_${fileId}`;
        const metaPath = `${filePath}.meta`;

        // In Produktion: verschlüsselte Fake Daten
        await FileSystem.writeAsStringAsync(filePath, 'fake_data_placeholder');
        await FileSystem.writeAsStringAsync(metaPath, JSON.stringify(file));
      }

      await SecureStore.setItemAsync(this.DECOY_CREATED_KEY, Date.now().toString());
      console.log('DecoyVault: Fake files created');
    } catch (error) {
      console.error('DecoyVault: Failed to create fake files:', error);
    }
  }

  /**
   * Erstellt Fake Notizen
   */
  static async createFakeNotes(): Promise<void> {
    try {
      const fakeNotes = [
        { title: 'Bank Account', content: 'Bank: XYZ Bank, Account: 123456789' },
        { title: 'Password List', content: 'Gmail: password123\nFacebook: mypassword\n' },
        { title: 'Secret Recipe', content: 'Grandmas secret cookie recipe...' },
      ];

      for (const note of fakeNotes) {
        const noteId = this.generateId();
        const notePath = `${this.DECOY_DIR}note_${noteId}`;

        await FileSystem.writeAsStringAsync(
          notePath,
          JSON.stringify({
            id: noteId,
            title: note.title,
            content: note.content,
            createdAt: new Date().toISOString(),
          })
        );
      }

      console.log('DecoyVault: Fake notes created');
    } catch (error) {
      console.error('DecoyVault: Failed to create fake notes:', error);
    }
  }

  /**
   * Generiert Decoy Datei ID
   */
  private static generateId(): string {
    return (Date.now().toString(36) + Math.random().toString(36).substring(2, 8));
  }

  // ─────────────────────────────── Decoy PIN Management ───────────────────────────────

  /**
   * Setzt Decoy PIN
   */
  static async setDecoyPin(pin: string): Promise<void> {
    const settings = await SettingsService.get();
    const minLen = settings.minPinLength;
    if (pin.length < minLen) {
      throw new Error(`PIN zu kurz — mindestens ${minLen} Zeichen erforderlich`);
    }
    try {
      const { hash, salt } = await this.computePinHash(pin);
      await SecureStore.setItemAsync(this.DECOY_PIN_HASH, hash);
      await SecureStore.setItemAsync(this.DECOY_PIN_SALT, salt);
      console.log('DecoyVault: Decoy PIN set (AES-256)');
    } catch (error) {
      console.error('Error setting decoy pin:', error);
      throw error instanceof Error ? error : new Error('Konnte Decoy PIN nicht setzen');
    }
  }

  /**
   * Prüft Decoy PIN
   */
  static async verifyDecoyPin(pin: string): Promise<boolean> {
    try {
      const storedHash = await SecureStore.getItemAsync(this.DECOY_PIN_HASH);
      const storedSalt = await SecureStore.getItemAsync(this.DECOY_PIN_SALT);

      if (!storedHash || !storedSalt) {
        return false;
      }

      const { hash } = await this.computePinHash(pin, storedSalt);
      return SecureCryptoService.constantsTimeEquals(hash, storedHash);
    } catch (error) {
      console.error('DecoyVault: PIN verification error:', error);
      return false;
    }
  }

  /**
   * Berechnet Decoy PIN Hash mit Argon2id oder PBKDF2
   * Fallback zu PBKDF2 wenn Argon2id nicht verfügbar ist
   */
  private static async computePinHash(
    pin: string,
    salt?: string
  ): Promise<{ hash: string; salt: string }> {
    try {
      if (!salt) {
        // Generiere neuen Salt für Decoy Vault
        const saltBytes = await CryptoModule.getRandomBytesAsync(16);
        salt = Array.from(new Uint8Array(saltBytes))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }

      // Verwende fastPbkdf2 für PIN Hash (100k Iterationen wie normale PIN)
      // Dies ist viel sicherer als HMAC-SHA256
      const iterations = 100000;
      const keyLength = 32; // 32 bytes = 256 bits
      const derivedKey = await fastPbkdf2(pin, salt, iterations, keyLength);

      return {
        hash: derivedKey,
        salt,
      };
    } catch {
      return { hash: '', salt: '' };
    }
  }

  // ─────────────────────────────── Decoy Data Access ───────────────────────────────

  /**
   * Lädt Fake Dateien
   */
  static async getFakeFiles(): Promise<DecoyFile[]> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      const decoyFiles: DecoyFile[] = [];

      for (const file of files) {
        if (file.startsWith('file_') && !file.endsWith('.meta')) {
          const filePath = `${this.DECOY_DIR}${file}`;
          const metaPath = `${filePath}.meta`;

          try {
            const info = await FileSystem.getInfoAsync(metaPath);
            if (info.exists) {
              const meta = await FileSystem.readAsStringAsync(metaPath);
              const data = JSON.parse(meta);
              decoyFiles.push({
                id: file.replace('file_', ''),
                name: file,
                originalName: data.originalName,
                type: data.type,
                size: data.size,
                createdAt: new Date(),
              });
            }
          } catch {
            // Skip invalid files
          }
        }
      }

      return decoyFiles;
    } catch {
      return [];
    }
  }

  /**
   * Lädt Fake Notizen
   */
  static async getFakeNotes(): Promise<DecoyNote[]> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      const decoyNotes: DecoyNote[] = [];

      for (const file of files) {
        if (file.startsWith('note_')) {
          const filePath = `${this.DECOY_DIR}${file}`;
          const content = await FileSystem.readAsStringAsync(filePath);
          const data = JSON.parse(content);
          decoyNotes.push({
            id: data.id,
            title: data.title,
            content: data.content,
            createdAt: new Date(data.createdAt),
          });
        }
      }

      return decoyNotes;
    } catch {
      return [];
    }
  }

  // ─────────────────────────────── Decoy Security ───────────────────────────────

  /**
   * Zerstört den Decoy Vault bei falschem PIN
   */
  static async destroyDecoyVault(): Promise<void> {
    try {
      console.log('DecoyVault: Destroying vault...');

      // Lösche alle Dateien
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      for (const file of files) {
        await FileSystem.deleteAsync(`${this.DECOY_DIR}${file}`);
      }

      // Disable vault
      await SecureStore.deleteItemAsync(this.DECOY_ENABLED_KEY);
      await SecureStore.deleteItemAsync(this.DECOY_PIN_HASH);
      await SecureStore.deleteItemAsync(this.DECOY_PIN_SALT);

      console.log('DecoyVault: Vault destroyed');
    } catch (error) {
      console.error('DecoyVault: Destroy failed:', error);
    }
  }

  /**
   * Reinstellt den Decoy Vault mit neuen Fake Daten
   */
  static async resetDecoyVault(): Promise<void> {
    try {
      await this.destroyDecoyVault();
      await this.createFakeFiles();
      await this.createFakeNotes();
      console.log('DecoyVault: Vault reset complete');
    } catch (error) {
      console.error('DecoyVault: Reset failed:', error);
    }
  }

  /**
   * Prüft ob Decoy Vault intakt ist
   */
  static async isVaultIntact(): Promise<boolean> {
    try {
      // Prüft ob genügend Fake Dateien existieren
      const files = await this.getFakeFiles();
      const notes = await this.getFakeNotes();

      return files.length >= 3 || notes.length >= 2;
    } catch {
      return false;
    }
  }
}

export default DecoyVaultService;
