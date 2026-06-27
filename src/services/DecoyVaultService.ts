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
import { Argon2idService, Argon2Params } from './Argon2idService';
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
  // L6: deniable naming. On-disk/SecureStore artifacts MUST NOT contain the literal
  // string "decoy" — that single word lets a forensic string-grep flag exactly which
  // credential set / directory is the fake one (and, by elimination, prove the real
  // vault is the hidden one). Everything is framed as a benign "guest" profile, blending
  // with the real vault's filevault_* / vault/ / notes/ / backups/ naming family. This
  // defeats naive grep forensics; it does NOT hide the feature from an analyst who
  // recognises the app (see §15 Layer 6 deniability ceiling).
  private static readonly DECOY_DIR = (FileSystem.documentDirectory || '') + 'guest/';
  private static readonly DECOY_PIN_HASH = 'filevault_guest_pin_hash';
  private static readonly DECOY_PIN_SALT = 'filevault_guest_pin_salt';
  // S1: KDF marker. 'argon2id' = current; absent = legacy PBKDF2-10k (migrated on verify).
  private static readonly DECOY_PIN_ALGO = 'filevault_guest_pin_algo';
  private static readonly DECOY_ENABLED_KEY = 'filevault_guest_enabled';
  private static readonly DECOY_CREATED_KEY = 'filevault_guest_created';

  // S1: same Argon2id hardness class as the vault KEK / Panic PIN. p=1 matches native
  // libsodium crypto_pwhash (C1); 16-byte salt. Native preferred, @noble JS fallback.
  private static readonly DECOY_ARGON2: Argon2Params = {
    version: 0x13, type: 2, memoryKB: 65536, iterations: 3, parallelism: 1, hashLength: 32,
  };
  private static readonly LEGACY_PBKDF2_ITERATIONS = 10000;

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
      console.log('GuestVault: Service initialized with AES-256');
    } catch (error) {
      console.error('Error initializing GuestVault:', error);
    }
  }

  /**
   * Aktiviert den Decoy Vault
   */
  static async enableDecoyVault(): Promise<void> {
    try {
      await this.initialize();
      await SecureStore.setItemAsync(this.DECOY_ENABLED_KEY, 'true');
      console.log('GuestVault: guest vault enabled');
    } catch (error) {
      console.error('Error enabling guest vault:', error);
    }
  }

  /**
   * Deaktiviert den Decoy Vault
   */
  static async disableDecoyVault(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.DECOY_ENABLED_KEY);
      console.log('GuestVault: guest vault disabled');
    } catch (error) {
      console.error('Error disabling guest vault:', error);
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
      console.log('GuestVault: Fake files created');
    } catch (error) {
      console.error('GuestVault: Failed to create fake files:', error);
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

      console.log('GuestVault: Fake notes created');
    } catch (error) {
      console.error('GuestVault: Failed to create fake notes:', error);
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
      await SecureStore.setItemAsync(this.DECOY_PIN_ALGO, 'argon2id');
      console.log('GuestVault: guest PIN set (Argon2id)');
    } catch (error) {
      console.error('Error setting guest pin:', error);
      throw error instanceof Error ? error : new Error('Konnte PIN nicht setzen');
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

      const algo = await SecureStore.getItemAsync(this.DECOY_PIN_ALGO);

      if (algo === 'argon2id') {
        const { hash } = await this.computePinHash(pin, storedSalt);
        return await SecureCryptoService.constantsTimeEquals(hash, storedHash);
      }

      // S1 migration: legacy PBKDF2-10k hash (no marker). Verify the old way, then
      // transparently re-hash with Argon2id on success. No lockout for existing users.
      const legacyHash = await this.computePinHashLegacy(pin, storedSalt);
      const match = await SecureCryptoService.constantsTimeEquals(legacyHash, storedHash);
      if (match) {
        try {
          await this.setDecoyPin(pin);
        } catch {
          // Keep the legacy hash if migration write fails — verification already succeeded.
        }
      }
      return match;
    } catch (error) {
      console.error('GuestVault: PIN verification error:', error);
      return false;
    }
  }

  /**
   * Berechnet Decoy PIN Hash mit Argon2id (S1).
   * Memory-hard (m=64 MiB, t=3, p=1); native libsodium bevorzugt, @noble JS-Fallback.
   * KEIN stiller PBKDF2-Downgrade.
   */
  private static async computePinHash(
    pin: string,
    salt?: string
  ): Promise<{ hash: string; salt: string }> {
    if (!salt) {
      // 16-byte salt (crypto_pwhash_SALTBYTES).
      const saltBytes = await CryptoModule.getRandomBytesAsync(16);
      salt = Array.from(new Uint8Array(saltBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    }
    // R-03: NFC-normalisieren, sonst leiten NFD/NFC-Eingaben verschiedene Keys ab.
    const saltBuffer = SecureCryptoService.hexToBuffer(salt);
    const derived = await Argon2idService.deriveKey(pin.normalize('NFC'), saltBuffer, this.DECOY_ARGON2);
    return { hash: SecureCryptoService.bufferToHex(derived), salt };
  }

  /**
   * Legacy-Verifikationspfad (PBKDF2-10k): NUR zum Prüfen und anschließenden Migrieren
   * vorhandener pre-S1-Hashes. Wird nie mehr zum Speichern verwendet.
   */
  private static async computePinHashLegacy(pin: string, salt: string): Promise<string> {
    return fastPbkdf2(pin.normalize('NFC'), salt, this.LEGACY_PBKDF2_ITERATIONS, 32);
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
      console.log('GuestVault: Destroying vault...');

      // Lösche alle Dateien
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      for (const file of files) {
        await FileSystem.deleteAsync(`${this.DECOY_DIR}${file}`);
      }

      // Disable vault
      await SecureStore.deleteItemAsync(this.DECOY_ENABLED_KEY);
      await SecureStore.deleteItemAsync(this.DECOY_PIN_HASH);
      await SecureStore.deleteItemAsync(this.DECOY_PIN_SALT);
      await SecureStore.deleteItemAsync(this.DECOY_PIN_ALGO);

      console.log('GuestVault: Vault destroyed');
    } catch (error) {
      console.error('GuestVault: Destroy failed:', error);
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
      console.log('GuestVault: Vault reset complete');
    } catch (error) {
      console.error('GuestVault: Reset failed:', error);
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
