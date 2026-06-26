/**
 * Secure Backup Service
 * End-to-end verschlüsseltes Backup System
 *
 * Sicherheitsmerkmale:
 * - E2E Verschlüsselung (kein Backend Zugriff)
 * - Backup-Schlüssel via Argon2id (v3, memory-hard) + zufälligem Salt (H1)
 *   (v2 PBKDF2-SHA256 600k wird nur noch beim Restore akzeptiert, nie erzeugt)
 * - Encrypt-then-MAC über (iv || ciphertext)
 * - Mindest-Passphrase 12 Zeichen (S2), konsistent zur Vault-Untergrenze (H4)
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import * as Sharing from 'expo-sharing';
import CryptoJS from 'crypto-js';
import { SecureCryptoService } from './CryptoService';
import { Argon2idService, Argon2Params } from './Argon2idService';
import { fastPbkdf2 } from './FastPBKDF2';
import { FileManager } from './FileManager';
import { NotesService } from './NotesService';
import { SettingsService } from './SettingsService';

// Legacy v2: PBKDF2 iterations (accepted on restore, never produced anymore).
const BACKUP_PBKDF2_ITERATIONS = 600000;

// S2: raised 8 → 12, consistent with the vault passphrase floor (H4). The backup is a
// portable, offline-attackable artifact, so its passphrase is the weakest link and must
// not be weaker than the vault's. Enforced on WRITE (createBackup) only; existing backups
// made with a shorter passphrase remain restorable.
const BACKUP_MIN_PASSPHRASE = 12;

// H1: Argon2id parameters for backup key derivation (same hardness as the vault KEK,
// p=1 to match native libsodium — see C1). 16-byte salt: crypto_pwhash needs exactly 16.
const BACKUP_ARGON2: Argon2Params = {
  version: 0x13, type: 2, memoryKB: 65536, iterations: 3, parallelism: 1, hashLength: 32,
};

export interface BackupMetadata {
  version: string;
  timestamp: number;
  fileCount: number;
  noteCount: number;
  encrypted: boolean;
}

// v3 (current): backup key via Argon2id (memory-hard), Encrypt-then-MAC over (iv||ct).
// v2 (legacy): PBKDF2-600k — still ACCEPTED on restore, never produced.
// v1 (ancient): rejected (MAC was over plaintext).
export interface EncryptedBackupDataV2 {
  version: 2;
  backup: string;
  iv: string;
  tag: string;
  salt: string; // PBKDF2 salt (hex)
}
export interface EncryptedBackupDataV3 {
  version: 3;
  kdf: 'argon2id';
  kdfParams: { m: number; t: number; p: number };
  salt: string; // 16-byte Argon2id salt (hex)
  iv: string;   // 16-byte AES-CBC IV (hex)
  tag: string;  // HMAC-SHA256(macKey, iv || ciphertext)
  backup: string; // AES-256-CBC ciphertext (hex)
}
export type EncryptedBackupData = EncryptedBackupDataV2 | EncryptedBackupDataV3;

export class BackupService {
  private static readonly BACKUP_DIR = (FileSystem.documentDirectory || '') + 'backups/';
  private static readonly LAST_BACKUP_KEY = 'filevault_last_backup';

  static async initialize(): Promise<void> {
    try {
      const dirInfo = await FileSystem.getInfoAsync(this.BACKUP_DIR);
      if (!dirInfo.exists) {
        await FileSystem.makeDirectoryAsync(this.BACKUP_DIR, { intermediates: true });
      }
    } catch (error) {
      console.error('Backup: init failed:', error);
    }
  }

  // ─────────────────────────────── Backup Creation ───────────────────────────────

  static async createBackup(passphrase: string, includeSettings: boolean = false): Promise<string> {
    // H1: enforce a strong backup passphrase — the backup is portable plaintext.
    // Outside the try so the specific message reaches the caller.
    if (passphrase.normalize('NFC').length < BACKUP_MIN_PASSPHRASE) {
      throw new Error(`Backup-Passwort muss mindestens ${BACKUP_MIN_PASSPHRASE} Zeichen haben`);
    }
    try {
      await this.initialize();

      const files = await FileManager.getFiles();
      const notes = await NotesService.getNotes();

      // E2E-Backup: Klartext-Inhalte (entschlüsselt mit aktuellem Master-Key)
      // werden gleich darunter mit dem separaten Backup-Key verschlüsselt.
      // So ist das Backup portabel und unabhängig vom Vault-Master-Key.
      const fileEntries = await Promise.all(
        files.map(async (f) => ({
          originalName: f.originalName,
          type: f.type,
          size: f.size,
          createdAt: f.createdAt.toISOString(),
          content: await FileManager.getFileContent(f.id), // Base64-Klartext
        }))
      );

      const backupData: Record<string, unknown> = {
        version: '2.0',
        timestamp: Date.now(),
        files: fileEntries,
        notes: notes.map((n) => ({
          id: n.id,
          title: n.title,
          content: n.content,
          category: n.category,
          tags: n.tags,
          createdAt: n.createdAt.toISOString(),
          updatedAt: n.updatedAt.toISOString(),
        })),
      };
      if (includeSettings) {
        backupData.settings = await SettingsService.get();
      }

      const encrypted = await this.encryptBackup(JSON.stringify(backupData), passphrase);

      const backupId = this.generateBackupId();
      const backupPath = `${this.BACKUP_DIR}backup_${backupId}.json`;
      await FileSystem.writeAsStringAsync(backupPath, JSON.stringify(encrypted));
      await SecureStore.setItemAsync(this.LAST_BACKUP_KEY, Date.now().toString());

      return backupId;
    } catch (error) {
      console.error('Backup: create failed:', error);
      throw new Error('Backup konnte nicht erstellt werden');
    }
  }

  // ─────────────────────────────── Encryption ───────────────────────────────

  private static async encryptBackup(
    data: string,
    passphrase: string
  ): Promise<EncryptedBackupDataV3> {
    // H1: derive the backup key with Argon2id (memory-hard), 16-byte salt.
    const saltBuf = await SecureCryptoService.generateSecureBytes(16);
    const saltHex = SecureCryptoService.bufferToHex(saltBuf);
    const keyBuf = await Argon2idService.deriveKey(passphrase.normalize('NFC'), saltBuf, BACKUP_ARGON2);
    const backupKey = SecureCryptoService.bufferToHex(keyBuf);

    // AES-256-CBC with backup key and fresh IV.
    const ivBuf = await SecureCryptoService.generateSecureBytes(16);
    const ivHex = SecureCryptoService.bufferToHex(ivBuf);

    const keyWords = CryptoJS.enc.Hex.parse(backupKey);
    const ivWords  = CryptoJS.enc.Hex.parse(ivHex);
    const cipher = CryptoJS.AES.encrypt(data, keyWords, {
      iv: ivWords,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const ciphertextHex = cipher.ciphertext.toString(CryptoJS.enc.Hex);

    // Encrypt-then-MAC: tag covers (iv || ciphertext) — not plaintext.
    const macKey = await SecureCryptoService.deriveMacKey(backupKey);
    const tag = await SecureCryptoService.computeMac(macKey, ivHex + ciphertextHex);

    return {
      version: 3,
      kdf: 'argon2id',
      kdfParams: { m: BACKUP_ARGON2.memoryKB, t: BACKUP_ARGON2.iterations, p: BACKUP_ARGON2.parallelism },
      salt: saltHex,
      iv: ivHex,
      tag,
      backup: ciphertextHex,
    };
  }

  // ─────────────────────────────── Backup Restore ───────────────────────────────

  static async restoreBackup(passphrase: string, backupId: string): Promise<boolean> {
    try {
      const backupPath = `${this.BACKUP_DIR}backup_${backupId}.json`;
      const content = await FileSystem.readAsStringAsync(backupPath);
      const encryptedData = JSON.parse(content);

      // Accept v3 (Argon2id, current) and v2 (PBKDF2, legacy). Reject v1/unknown.
      if (encryptedData.version !== 2 && encryptedData.version !== 3) {
        throw new Error('Nicht unterstütztes Backup-Format');
      }

      const plaintext = await this.decryptBackup(encryptedData as EncryptedBackupData, passphrase);
      await this.applyBackupData(plaintext);
      return true;
    } catch (error) {
      console.error('Backup: restore failed:', error);
      return false;
    }
  }

  private static async applyBackupData(plaintext: string): Promise<void> {
    const data = JSON.parse(plaintext) as {
      files?: { originalName: string; type: 'image' | 'video' | 'document'; content: string; createdAt?: string }[];
      notes?: { title: string; content: string; category?: string; tags?: string[] }[];
      settings?: any;
    };
    for (const f of data.files ?? []) {
      if (!f || typeof f.content !== 'string') continue;
      await FileManager.importFile(f.content, f.type, f.originalName, f.createdAt);
    }
    for (const n of data.notes ?? []) {
      if (!n) continue;
      await NotesService.createNote(n.title, n.content, n.category, n.tags);
    }
    if (data.settings) {
      await SettingsService.save(data.settings);
    }
  }

  static async shareBackup(backupId: string): Promise<void> {
    const backupPath = `${this.BACKUP_DIR}backup_${backupId}.json`;
    await Sharing.shareAsync(backupPath, {
      mimeType: 'application/json',
      dialogTitle: 'Backup speichern',
      UTI: 'public.json',
    });
  }

  static async importBackupFromFile(passphrase: string, fileUri: string): Promise<boolean> {
    try {
      const content = await FileSystem.readAsStringAsync(fileUri);
      const encryptedData = JSON.parse(content);
      if (encryptedData.version !== 2 && encryptedData.version !== 3) {
        throw new Error('Nicht unterstütztes Backup-Format');
      }
      const plaintext = await this.decryptBackup(encryptedData as EncryptedBackupData, passphrase);
      await this.applyBackupData(plaintext);
      return true;
    } catch (error) {
      console.error('Backup: importFromFile failed:', error);
      return false;
    }
  }

  private static async decryptBackup(
    encrypted: EncryptedBackupData,
    passphrase: string
  ): Promise<string> {
    // Re-derive backup key from stored salt — Argon2id (v3) or legacy PBKDF2 (v2).
    let backupKey: string;
    if (encrypted.version === 3) {
      const saltBuf = SecureCryptoService.hexToBuffer(encrypted.salt);
      const params: Argon2Params = {
        version: 0x13, type: 2,
        memoryKB: encrypted.kdfParams.m,
        iterations: encrypted.kdfParams.t,
        parallelism: encrypted.kdfParams.p,
        hashLength: 32,
      };
      const keyBuf = await Argon2idService.deriveKey(passphrase.normalize('NFC'), saltBuf, params);
      backupKey = SecureCryptoService.bufferToHex(keyBuf);
    } else {
      backupKey = await fastPbkdf2(passphrase.normalize('NFC'), encrypted.salt, BACKUP_PBKDF2_ITERATIONS, 32);
    }

    // Verify MAC over (iv || ciphertext) BEFORE decrypting.
    const macKey = await SecureCryptoService.deriveMacKey(backupKey);
    const expectedTag = await SecureCryptoService.computeMac(macKey, encrypted.iv + encrypted.backup);
    if (!await SecureCryptoService.constantsTimeEquals(expectedTag, encrypted.tag)) {
      throw new Error('Backup Integrität verletzt — falsches Passwort oder Datei beschädigt');
    }

    const keyWords = CryptoJS.enc.Hex.parse(backupKey);
    const ivWords  = CryptoJS.enc.Hex.parse(encrypted.iv);
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(encrypted.backup),
    });
    const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWords, {
      iv: ivWords,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    if (!plaintext) throw new Error('Backup Entschlüsselung fehlgeschlagen');
    return plaintext;
  }

  // ─────────────────────────────── Backup Management ───────────────────────────────

  static async listBackups(): Promise<{ id: string; timestamp: number; size: number }[]> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.BACKUP_DIR);
      const backupFiles = files.filter((f) => f.startsWith('backup_') && f.endsWith('.json'));
      const backups: { id: string; timestamp: number; size: number }[] = [];

      for (const file of backupFiles) {
        try {
          const filePath = `${this.BACKUP_DIR}${file}`;
          const info = await FileSystem.getInfoAsync(filePath);
          if (info.exists) {
            backups.push({
              id: file.replace('backup_', '').replace('.json', ''),
              timestamp: Date.now(),
              size: info.size ?? 0,
            });
          }
        } catch {
          // Skip invalid backups
        }
      }

      return backups.sort((a, b) => b.timestamp - a.timestamp);
    } catch {
      return [];
    }
  }

  static async deleteBackup(backupId: string): Promise<void> {
    const filePath = `${this.BACKUP_DIR}backup_${backupId}.json`;
    await FileSystem.deleteAsync(filePath);
  }

  static async deleteAllBackups(): Promise<void> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.BACKUP_DIR);
      for (const file of files.filter((f) => f.startsWith('backup_') && f.endsWith('.json'))) {
        await FileSystem.deleteAsync(`${this.BACKUP_DIR}${file}`);
      }
    } catch (error) {
      console.error('Backup: deleteAll failed:', error);
    }
  }

  static async autoBackup(passphrase: string): Promise<void> {
    try {
      const lastBackup = await SecureStore.getItemAsync(this.LAST_BACKUP_KEY);
      if (!lastBackup) {
        await this.createBackup(passphrase);
        return;
      }
      const oneWeek = 7 * 24 * 60 * 60 * 1000;
      if (Date.now() - parseInt(lastBackup, 10) > oneWeek) {
        await this.createBackup(passphrase);
      }
    } catch (error) {
      console.error('Backup: autoBackup failed:', error);
    }
  }

  static async hasBackups(): Promise<boolean> {
    return (await this.listBackups()).length > 0;
  }

  static async getBackupStatus(): Promise<{ lastBackup: number | null; backupCount: number; totalSize: number }> {
    try {
      const lastBackup = await SecureStore.getItemAsync(this.LAST_BACKUP_KEY);
      const backups = await this.listBackups();
      return {
        lastBackup: lastBackup ? parseInt(lastBackup, 10) : null,
        backupCount: backups.length,
        totalSize: backups.reduce((sum, b) => sum + b.size, 0),
      };
    } catch {
      return { lastBackup: null, backupCount: 0, totalSize: 0 };
    }
  }

  private static generateBackupId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `${timestamp}_${random}`;
  }
}

export default BackupService;
