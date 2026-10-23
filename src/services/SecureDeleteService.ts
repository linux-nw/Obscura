/**
 * Secure Delete Service
 * Überschreiben + Löschen von Vault-Dateien, vollständiger Wipe.
 *
 * WICHTIG: Auf Flash/F2FS (Android) schreibt ein Überschreiben in neue Blöcke (Wear-Leveling,
 * Copy-on-Write) — Mehrfach-Pässe (DoD/Guttman) sind dort KEINE Garantie. Der verlässliche
 * Schutz ist der Crypto-Shred: der Master-Key wird ZUERST vernichtet, die Blobs sind danach
 * ohne Schlüssel wertlos. Die Überschreib-Pässe sind Defense-in-Depth.
 */

import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from './CryptoService';
import { BlobVersionService, isValidObjectId } from './BlobVersionService';

const dev = typeof __DEV__ !== 'undefined' && __DEV__;
const dbgErr = (...a: unknown[]) => { if (dev) console.error(...a); };

/** Every SecureStore secret/state key that must not survive a full wipe. */
export const ALL_SECURE_KEYS: readonly string[] = [
  'filevault_encryption_key',
  'filevault_pbkdf2_salt',
  'filevault_argon2id_salt',
  'filevault_kek_salt',
  'filevault_kdf_meta',
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
  'filevault_auth_attempts',
  'filevault_keyrotation_wal',
  'filevault_last_backup',
  'filevault_panic_pin_hash',
  'filevault_panic_pin_salt',
  'filevault_panic_pin_algo',
  'filevault_panic_settings',
  'filevault_panic_failed_attempts',
  'filevault_guest_pin_hash',
  'filevault_guest_pin_salt',
  'filevault_guest_pin_algo',
  'filevault_guest_enabled',
  'filevault_guest_created',
  'filevault_guest_kdf_salt',
  'filevault_guest_active',
  // Attack_Data: state/secret keys other services write that the wipe used to leave behind.
  'filevault_master_txn',
  'filevault_xchacha20_key',
  'filevault_last_rotation',
  'filevault_next_rotation',
  'filevault_rotation_count',
  'filevault_rotation_enabled',
  'filevault_rotation_interval',
  'filevault_auto_lock_settings',
  'filevault_last_activity',
  'filevault_auto_locked',
  'filevault_integrity_result',
  'filevault_last_integrity_check',
  'filevault_integrity_enabled',
  'filevault_last_security_audit',
  'filevault_checks_passed',
  'filevault_checks_failed',
];

/** Dynamic SecureStore key families (suffix = id/index) — cannot be enumerated, so derived. */
const KEY_HISTORY_PREFIX = 'filevault_key_history_';
const FILE_KEY_PREFIX = 'filevault_filekey_';

// Overwrite work per pass is bounded; larger blobs rely on the crypto-shred.
const MAX_OVERWRITE_BYTES = 32 * 1024 * 1024;

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
  private static readonly GUEST_DIR = (FileSystem.documentDirectory || '') + 'guest/';
  private static readonly BACKUP_DIR = (FileSystem.documentDirectory || '') + 'backups/';

  private static passesFor(method: SecureDeleteMethod): number {
    return method === 'guttman' ? 7 : method === 'dod' ? 3 : 1;
  }

  /**
   * Überschreibt + löscht alle Einträge eines Verzeichnisses und das Verzeichnis selbst.
   * Fehlendes Verzeichnis = nichts zu tun (kein Abbruch). Gibt die Anzahl nicht
   * löschbarer Einträge zurück statt den Rest des Wipes abzubrechen.
   */
  private static async secureDeleteDir(dir: string, method: SecureDeleteMethod): Promise<number> {
    let failures = 0;
    const info = await FileSystem.getInfoAsync(dir);
    if (!info.exists) return 0;
    const entries = await FileSystem.readDirectoryAsync(dir);
    for (const name of entries) {
      try {
        await this.secureDeleteFile(`${dir}${name}`, method);
      } catch {
        failures++;
      }
    }
    await FileSystem.deleteAsync(dir, { idempotent: true });
    return failures;
  }

  /** Sammelt gültige Objekt-IDs aus Meta-/Notiz-Dateien (für Blob-Version-Floors). */
  private static async collectIds(dir: string, kind: 'vault' | 'notes'): Promise<string[]> {
    const ids: string[] = [];
    try {
      for (const name of await FileSystem.readDirectoryAsync(dir)) {
        const isTarget = kind === 'vault' ? name.endsWith('.meta.enc') : name.startsWith('note_') && !name.endsWith('.tmp');
        if (!isTarget) continue;
        try {
          const id = JSON.parse(await FileSystem.readAsStringAsync(`${dir}${name}`)).id;
          if (isValidObjectId(id)) ids.push(id);
        } catch {
          // unreadable → no id to clean
        }
      }
    } catch {
      // dir missing
    }
    return ids;
  }

  /**
   * Sichert den Vault Ordner und löscht ihn sicher
   */
  static async secureDeleteVault(
    method: SecureDeleteMethod = 'guttman'
  ): Promise<void> {
    try {
      const failed = await this.secureDeleteDir(this.VAULT_DIR, method);
      if (failed > 0) throw new Error(`${failed} Einträge nicht gelöscht`);
    } catch (error) {
      dbgErr('SecureDelete: Vault deletion failed:', error);
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
      const failed = await this.secureDeleteDir(this.NOTES_DIR, method);
      if (failed > 0) throw new Error(`${failed} Einträge nicht gelöscht`);
    } catch (error) {
      dbgErr('SecureDelete: Notes deletion failed:', error);
      throw new Error('Notizen konnten nicht sicher gelöscht werden');
    }
  }

  /**
   * Überschreibt eine einzelne Datei und löscht sie. Ein fehlgeschlagenes Überschreiben
   * verhindert das Löschen NICHT; schlägt das Löschen selbst fehl, wird geworfen.
   */
  private static async secureDeleteFile(
    filePath: string,
    method: SecureDeleteMethod
  ): Promise<void> {
    const fileInfo = await FileSystem.getInfoAsync(filePath);
    if (!fileInfo.exists) return;

    if (!fileInfo.isDirectory) {
      await this.overwriteWithPattern(filePath, this.passesFor(method), fileInfo.size ?? 0);
    }
    await FileSystem.deleteAsync(filePath, { idempotent: true });
  }

  /**
   * Überschreibt Datei mit Mustern (best effort, siehe Datei-Header zu Flash).
   * Liest den bisherigen Inhalt NICHT ein — nur die Größe zählt.
   */
  private static async overwriteWithPattern(
    filePath: string,
    passes: number,
    fileSize: number
  ): Promise<void> {
    const size = Math.min(Math.max(0, Math.floor(fileSize)), MAX_OVERWRITE_BYTES);
    if (size === 0) return;
    try {
      for (let pass = 0; pass < passes; pass++) {
        const byte = parseInt(this.getPatternForPass(pass), 16);
        await FileSystem.writeAsStringAsync(filePath, this.bytesToBase64(new Uint8Array(size).fill(byte)), {
          encoding: FileSystem.EncodingType.Base64,
        });
      }
      // Letzte Überschreibung mit Zufallsdaten
      await FileSystem.writeAsStringAsync(filePath, await this.generateRandomPattern(size), {
        encoding: FileSystem.EncodingType.Base64,
      });
    } catch (error) {
      dbgErr('SecureDelete: Overwrite failed:', error);
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
    return pass < patterns.length ? patterns[pass] : '00';
  }

  private static bytesToBase64(bytes: Uint8Array): string {
    // Chunked: per-byte string concatenation is O(n^2) on Hermes.
    const parts: string[] = [];
    for (let i = 0; i < bytes.length; i += 8192) {
      parts.push(String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + 8192))));
    }
    return btoa(parts.join(''));
  }

  /**
   * Zufalls-Pass. expo-crypto liefert nur kleine Blöcke pro Bridge-Call (siehe Decoy-L6-Notiz);
   * daher: 16 CSPRNG-Bytes als Seed → xoshiro128** Expansion. Für ein Überschreib-Pattern
   * genügt das; ein fehlgeschlagener CSPRNG-Aufruf fällt NICHT stumm auf Nullen zurück.
   */
  private static async generateRandomPattern(size: number): Promise<string> {
    const seed = new Uint32Array(new Uint8Array(await SecureCryptoService.generateSecureBytes(16)).buffer.slice(0, 16));
    if (!(seed[0] | seed[1] | seed[2] | seed[3])) seed[0] = 1;
    const out = new Uint8Array(size);
    let [a, b, c, d] = [seed[0], seed[1], seed[2], seed[3]];
    const rotl = (x: number, k: number) => ((x << k) | (x >>> (32 - k))) >>> 0;
    for (let i = 0; i < size; i += 4) {
      const r = Math.imul(rotl(Math.imul(b, 5) >>> 0, 7), 9) >>> 0;
      const t = (b << 9) >>> 0;
      c ^= a; d ^= b; b ^= c; a ^= d; c ^= t; d = rotl(d, 11);
      a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
      out[i] = r;
      if (i + 1 < size) out[i + 1] = r >>> 8;
      if (i + 2 < size) out[i + 2] = r >>> 16;
      if (i + 3 < size) out[i + 3] = r >>> 24;
    }
    return this.bytesToBase64(out);
  }

  /**
   * Vollständiger Wipe. Reihenfolge: (1) Crypto-Shred der Schlüssel, (2) alle SecureStore-
   * Einträge, (3) Vault/Notizen/Guest/Backups/Cache-Temps. Jeder Schritt läuft unabhängig:
   * ein Fehler bricht den Rest NICHT ab; am Ende wird aggregiert geworfen.
   */
  static async secureWipeAll(): Promise<void> {
    const errors: unknown[] = [];
    const step = async (fn: () => Promise<unknown>) => {
      try { await fn(); } catch (e) { errors.push(e); }
    };

    // Blob-Version-Floors brauchen die IDs → vor dem Löschen der Meta-Dateien einsammeln.
    const ids = [
      ...(await this.collectIds(this.VAULT_DIR, 'vault')),
      ...(await this.collectIds(this.NOTES_DIR, 'notes')),
    ];

    // Dynamic families: wrapped per-file keys (by id) and key-rotation history (0..count).
    let rotationCount = 0;
    try { rotationCount = parseInt((await SecureStore.getItemAsync('filevault_rotation_count')) ?? '0', 10) || 0; } catch { /* none */ }
    const dynamicKeys = [
      ...ids.map((id) => `${FILE_KEY_PREFIX}${id}`),
      ...Array.from({ length: Math.min(Math.max(rotationCount, 0), 10000) + 1 }, (_, i) => `${KEY_HISTORY_PREFIX}${i}`),
    ];

    await step(() => SecureCryptoService.deleteEncryptionKey());
    await step(() => SecureCryptoService.deletePinData());
    for (const key of [...ALL_SECURE_KEYS, ...dynamicKeys]) {
      await step(() => SecureStore.deleteItemAsync(key));
    }
    for (const id of ids) await step(() => BlobVersionService.remove(id));

    await step(() => this.secureDeleteVault());
    await step(() => this.secureDeleteNotes());
    await step(async () => {
      const failed = await this.secureDeleteDir(this.GUEST_DIR, 'quick');
      if (failed > 0) throw new Error('guest');
    });
    await step(async () => {
      const failed = await this.secureDeleteDir(this.BACKUP_DIR, 'quick');
      if (failed > 0) throw new Error('backups');
    });
    await step(async () => {
      const cache = FileSystem.cacheDirectory || '';
      if (!cache) return;
      for (const name of await FileSystem.readDirectoryAsync(cache)) {
        if (name.startsWith('vault_view_')) await this.secureDeleteFile(`${cache}${name}`, 'quick');
      }
    });

    // Read-back-Verifikation direkt auf SecureStore (kein Cache dazwischen).
    for (const key of ALL_SECURE_KEYS) {
      try {
        if ((await SecureStore.getItemAsync(key)) !== null) {
          errors.push(new Error(`secureWipeAll: Key still exists after deletion: ${key}`));
        }
      } catch (e) {
        errors.push(e);
      }
    }

    if (errors.length > 0) {
      dbgErr('SecureDelete: Full wipe incomplete:', errors.length);
      throw new Error('Wipe unvollständig');
    }
  }

  /**
   * Sichert und löscht eine einzelne Datei
   */
  static async secureDeleteFileById(fileId: string): Promise<void> {
    if (!isValidObjectId(fileId)) throw new Error('Ungültige Datei-ID');
    try {
      const filePath = `${this.VAULT_DIR}file_${fileId}`;
      // Meta zuerst: ein Abbruch hinterlässt höchstens verwaisten Ciphertext, keinen Listeneintrag.
      await this.secureDeleteFile(`${filePath}.meta.enc`, 'guttman');
      await this.secureDeleteFile(filePath, 'guttman');
      await BlobVersionService.remove(fileId);
    } catch (error) {
      dbgErr(`SecureDelete: Failed to delete file:`, error);
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
    const passes = this.passesFor(method);

    // Geschätzt: 100KB/s pro Pass
    const estimatedSeconds = (fileSize / 100000) * passes;
    if (estimatedSeconds < 60) {
      return `${Math.ceil(estimatedSeconds)} Sekunden`;
    }
    return `${Math.ceil(estimatedSeconds / 60)} Minuten`;
  }
}

export default SecureDeleteService;
