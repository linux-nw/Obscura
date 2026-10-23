import * as FileSystem from 'expo-file-system/legacy';
import * as Crypto from 'expo-crypto';
import { SecureCryptoService as CryptoService } from './CryptoService';
import { writeFileAtomic, cleanupTempFiles } from './fsAtomic';
import { BlobVersionService, isValidObjectId, parseBlobVersion } from './BlobVersionService';

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
  version: number; // A3: blob version bound into the AAD
}

class SecureFileManager {
  private static readonly VAULT_DIR = (FileSystem.documentDirectory || '') + 'vault/';
  private static readonly METADATA_SUFFIX = '.meta.enc';
  // Cap on a single imported file (matches the 100 MB storage quota; also bounds JS-heap use).
  private static readonly MAX_IMPORT_BYTES = 100 * 1024 * 1024;
  // Startup-only sweeps: running them from every initialize() would delete live plaintext
  // view-temps of an open viewer and in-flight atomic temps.
  private static startupSweepDone = false;

  /**
   * Initialisiert den Vault-Ordner
   */
  static async initialize(): Promise<void> {
    try {
      const dirInfo = await FileSystem.getInfoAsync(this.VAULT_DIR);
      if (!dirInfo.exists) {
        await FileSystem.makeDirectoryAsync(this.VAULT_DIR, { intermediates: true });
      }
      if (!this.startupSweepDone) {
        this.startupSweepDone = true;
        // H3: drop any leftover .tmp from an interrupted atomic write.
        await cleanupTempFiles(this.VAULT_DIR);
        // Layer 5: sweep any plaintext view-temp left in cache by a previous crash/kill.
        await this.cleanupViewTemps();
      }
    } catch (error) {
      console.error('Error initializing vault:', error);
      throw new Error('Konnte Tresor nicht initialisieren');
    }
  }

  /**
   * Speichert eine Datei im Tresor
   * - Verschlüsselt den Dateiinhalt mit XChaCha20-Poly1305 (AES-CBC+HMAC als Fallback)
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
      if (this.containsPathTraversal(originalName) || !this.isValidType(type)) {
        throw new Error('Ungültiger Dateiname');
      }

      let fileContent: string;

      if (fileUri.startsWith('data:')) {
        const base64Data = fileUri.split(',')[1];
        fileContent = base64Data;
      } else {
        const info = await FileSystem.getInfoAsync(fileUri);
        if (info.exists && typeof info.size === 'number' && info.size > this.MAX_IMPORT_BYTES) {
          throw new Error('Datei zu groß');
        }
        fileContent = await FileSystem.readAsStringAsync(fileUri, {
          encoding: FileSystem.EncodingType.Base64,
        });
      }
      if (typeof fileContent !== 'string' || fileContent.length > Math.ceil(this.MAX_IMPORT_BYTES / 3) * 4) {
        throw new Error('Datei zu groß');
      }

      // Generiert sichere File-ID zuerst — wird als AAD-Kontext gebunden (H2)
      const fileId = await this.generateSecureFileId();
      const fileName = `file_${fileId}`;
      // A3: neue Version für dieses Objekt (Files sind immutable → bleibt v1).
      const version = await BlobVersionService.nextVersion(fileId);

      // Verschlüsselt Inhalt + Metadaten, gebunden an fileId:role:vN (H2 + A3)
      const { encryptedData, iv, mac } = await CryptoService.encryptFile(fileContent, `${fileId}:content:v${version}`);
      const { encryptedData: encryptedOriginalName, iv: ivName, mac: macName } = await CryptoService.encryptMetadata(originalName, `${fileId}:name:v${version}`);
      const { encryptedData: encryptedType, iv: ivType, mac: macType } = await CryptoService.encryptMetadata(type, `${fileId}:type:v${version}`);

      const createdAt = new Date();
      await writeFileAtomic(
        `${this.VAULT_DIR}${fileName}.meta.enc`,
        JSON.stringify({
          id: fileId,
          name: fileName,
          version,
          originalName: { data: encryptedOriginalName, iv: ivName, mac: macName },
          type: { data: encryptedType, iv: ivType, mac: macType },
          size: encryptedData.length,
          createdAt: createdAt.toISOString(),
          iv,
          mac,
        })
      );
      await writeFileAtomic(`${this.VAULT_DIR}${fileName}`, encryptedData);

      // A3: Floor erst NACH erfolgreichem (atomarem) Write anheben.
      await BlobVersionService.advanceTo(fileId, version);

      // F2: Lösche die Klartext-Kopie, die expo-document-picker/-image-picker
      // ins Cache-Verzeichnis gelegt hat. Sonst bleibt das unverschlüsselte
      // Original forensisch auslesbar im Cache liegen.
      await this.deletePlaintextCacheCopy(fileUri);

      return {
        id: fileId,
        name: fileName,
        originalName: originalName, // Für UI: Klartext-Name
        type: type as 'image' | 'video' | 'document', // Für UI: Klartext-Type
        size: encryptedData.length,
        createdAt,
        iv,
        mac,
        version,
      };
    } catch (error) {
      console.error('Error saving file:', error);
      throw new Error('Konnte Datei nicht speichern');
    }
  }

  /**
   * Importiert eine Datei aus bereits vorliegendem Base64-Klartext (z.B. beim
   * Backup-Restore). Verschlüsselt Inhalt + Metadaten mit dem AKTUELLEN Master-Key
   * und legt sie wie saveFile im Tresor ab.
   */
  static async importFile(
    base64Content: string,
    type: 'image' | 'video' | 'document',
    originalName: string,
    createdAtIso?: string
  ): Promise<FileMetadata> {
    await this.initialize();

    if (this.containsPathTraversal(originalName) || !this.isValidType(type)) {
      throw new Error('Ungültiger Dateiname');
    }
    if (typeof base64Content !== 'string' || base64Content.length > Math.ceil(this.MAX_IMPORT_BYTES / 3) * 4) {
      throw new Error('Datei zu groß');
    }

    const fileId = await this.generateSecureFileId();
    const fileName = `file_${fileId}`;
    let createdAt = createdAtIso ? new Date(createdAtIso) : new Date();
    if (isNaN(createdAt.getTime())) createdAt = new Date();
    const version = await BlobVersionService.nextVersion(fileId);

    const { encryptedData, iv, mac } = await CryptoService.encryptFile(base64Content, `${fileId}:content:v${version}`);
    const { encryptedData: encryptedOriginalName, iv: ivName, mac: macName } = await CryptoService.encryptMetadata(originalName, `${fileId}:name:v${version}`);
    const { encryptedData: encryptedType, iv: ivType, mac: macType } = await CryptoService.encryptMetadata(type, `${fileId}:type:v${version}`);

    await writeFileAtomic(
      `${this.VAULT_DIR}${fileName}.meta.enc`,
      JSON.stringify({
        id: fileId,
        name: fileName,
        version,
        originalName: { data: encryptedOriginalName, iv: ivName, mac: macName },
        type: { data: encryptedType, iv: ivType, mac: macType },
        size: encryptedData.length,
        createdAt: createdAt.toISOString(),
        iv,
        mac,
      })
    );
    await writeFileAtomic(`${this.VAULT_DIR}${fileName}`, encryptedData);
    await BlobVersionService.advanceTo(fileId, version);

    return {
      id: fileId,
      name: fileName,
      originalName,
      type,
      size: encryptedData.length,
      createdAt,
      iv,
      mac,
      version,
    };
  }

  /**
   * F2: Entfernt die vom Picker im Cache abgelegte Klartext-Kopie.
   *
   * Sicherheitsregel: löscht NUR Dateien innerhalb von FileSystem.cacheDirectory
   * — niemals Nutzer-Originale aus der Galerie/Storage. Die Picker kopieren das
   * gewählte Asset in unser App-Cache (DocumentPicker copyToCacheDirectory,
   * ImagePicker standardmäßig), daher liegt die URI im Cache.
   *
   * NAND-Disclaimer: deleteAsync entfernt nur den Verzeichniseintrag; auf
   * Flash-Speicher können Restblöcke bis zum Wear-Leveling-Überschreiben
   * verbleiben (nicht software-seitig garantiert tilgbar).
   */
  private static async deletePlaintextCacheCopy(fileUri: string): Promise<void> {
    try {
      if (!fileUri || fileUri.startsWith('data:')) return;
      const cacheDir = FileSystem.cacheDirectory || '';
      if (cacheDir && fileUri.startsWith(cacheDir) && !fileUri.includes('..')) {
        await FileSystem.deleteAsync(fileUri, { idempotent: true });
      }
    } catch {
      // best-effort: ein verbleibender Cache-Rest darf den Import nicht scheitern lassen
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
          // The id and version come from plaintext JSON: validate shape, and bind the id to
          // the on-disk filename so a copied/renamed meta cannot masquerade as another entry.
          if (!isValidObjectId(encryptedMeta.id) || metaFile !== `file_${encryptedMeta.id}${this.METADATA_SUFFIX}`) {
            console.warn('[Sec] meta id/filename mismatch — skipping');
            continue;
          }
          const version = parseBlobVersion(encryptedMeta.version);

          // A3: rollback check — a blob whose version is below the monotonic floor
          // was rolled back to a stale state. Skip it (do not surface stale content).
          const floor = await BlobVersionService.getFloor(encryptedMeta.id);
          if (version < floor) {
            console.warn(`[A3] rollback detected for file ${encryptedMeta.id}: v${version} < floor v${floor} — skipping`);
            continue;
          }

          // Entschlüsselt Metadaten (H2 + A3: an fileId:role:vN gebunden)
          const originalName = await CryptoService.decryptMetadata(encryptedMeta.originalName, `${encryptedMeta.id}:name:v${version}`);
          const type = await CryptoService.decryptMetadata(encryptedMeta.type, `${encryptedMeta.id}:type:v${version}`);

          // The stored `name` is unauthenticated plaintext (path-injection vector): always
          // derive the content path from the validated id.
          const fileName = `file_${encryptedMeta.id}`;
          loadedFiles.push({
            id: encryptedMeta.id,
            name: fileName,
            originalName,
            type: type as 'image' | 'video' | 'document',
            size: encryptedMeta.size,
            createdAt: new Date(encryptedMeta.createdAt),
            iv: encryptedMeta.iv,
            mac: encryptedMeta.mac,
            version,
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

      // Entschlüsselt mit HMAC-Verifizierung (H2 + A3: an fileId:content:vN gebunden)
      return await CryptoService.decryptFile(encryptedData, file.iv, file.mac, `${file.id}:content:v${file.version}`);
    } catch (error) {
      console.error('Error getting file content:', error);
      throw new Error('Konnte Dateiinhalt nicht laden');
    }
  }

  /**
   * Entschlüsselt eine Datei in eine TEMPORÄRE Klartext-Datei im App-Cache und
   * liefert deren file://-URI zurück. Wird vom In-App-Viewer für Inhalte gebraucht,
   * die nur über einen Datei-URI darstellbar sind (Video/Audio via expo-video) oder
   * an eine externe App übergeben werden (expo-sharing, z.B. PDF).
   *
   * SICHERHEIT: schreibt KLARTEXT in FileSystem.cacheDirectory (App-privat). Der
   * Aufrufer MUSS nach Gebrauch deleteTempFile(uri) aufrufen (Viewer-Close). Solange
   * die Datei existiert, liegt der Inhalt unverschlüsselt im App-Sandbox-Cache.
   *
   * NAND-Disclaimer: deleteAsync entfernt nur den Verzeichniseintrag; Restblöcke
   * können bis zum Wear-Leveling-Überschreiben verbleiben.
   */
  static async exportToTempFile(fileId: string): Promise<string> {
    const files = await this.getFiles();
    const file = files.find(f => f.id === fileId);
    if (!file) throw new Error('Datei nicht gefunden');

    const base64 = await this.getFileContent(fileId);

    const cacheDir = FileSystem.cacheDirectory || '';
    const ext = this.extensionOf(file.originalName);
    // Zufälliger Name, KEIN Originalname (kein Metadaten-Leak über Dateinamen).
    const rand = await this.generateSecureFileId();
    const tempUri = `${cacheDir}vault_view_${rand}${ext}`;

    try {
      await FileSystem.writeAsStringAsync(tempUri, base64, {
        encoding: FileSystem.EncodingType.Base64,
      });
    } catch (e) {
      await this.overwriteThenDelete(tempUri).catch(() => {}); // no partial plaintext left behind
      throw e;
    }
    return tempUri;
  }

  /**
   * Löscht eine via exportToTempFile erzeugte Klartext-Kopie. Löscht NUR innerhalb
   * von cacheDirectory (defensiv gegen versehentliches Löschen von Nutzerdaten).
   */
  static async deleteTempFile(uri: string): Promise<void> {
    try {
      const cacheDir = FileSystem.cacheDirectory || '';
      // Prefix match alone is bypassable with `..` segments; require a plain leaf name.
      if (uri && cacheDir && uri.startsWith(`${cacheDir}vault_view_`) && !/[\\/]|\.\./.test(uri.slice(cacheDir.length))) {
        await this.overwriteThenDelete(uri);
      }
    } catch {
      // best-effort
    }
  }

  /**
   * Layer 5: best-effort overwrite of a plaintext cache temp with zeros before deleting,
   * then delete. NAND-Disclaimer: on flash/wear-leveling the overwrite may hit a fresh
   * block, so this is defense-in-depth, not a guarantee — the reliable protection is that
   * the temp is short-lived and swept on lock/start (cleanupViewTemps), and that the
   * vault's at-rest data is crypto-shredded (master-key destruction) on wipe.
   */
  private static async overwriteThenDelete(uri: string): Promise<void> {
    try {
      const info = await FileSystem.getInfoAsync(uri);
      if (info.exists && typeof info.size === 'number' && info.size > 0) {
        const cap = Math.min(info.size, 2 * 1024 * 1024); // cap overwrite work at 2 MiB
        // base64 of zero bytes: 'AAAA' encodes 3 zero bytes → length scaled to cap.
        const zeros = 'A'.repeat(Math.ceil(cap / 3) * 4);
        await FileSystem.writeAsStringAsync(uri, zeros, { encoding: FileSystem.EncodingType.Base64 });
      }
    } catch {
      // overwrite is best-effort; still attempt deletion below
    }
    await FileSystem.deleteAsync(uri, { idempotent: true });
  }

  /**
   * Layer 5: sweep every leftover plaintext view-temp (vault_view_*) from the cache dir.
   * Called on app start and on lock so a crash/kill that left a decrypted temp behind does
   * not leave plaintext in the sandbox cache.
   */
  static async cleanupViewTemps(): Promise<void> {
    try {
      const cacheDir = FileSystem.cacheDirectory || '';
      if (!cacheDir) return;
      const entries = await FileSystem.readDirectoryAsync(cacheDir);
      await Promise.all(
        entries
          .filter(name => name.startsWith('vault_view_'))
          .map(name => this.overwriteThenDelete(`${cacheDir}${name}`).catch(() => {})),
      );
    } catch {
      // best-effort
    }
  }

  /**
   * Liefert die Dateiendung (inkl. Punkt, klein geschrieben) eines Namens, oder ''.
   */
  private static extensionOf(name: string): string {
    const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || '');
    return m ? `.${m[1].toLowerCase()}` : '';
  }

  /**
   * Re-verschlüsselt ALLE Datei-Inhalte + Metadaten vom alten auf den neuen
   * Master-Key (Key-Rotation). Pro Blob idempotent via CryptoService.recryptBlob,
   * daher crash-sicher wiederholbar.
   */
  static async reencryptAll(oldHandle: string, newHandle: string): Promise<void> {
    await this.initialize();
    const files = await FileSystem.readDirectoryAsync(this.VAULT_DIR);
    const metaFiles = files.filter(f => f.endsWith('.meta.enc'));

    for (const metaFile of metaFiles) {
      const metaPath = `${this.VAULT_DIR}${metaFile}`;
      const meta = JSON.parse(await FileSystem.readAsStringAsync(metaPath));
      if (!isValidObjectId(meta.id) || metaFile !== `file_${meta.id}${this.METADATA_SUFFIX}`) continue;
      const contentPath = `${this.VAULT_DIR}file_${meta.id}`;

      // Datei-Inhalt (Ciphertext separat, iv/mac in der Metadatei).
      // A3: dieselbe Version in alter+neuer AAD bewahren (recryptBlob ändert sie nicht).
      const contentData = await FileSystem.readAsStringAsync(contentPath);
      const fid = meta.id;
      const v = parseBlobVersion(meta.version);
      const newContent = await CryptoService.recryptBlob(
        { data: contentData, iv: meta.iv, mac: meta.mac },
        oldHandle,
        newHandle,
        `${fid}:content:v${v}`
      );
      const newOriginalName = await CryptoService.recryptBlob(meta.originalName, oldHandle, newHandle, `${fid}:name:v${v}`);
      const newType = await CryptoService.recryptBlob(meta.type, oldHandle, newHandle, `${fid}:type:v${v}`);

      // Inhalt zuerst, dann Metadatei schreiben (per-Blob-Idempotenz macht die
      // Reihenfolge unkritisch — ein Abbruch dazwischen wird sauber resümiert).
      // H3: atomic temp+rename so a crash never truncates a blob.
      await writeFileAtomic(contentPath, newContent.data);
      meta.iv = newContent.iv;
      meta.mac = newContent.mac;
      meta.originalName = newOriginalName;
      meta.type = newType;
      await writeFileAtomic(metaPath, JSON.stringify(meta));
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

      // Meta first: a half-finished delete must not leave a listable entry without content.
      await FileSystem.deleteAsync(`${this.VAULT_DIR}${file.name}.meta.enc`, { idempotent: true });
      await FileSystem.deleteAsync(`${this.VAULT_DIR}${file.name}`, { idempotent: true });
      await BlobVersionService.remove(fileId); // A3: random fileIds are never reused
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
        if (file.endsWith(this.METADATA_SUFFIX)) {
          try {
            const id = JSON.parse(await FileSystem.readAsStringAsync(`${this.VAULT_DIR}${file}`)).id;
            if (isValidObjectId(id)) await BlobVersionService.remove(id);
          } catch {
            // unreadable meta — nothing to clean
          }
        }
        await FileSystem.deleteAsync(`${this.VAULT_DIR}${file}`, { idempotent: true });
      }
    } catch (error) {
      console.error('Error clearing vault:', error);
      throw new Error('Konnte Tresor nicht leeren');
    }
  }

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  /**
   * Generiert eine nicht vorhersagbare File-ID (ohne Präfix).
   * Der Aufrufer ist verantwortlich für das Präfix im Dateinamen.
   */
  private static async generateSecureFileId(): Promise<string> {
    try {
      const timestamp = Date.now().toString(36);
      const randomBytes = await Crypto.getRandomBytesAsync(8);
      const randomHex = Array.from(new Uint8Array(randomBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      return `${timestamp}_${randomHex}`;
    } catch (error) {
      console.error('Error generating file ID:', error);
      throw new Error('Konnte File-ID nicht generieren');
    }
  }

  /**
   * Prüft ob der Dateiname Directory Traversal enthält
   */
  private static containsPathTraversal(filename: string): boolean {
    if (typeof filename !== 'string' || filename.length === 0 || filename.length > 255) return true;
    // Separators, '..', NUL/control chars and bidi overrides (display spoofing) are rejected.
    return /\.\.|[\/\\\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(filename);
  }

  /** Pre-flight check used by BackupService to validate a whole restore before importing. */
  static isImportable(type: unknown, originalName: unknown): boolean {
    return this.isValidType(type) && typeof originalName === 'string' && !this.containsPathTraversal(originalName);
  }

  private static isValidType(type: unknown): boolean {
    return type === 'image' || type === 'video' || type === 'document';
  }
}

export { SecureFileManager as FileManager };
