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
  // L6: salt for the content-encryption KDF — SEPARATE from the PIN-hash salt so the
  // stored PIN hash can never double as the content key. Public; the key is never stored.
  private static readonly DECOY_KDF_SALT = 'filevault_guest_kdf_salt';

  // S1: same Argon2id hardness class as the vault KEK / Panic PIN. p=1 matches native
  // libsodium crypto_pwhash (C1); 16-byte salt. Native preferred, @noble JS fallback.
  private static readonly DECOY_ARGON2: Argon2Params = {
    version: 0x13, type: 2, memoryKB: 65536, iterations: 3, parallelism: 1, hashLength: 32,
  };
  private static readonly LEGACY_PBKDF2_ITERATIONS = 10000;

  // L6 / L3 Phase 2: guest content-encryption key, derived from the guest PIN via Argon2id
  // over DECOY_KDF_SALT, held for the active guest session as a SEPARATE custody handle that
  // coexists with the real master handle in KeyCustody. Never persisted, so a SecureStore
  // dump alone cannot decrypt the guest blobs; recovering the key costs the same Argon2id
  // work as cracking the PIN. Populated by setDecoyPin()/unlockDecoyContent(), closed by
  // clearDecoyCache()/destroyDecoyVault(). The guest path is fully separate from the master
  // path — a guest session never touches the master handle.
  // Residual (2a, JS-backed): the derived key still lives in the JS heap inside KeyCustody;
  // 2b moves it to native secure memory. See §15 Layer 3 / Layer 6.
  private static _contentHandle: string | null = null;

  /** Register (or clear) the guest content key as its own custody handle. */
  private static setContentKey(keyHex: string | null): void {
    if (this._contentHandle) {
      SecureCryptoService.closeKeyHandle(this._contentHandle); // zero + drop previous guest key
      this._contentHandle = null;
    }
    if (keyHex) this._contentHandle = SecureCryptoService.registerKeyHandle(keyHex);
  }

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
    const handle = this._contentHandle;
    if (!handle) {
      throw new Error('Guest content key not unlocked — set the guest PIN first');
    }
    try {
      await this.initialize();
      await this.clearEntries('file_'); // also clears file_*.meta

      // L6: credible, size-matched fakes. Content is CSPRNG bytes (rendered as hex) then
      // XChaCha20-encrypted with the guest key — on disk an opaque blob, not the old
      // 'fake_data_placeholder' stub. `size` equals the bytes actually generated, so there
      // is no claimed-vs-actual size differential to flag the file as fake. The metadata
      // itself is encrypted too (no plaintext filenames/sizes on disk).
      const fakeFiles = [
        { originalName: 'holiday_photo.jpg', type: 'image' as const, bytes: 65536 },
        { originalName: 'family_clip.mp4', type: 'video' as const, bytes: 98304 },
        { originalName: 'work_document.pdf', type: 'document' as const, bytes: 32768 },
      ];

      for (const f of fakeFiles) {
        const fileId = this.generateId();
        const filePath = `${this.DECOY_DIR}file_${fileId}`;
        const metaPath = `${filePath}.meta`;

        const content = await this.randomHex(f.bytes);
        await FileSystem.writeAsStringAsync(filePath, await this.seal(content, handle, `guest:file:${fileId}`));

        const meta = { name: `file_${fileId}`, originalName: f.originalName, type: f.type, size: f.bytes };
        await FileSystem.writeAsStringAsync(metaPath, await this.seal(JSON.stringify(meta), handle, `guest:meta:${fileId}`));
      }

      await SecureStore.setItemAsync(this.DECOY_CREATED_KEY, Date.now().toString());
      console.log('GuestVault: Fake files created (encrypted)');
    } catch (error) {
      console.error('GuestVault: Failed to create fake files:', error);
    }
  }

  /**
   * Erstellt Fake Notizen
   */
  static async createFakeNotes(): Promise<void> {
    const handle = this._contentHandle;
    if (!handle) {
      throw new Error('Guest content key not unlocked — set the guest PIN first');
    }
    try {
      await this.initialize();
      await this.clearEntries('note_');

      const fakeNotes = [
        { title: 'Bank Account', content: 'Bank: XYZ Bank, IBAN: DE00 1234 5678 9012 3456 78' },
        { title: 'Password List', content: 'Gmail: sunshine2021\nFacebook: hunter2!\nNetflix: family#vault' },
        { title: 'Secret Recipe', content: "Grandma's cookie recipe: 250g butter, 200g sugar, 1 egg, vanilla..." },
      ];

      for (const note of fakeNotes) {
        const noteId = this.generateId();
        const notePath = `${this.DECOY_DIR}note_${noteId}`;
        const payload = JSON.stringify({
          id: noteId,
          title: note.title,
          content: note.content,
          createdAt: new Date().toISOString(),
        });
        // L6: encrypted on disk (was plaintext JSON) — no readable fake notes leaking.
        await FileSystem.writeAsStringAsync(notePath, await this.seal(payload, handle, `guest:note:${noteId}`));
      }

      console.log('GuestVault: Fake notes created (encrypted)');
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

  // ─────────────────────────────── Content Encryption (L6) ───────────────────────────────

  /**
   * L6: get-or-create the 16-byte content-KDF salt. Separate from the PIN-hash salt
   * (DECOY_PIN_SALT). Salt is public, so storing it leaks nothing.
   */
  private static async getOrCreateContentKdfSalt(): Promise<string> {
    let salt = await SecureStore.getItemAsync(this.DECOY_KDF_SALT);
    if (!salt) {
      const saltBytes = await CryptoModule.getRandomBytesAsync(16);
      salt = Array.from(new Uint8Array(saltBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      await SecureStore.setItemAsync(this.DECOY_KDF_SALT, salt);
    }
    return salt;
  }

  /**
   * L6: derive the 32-byte guest content key from the guest PIN via Argon2id (same
   * hardness class as the vault KEK). Never stored.
   */
  private static async deriveContentKey(pin: string): Promise<string> {
    const saltHex = await this.getOrCreateContentKdfSalt();
    const saltBuffer = SecureCryptoService.hexToBuffer(saltHex);
    const derived = await Argon2idService.deriveKey(pin.normalize('NFC'), saltBuffer, this.DECOY_ARGON2);
    return SecureCryptoService.bufferToHex(derived);
  }

  /**
   * L6: derive + cache the guest content key for the active session. Call when the guest
   * PIN unlocks the decoy view (AuthScreen). Without this getFake*() cannot read anything.
   */
  static async unlockDecoyContent(pin: string): Promise<void> {
    this.setContentKey(await this.deriveContentKey(pin));
  }

  /**
   * L6: drop the in-memory guest content key (call on logout).
   */
  static clearDecoyCache(): void {
    this.setContentKey(null);
  }

  /**
   * L6: encrypt a string into an on-disk envelope using the guest content key. Reuses the
   * vault's XChaCha20-Poly1305 AEAD via encryptDataWithHandle() with the guest content
   * handle — it never touches the master handle, so the real vault crypto path is unaffected.
   * aadContext
   * binds the blob to its slot (prevents swapping). On disk the result is opaque ciphertext,
   * indistinguishable from a real vault blob.
   */
  private static async seal(plaintext: string, handle: string, aadContext: string): Promise<string> {
    const { encryptedData, iv, mac } = await SecureCryptoService.encryptDataWithHandle(plaintext, handle, aadContext);
    return JSON.stringify({ c: encryptedData, iv, mac });
  }

  /**
   * L6: inverse of seal(). Throws if the key is wrong or the blob is tampered (AEAD fail).
   */
  private static async open(envelope: string, handle: string, aadContext: string): Promise<string> {
    const { c, iv, mac } = JSON.parse(envelope);
    return SecureCryptoService.decryptDataWithHandle(c, iv, mac, handle, aadContext);
  }

  /**
   * L6: nBytes of CSPRNG output rendered as hex — the credible "file payload" before
   * encryption. Random bytes encrypt to ciphertext indistinguishable from a real file.
   */
  private static async randomHex(nBytes: number): Promise<string> {
    // Decoy filler of the claimed file size (tens of KB). It is XChaCha20-sealed before it
    // ever hits disk, so the on-disk blob is full-size opaque ciphertext regardless of the
    // plaintext's entropy — the plaintext is never exposed without the guest PIN. So instead
    // of thousands of CSPRNG bytes (expo-crypto caps getRandomBytesAsync at 1024/call, and
    // chunking it into ~hundreds of bridge calls HANGS on-device), take one small random seed
    // and expand it. One bridge call, O(n), and within the 1024 cap.
    const seedBuf = await CryptoModule.getRandomBytesAsync(256);
    const seed = Array.from(new Uint8Array(seedBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''); // 512 hex chars
    const target = nBytes * 2; // 2 hex chars per byte
    return seed.repeat(Math.ceil(target / seed.length)).slice(0, target);
  }

  /**
   * L6: delete existing guest entries with the given prefix (idempotent re-create).
   */
  private static async clearEntries(prefix: string): Promise<void> {
    try {
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      for (const file of files) {
        if (file.startsWith(prefix)) {
          await FileSystem.deleteAsync(`${this.DECOY_DIR}${file}`).catch(() => {});
        }
      }
    } catch {
      // dir may not exist yet — nothing to clear
    }
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
      // L6: (re)key guest content. A fresh content-KDF salt is generated so changing the
      // guest PIN re-keys every guest blob; cache the derived key so createFake*() can
      // encrypt immediately after.
      await SecureStore.deleteItemAsync(this.DECOY_KDF_SALT);
      this.setContentKey(await this.deriveContentKey(pin));
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
    const handle = this._contentHandle;
    if (!handle) return []; // guest content key not unlocked → nothing readable
    try {
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      const decoyFiles: DecoyFile[] = [];

      for (const file of files) {
        if (file.startsWith('file_') && file.endsWith('.meta')) {
          const id = file.replace('file_', '').replace('.meta', '');
          try {
            const envelope = await FileSystem.readAsStringAsync(`${this.DECOY_DIR}${file}`);
            const data = JSON.parse(await this.open(envelope, handle, `guest:meta:${id}`));
            decoyFiles.push({
              id,
              name: data.name,
              originalName: data.originalName, // L6: now present (was never written before)
              type: data.type,
              size: data.size,
              createdAt: new Date(),
            });
          } catch {
            // wrong key or tampered blob → skip
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
    const handle = this._contentHandle;
    if (!handle) return []; // guest content key not unlocked → nothing readable
    try {
      const files = await FileSystem.readDirectoryAsync(this.DECOY_DIR);
      const decoyNotes: DecoyNote[] = [];

      for (const file of files) {
        if (file.startsWith('note_')) {
          const id = file.replace('note_', '');
          try {
            const envelope = await FileSystem.readAsStringAsync(`${this.DECOY_DIR}${file}`);
            const data = JSON.parse(await this.open(envelope, handle, `guest:note:${id}`));
            decoyNotes.push({
              id: data.id,
              title: data.title,
              content: data.content,
              createdAt: new Date(data.createdAt),
              category: data.category,
            });
          } catch {
            // wrong key or tampered blob → skip
          }
        }
      }

      return decoyNotes;
    } catch {
      return [];
    }
  }

  // ─────────────────────────────── Guest Writes (L6) ───────────────────────────────
  //
  // Interactive writes INTO the guest vault. The decoy view must be writable to be
  // credible (a guest who can only read is a tell). Every write is sealed with the guest
  // content key into guest/ — never the master key, never notes/ or vault/. Crucially the
  // guest path uses NO BlobVersionService and NO shared SecureStore counter: a guest write
  // leaves no identifier (version, counter, sequential id) that an analyst could correlate
  // with the real vault, consistent with the §15.2 deniability boundary. IDs are the same
  // base36-timestamp+random shape the real vault already uses, so they add no new
  // distinguisher. Fail-closed: without the guest content key these THROW rather than
  // writing anything in the clear.

  /**
   * L6: create/update a note inside the guest vault. Sealed with the guest key.
   */
  static async saveNote(
    title: string,
    content: string,
    category?: string,
    id?: string,
  ): Promise<DecoyNote> {
    const handle = this._contentHandle;
    if (!handle) {
      throw new Error('Guest content key not unlocked — set the guest PIN first');
    }
    await this.initialize();
    const noteId = id ?? this.generateId();
    const createdAt = new Date().toISOString();
    const payload = JSON.stringify({ id: noteId, title, content, category: category || undefined, createdAt });
    await FileSystem.writeAsStringAsync(
      `${this.DECOY_DIR}note_${noteId}`,
      await this.seal(payload, handle, `guest:note:${noteId}`),
    );
    return { id: noteId, title, content, category: category || undefined, createdAt: new Date(createdAt) };
  }

  /**
   * L6: import a file into the guest vault. Reads the picked file's bytes (base64) and
   * seals content + metadata separately, mirroring createFakeFiles' on-disk layout.
   */
  static async saveFile(
    fileUri: string,
    type: 'image' | 'video' | 'document',
    originalName: string,
  ): Promise<DecoyFile> {
    const handle = this._contentHandle;
    if (!handle) {
      throw new Error('Guest content key not unlocked — set the guest PIN first');
    }
    await this.initialize();

    let base64: string;
    if (fileUri.startsWith('data:')) {
      base64 = fileUri.split(',')[1] ?? '';
    } else {
      base64 = await FileSystem.readAsStringAsync(fileUri, { encoding: FileSystem.EncodingType.Base64 });
    }

    const fileId = this.generateId();
    const filePath = `${this.DECOY_DIR}file_${fileId}`;
    const size = Math.floor((base64.length * 3) / 4); // approx decoded byte length

    await FileSystem.writeAsStringAsync(filePath, await this.seal(base64, handle, `guest:file:${fileId}`));
    const meta = { name: `file_${fileId}`, originalName, type, size };
    await FileSystem.writeAsStringAsync(`${filePath}.meta`, await this.seal(JSON.stringify(meta), handle, `guest:meta:${fileId}`));

    return { id: fileId, name: `file_${fileId}`, originalName, type, size, createdAt: new Date() };
  }

  /**
   * L6: decrypt a guest file's content to base64. Fail-closed (throws without the key).
   */
  static async getFakeFileContent(id: string): Promise<string> {
    const handle = this._contentHandle;
    if (!handle) {
      throw new Error('Guest content key not unlocked — set the guest PIN first');
    }
    const envelope = await FileSystem.readAsStringAsync(`${this.DECOY_DIR}file_${id}`);
    return this.open(envelope, handle, `guest:file:${id}`);
  }

  /**
   * L6: decrypt a guest file into a temporary plaintext cache copy for the in-app viewer.
   * Mirrors FileManager.exportToTempFile — caller MUST FileManager.deleteTempFile(uri) on
   * close (the L5 plaintext-cache sweep covers the same cacheDirectory).
   */
  static async exportFakeToTempFile(id: string): Promise<string> {
    const files = await this.getFakeFiles();
    const file = files.find(f => f.id === id);
    if (!file) throw new Error('Datei nicht gefunden');

    const base64 = await this.getFakeFileContent(id);
    const cacheDir = FileSystem.cacheDirectory || '';
    const dot = file.originalName.lastIndexOf('.');
    const ext = dot >= 0 ? file.originalName.slice(dot) : '';
    const tempUri = `${cacheDir}vault_view_${this.generateId()}${ext}`;
    await FileSystem.writeAsStringAsync(tempUri, base64, { encoding: FileSystem.EncodingType.Base64 });
    return tempUri;
  }

  /**
   * L6: delete a guest note.
   */
  static async deleteNote(id: string): Promise<void> {
    await FileSystem.deleteAsync(`${this.DECOY_DIR}note_${id}`).catch(() => {});
  }

  /**
   * L6: delete a guest file (content + metadata).
   */
  static async deleteFile(id: string): Promise<void> {
    await FileSystem.deleteAsync(`${this.DECOY_DIR}file_${id}`).catch(() => {});
    await FileSystem.deleteAsync(`${this.DECOY_DIR}file_${id}.meta`).catch(() => {});
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
      await SecureStore.deleteItemAsync(this.DECOY_KDF_SALT); // L6: content-KDF salt
      this.setContentKey(null); // L6: zero + drop any cached guest content key

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
