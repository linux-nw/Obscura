import * as FileSystem from 'expo-file-system/legacy';
import * as Crypto from 'expo-crypto';
import { SecureCryptoService as CryptoService } from './CryptoService';
import { writeFileAtomic, cleanupTempFiles } from './fsAtomic';
import { BlobVersionService } from './BlobVersionService';

/**
 * Notiz-Service mit sicherer Speicherung
 *
 * Sicherheitsmerkmale:
 * - Metadaten (Titel, Kategorien, Tags) sind verschlüsselt
 * - Notiz-ID ist nicht vorhersehbar (kryptographisch sicher)
 * - Verhindert Directory Traversal
 * - Hash-basierte Integritätsprüfung für Metadaten
 */

export interface Note {
  id: string;
  title: string;
  content: string;
  createdAt: Date;
  updatedAt: Date;
  category?: string;
  tags?: string[];
  isEncrypted: boolean;
}

class SecureNotesService {
  private static readonly NOTES_DIR = (FileSystem.documentDirectory || '') + 'notes/';
  private static readonly IV_LENGTH = 12;

  static async initialize(): Promise<void> {
    try {
      const dirInfo = await FileSystem.getInfoAsync(this.NOTES_DIR);
      if (!dirInfo.exists) {
        await FileSystem.makeDirectoryAsync(this.NOTES_DIR, { intermediates: true });
      }
      // H3: drop any leftover .tmp from an interrupted atomic write.
      await cleanupTempFiles(this.NOTES_DIR);
    } catch (error) {
      console.error('Error initializing notes directory:', error);
      throw new Error('Konnte Notizen-Verzeichnis nicht initialisieren');
    }
  }

  /**
   * Erstellt eine verschlüsselte Notiz
   * Verschlüsselt: Titel, Inhalt, Kategorien, Tags
   */
  static async createNote(
    title: string,
    content: string,
    category?: string,
    tags?: string[]
  ): Promise<Note> {
    try {
      await this.initialize();

      const noteId = await this.generateSecureNoteId();
      const now = new Date();
      const version = await BlobVersionService.nextVersion(noteId); // A3 (new → v1)

      // Verschlüsselt alle sensiblen Daten (H2 + A3: an noteId:role:vN gebunden)
      const { encryptedData: encryptedTitle, iv: ivTitle, mac: macTitle } = await this.encryptMetadata(title, `${noteId}:title:v${version}`);
      const { encryptedData: encryptedContent, iv: ivContent, mac: macContent } = await this.encryptContent(content, `${noteId}:content:v${version}`);
      const { encryptedData: encryptedCategory, iv: ivCategory, mac: macCategory } = await this.encryptMetadata(category || '', `${noteId}:category:v${version}`);
      const { encryptedData: encryptedTags, iv: ivTags, mac: macTags } = await this.encryptMetadata(JSON.stringify(tags || []), `${noteId}:tags:v${version}`);

      // Speichert vollständiges verschlüsseltes Note-Objekt in separater Datei
      const encryptedNote = {
        id: noteId,
        version,
        title: { data: encryptedTitle, iv: ivTitle, mac: macTitle },
        content: { data: encryptedContent, iv: ivContent, mac: macContent },
        category: { data: encryptedCategory, iv: ivCategory, mac: macCategory },
        tags: { data: encryptedTags, iv: ivTags, mac: macTags },
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
      };

      await writeFileAtomic(
        `${this.NOTES_DIR}note_${noteId}`,
        JSON.stringify(encryptedNote)
      );
      await BlobVersionService.advanceTo(noteId, version); // A3: floor after write

      // Return Klartext-Notiz für UI
      return {
        id: noteId,
        title,
        content,
        createdAt: now,
        updatedAt: now,
        category,
        tags,
        isEncrypted: true,
      };
    } catch (error) {
      console.error('Error creating note:', error);
      throw new Error('Konnte Notiz nicht erstellen');
    }
  }

  /**
   * Lädt alle Notizen mit Entschlüsselung
   */
  static async getNotes(): Promise<Note[]> {
    try {
      await this.initialize();

      const files = await FileSystem.readDirectoryAsync(this.NOTES_DIR);
      const noteFiles = files.filter(file => file.startsWith('note_'));

      const notes: Note[] = [];

      for (const noteFile of noteFiles) {
        try {
          const noteContent = await FileSystem.readAsStringAsync(
            `${this.NOTES_DIR}${noteFile}`
          );
          const encryptedNoteData = JSON.parse(noteContent);

          const nid = encryptedNoteData.id;
          const version: number = encryptedNoteData.version ?? 1;

          // A3: reject rolled-back notes (version below the monotonic floor).
          const floor = await BlobVersionService.getFloor(nid);
          if (version < floor) {
            console.warn(`[A3] rollback detected for note ${nid}: v${version} < floor v${floor} — skipping`);
            continue;
          }

          const title = await this.decryptMetadata(encryptedNoteData.title, `${nid}:title:v${version}`);
          const content = await this.decryptContent(encryptedNoteData.content, `${nid}:content:v${version}`);
          const category = await this.decryptMetadata(encryptedNoteData.category, `${nid}:category:v${version}`);
          const tagsRaw = await this.decryptMetadata(encryptedNoteData.tags, `${nid}:tags:v${version}`);
          const tags = JSON.parse(tagsRaw || '[]');

          notes.push({
            id: encryptedNoteData.id,
            title,
            content,
            createdAt: new Date(encryptedNoteData.createdAt),
            updatedAt: new Date(encryptedNoteData.updatedAt),
            category: category || undefined,
            tags: tags.length ? tags : undefined,
            isEncrypted: true,
          });
        } catch (error) {
          console.error('Error loading note:', error);
        }
      }

      return notes.sort((a, b) =>
        new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
      );
    } catch (error) {
      console.error('Error getting notes:', error);
      return [];
    }
  }

  /**
   * Lädt eine einzelne Notiz
   */
  static async getNoteById(noteId: string): Promise<Note | null> {
    try {
      const notes = await this.getNotes();
      return notes.find(note => note.id === noteId) || null;
    } catch (error) {
      console.error('Error getting note:', error);
      return null;
    }
  }

  /**
   * Aktualisiert eine Notiz
   */
  static async updateNote(
    noteId: string,
    updates: Partial<Omit<Note, 'id' | 'createdAt' | 'isEncrypted'>>
  ): Promise<Note | null> {
    try {
      await this.initialize();

      const notes = await this.getNotes();
      const existingNote = notes.find(note => note.id === noteId);

      if (!existingNote) {
        return null;
      }

      const now = new Date();
      const encryptedNoteData = await this.loadEncryptedNoteData(noteId);

      // A3: bump version. ALL fields are re-encrypted at the new version (even
      // unchanged ones) so the whole note shares one version — otherwise an
      // unchanged field would keep the old version and fail the read AAD check.
      const version = await BlobVersionService.nextVersion(noteId);

      const merged = {
        title: updates.title !== undefined ? updates.title : existingNote.title,
        content: updates.content !== undefined ? updates.content : existingNote.content,
        category: updates.category !== undefined ? (updates.category || '') : (existingNote.category || ''),
        tags: updates.tags !== undefined ? (updates.tags || []) : (existingNote.tags || []),
      };

      const t = await this.encryptMetadata(merged.title, `${noteId}:title:v${version}`);
      const c = await this.encryptContent(merged.content, `${noteId}:content:v${version}`);
      const cat = await this.encryptMetadata(merged.category, `${noteId}:category:v${version}`);
      const tg = await this.encryptMetadata(JSON.stringify(merged.tags), `${noteId}:tags:v${version}`);

      encryptedNoteData.version = version;
      encryptedNoteData.title = { data: t.encryptedData, iv: t.iv, mac: t.mac };
      encryptedNoteData.content = { data: c.encryptedData, iv: c.iv, mac: c.mac };
      encryptedNoteData.category = { data: cat.encryptedData, iv: cat.iv, mac: cat.mac };
      encryptedNoteData.tags = { data: tg.encryptedData, iv: tg.iv, mac: tg.mac };
      encryptedNoteData.updatedAt = now.toISOString();

      await writeFileAtomic(
        `${this.NOTES_DIR}note_${noteId}`,
        JSON.stringify(encryptedNoteData)
      );
      await BlobVersionService.advanceTo(noteId, version); // A3: floor after write

      return {
        ...existingNote,
        ...updates,
        updatedAt: now,
      };
    } catch (error) {
      console.error('Error updating note:', error);
      throw new Error('Konnte Notiz nicht aktualisieren');
    }
  }

  /**
   * Löscht eine Notiz (inklusive Metadaten)
   */
  static async deleteNote(noteId: string): Promise<boolean> {
    try {
      await this.initialize();
      await FileSystem.deleteAsync(`${this.NOTES_DIR}note_${noteId}`);
      await BlobVersionService.remove(noteId); // A3
      return true;
    } catch (error) {
      console.error('Error deleting note:', error);
      return false;
    }
  }

  /**
   * Sucht in Notizen (nur in Titel, da Inhalt verschlüsselt ist)
   * Für echte Inhaltssuche müsste man Index-Tabellen mit Hashs erstellen
   */
  static async searchNotes(query: string): Promise<Note[]> {
    try {
      const notes = await this.getNotes();
      const searchTerm = query.toLowerCase();

      return notes.filter(note =>
        note.title.toLowerCase().includes(searchTerm) ||
        note.category?.toLowerCase().includes(searchTerm) ||
        note.tags?.some((tag: string) => tag.toLowerCase().includes(searchTerm))
      );
    } catch (error) {
      console.error('Error searching notes:', error);
      return [];
    }
  }

  /**
   * Re-verschlüsselt ALLE Notiz-Felder vom alten auf den neuen Master-Key
   * (Key-Rotation). Pro Feld idempotent via CryptoService.recryptBlob; eine Notiz
   * wird mit einem einzigen Write komplett geschrieben (kein Feld-Mischzustand).
   */
  static async reencryptAll(oldHandle: string, newHandle: string): Promise<void> {
    await this.initialize();
    const files = await FileSystem.readDirectoryAsync(this.NOTES_DIR);
    const noteFiles = files.filter(file => file.startsWith('note_'));

    for (const noteFile of noteFiles) {
      const path = `${this.NOTES_DIR}${noteFile}`;
      const note = JSON.parse(await FileSystem.readAsStringAsync(path));
      const nid = note.id;
      const v = note.version ?? 1; // A3: preserve the same version in old+new AAD
      note.title = await CryptoService.recryptBlob(note.title, oldHandle, newHandle, `${nid}:title:v${v}`);
      note.content = await CryptoService.recryptBlob(note.content, oldHandle, newHandle, `${nid}:content:v${v}`);
      note.category = await CryptoService.recryptBlob(note.category, oldHandle, newHandle, `${nid}:category:v${v}`);
      note.tags = await CryptoService.recryptBlob(note.tags, oldHandle, newHandle, `${nid}:tags:v${v}`);
      await writeFileAtomic(path, JSON.stringify(note)); // H3: atomic
    }
  }

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  private static async loadEncryptedNoteData(noteId: string): Promise<any> {
    try {
      const content = await FileSystem.readAsStringAsync(
        `${this.NOTES_DIR}note_${noteId}`
      );
      return JSON.parse(content);
    } catch {
      throw new Error('Notiz nicht gefunden');
    }
  }

  private static async encryptContent(data: string, aadContext: string = ''): Promise<{ encryptedData: string; iv: string; mac: string }> {
    try {
      const { encryptedData, iv, mac } = await CryptoService.encryptData(data, aadContext);
      return { encryptedData, iv, mac };
    } catch {
      throw new Error('Kann Inhalt nicht verschlüsseln');
    }
  }

  private static async decryptContent(encrypted: { data: string; iv: string; mac: string }, aadContext: string = ''): Promise<string> {
    try {
      return await CryptoService.decryptData(encrypted.data, encrypted.iv, encrypted.mac, aadContext);
    } catch {
      throw new Error('Kann Inhalt nicht entschlüsseln');
    }
  }

  private static async encryptMetadata(data: string, aadContext: string = ''): Promise<{ encryptedData: string; iv: string; mac: string }> {
    try {
      return await this.encryptContent(data, aadContext);
    } catch {
      throw new Error('Kann Metadaten nicht verschlüsseln');
    }
  }

  private static async decryptMetadata(encrypted: { data: string; iv: string; mac: string }, aadContext: string = ''): Promise<string> {
    try {
      return await this.decryptContent(encrypted, aadContext);
    } catch {
      throw new Error('Kann Metadaten nicht entschlüsseln');
    }
  }

  /**
   * Generiert eine nicht vorhersehbare Note-ID
   * Kombiniert kryptographisch sichere Zufallsbytes mit Timestamp
   */
  private static async generateSecureNoteId(): Promise<string> {
    try {
      const timestamp = Date.now().toString(36);
      const randomBytes = await Crypto.getRandomBytesAsync(8);
      const randomHex = Array.from(new Uint8Array(randomBytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      return `note_${timestamp}_${randomHex}`;
    } catch (error) {
      console.error('Error generating note ID:', error);
      throw new Error('Konnte Note-ID nicht generieren');
    }
  }

  static async getCategories(): Promise<string[]> {
    try {
      const notes = await this.getNotes();
      const categories = new Set<string>();

      notes.forEach(note => {
        if (note.category) {
          categories.add(note.category);
        }
      });

      return Array.from(categories).sort();
    } catch (error) {
      console.error('Error getting categories:', error);
      return [];
    }
  }

  static async getTags(): Promise<string[]> {
    try {
      const notes = await this.getNotes();
      const tags = new Set<string>();

      notes.forEach(note => {
        note.tags?.forEach((tag: string) => tags.add(tag));
      });

      return Array.from(tags).sort();
    } catch (error) {
      console.error('Error getting tags:', error);
      return [];
    }
  }
}

export { SecureNotesService as NotesService };
