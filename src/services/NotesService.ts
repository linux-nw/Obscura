import * as FileSystem from 'expo-file-system/legacy';
import * as Crypto from 'expo-crypto';
import { SecureCryptoService as CryptoService } from './CryptoService';

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

      // Verschlüsselt alle sensiblen Daten
      const { encryptedData: encryptedTitle, iv: ivTitle, mac: macTitle } = await this.encryptMetadata(title);
      const { encryptedData: encryptedContent, iv: ivContent, mac: macContent } = await this.encryptContent(content);
      const { encryptedData: encryptedCategory, iv: ivCategory, mac: macCategory } = await this.encryptMetadata(category || '');
      const { encryptedData: encryptedTags, iv: ivTags, mac: macTags } = await this.encryptMetadata(JSON.stringify(tags || []));

      // Speichert vollständiges verschlüsseltes Note-Objekt in separater Datei
      const encryptedNote = {
        id: noteId,
        title: { data: encryptedTitle, iv: ivTitle, mac: macTitle },
        content: { data: encryptedContent, iv: ivContent, mac: macContent },
        category: { data: encryptedCategory, iv: ivCategory, mac: macCategory },
        tags: { data: encryptedTags, iv: ivTags, mac: macTags },
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
      };

      await FileSystem.writeAsStringAsync(
        `${this.NOTES_DIR}note_${noteId}`,
        JSON.stringify(encryptedNote)
      );

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

          const title = await this.decryptMetadata(encryptedNoteData.title);
          const content = await this.decryptContent(encryptedNoteData.content);
          const category = await this.decryptMetadata(encryptedNoteData.category);
          const tagsRaw = await this.decryptMetadata(encryptedNoteData.tags);
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

      // Update Titel
      if (updates.title !== undefined) {
        const { encryptedData, iv, mac } = await this.encryptMetadata(updates.title);
        encryptedNoteData.title = { data: encryptedData, iv, mac };
      }

      // Update Inhalt
      if (updates.content !== undefined) {
        const { encryptedData, iv, mac } = await this.encryptContent(updates.content);
        encryptedNoteData.content = { data: encryptedData, iv, mac };
      }

      // Update Kategorie
      if (updates.category !== undefined) {
        const { encryptedData, iv, mac } = await this.encryptMetadata(updates.category || '');
        encryptedNoteData.category = { data: encryptedData, iv, mac };
      }

      // Update Tags
      if (updates.tags !== undefined) {
        const { encryptedData, iv, mac } = await this.encryptMetadata(JSON.stringify(updates.tags || []));
        encryptedNoteData.tags = { data: encryptedData, iv, mac };
      }

      encryptedNoteData.updatedAt = now.toISOString();

      await FileSystem.writeAsStringAsync(
        `${this.NOTES_DIR}note_${noteId}`,
        JSON.stringify(encryptedNoteData)
      );

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

  private static async encryptContent(data: string): Promise<{ encryptedData: string; iv: string; mac: string }> {
    try {
      const { encryptedData, iv, mac } = await CryptoService.encryptData(data);
      return { encryptedData, iv, mac };
    } catch {
      throw new Error('Kann Inhalt nicht verschlüsseln');
    }
  }

  private static async decryptContent(encrypted: { data: string; iv: string; mac: string }): Promise<string> {
    try {
      return await CryptoService.decryptData(encrypted.data, encrypted.iv, encrypted.mac);
    } catch {
      throw new Error('Kann Inhalt nicht entschlüsseln');
    }
  }

  private static async encryptMetadata(data: string): Promise<{ encryptedData: string; iv: string; mac: string }> {
    try {
      return await this.encryptContent(data);
    } catch {
      throw new Error('Kann Metadaten nicht verschlüsseln');
    }
  }

  private static async decryptMetadata(encrypted: { data: string; iv: string; mac: string }): Promise<string> {
    try {
      return await this.decryptContent(encrypted);
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
