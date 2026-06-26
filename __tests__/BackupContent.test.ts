/**
 * BackupContent.test.ts — end-to-end backup with REAL content.
 *
 * Previously createBackup stored `content: f.iv` (the IV, not the ciphertext) and
 * restoreBackup decrypted the blob then threw it away. Now createBackup bundles the
 * decrypted file bytes + note fields, and restoreBackup re-imports them (re-encrypted
 * with the current master key).
 *
 * Verifies: create → wipe vault → restore reproduces file content and notes.
 */

const secureStore = require('../__mocks__/expo-secure-store');

// Stateful in-memory FS (factory closes over mock-prefixed store; survives ESM-interop copy).
const mockBakStore = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockBakStore.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockBakStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockBakStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockBakStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockBakStore.get(from);
    if (v !== undefined) { mockBakStore.set(to, v); mockBakStore.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockBakStore.has(p) || [...mockBakStore.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'),
    size: (mockBakStore.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockBakStore.keys()) {
      if (k.startsWith(dir)) {
        const rest = k.slice(dir.length);
        if (rest.length && !rest.includes('/')) names.add(rest);
      }
    }
    return [...names];
  }),
}));

beforeEach(() => {
  secureStore._reset();
  mockBakStore.clear();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { BackupService } from '../src/services/BackupService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';

const VAULT_PASS = 'VaultPass123!';
const BACKUP_PASS = 'BackupPass456!';
const FILE_CONTENT_B64 = Buffer.from('the-real-file-bytes 🔐').toString('base64');

function wipeVaultContent() {
  for (const k of [...mockBakStore.keys()]) {
    if (k.startsWith('/mock/documents/vault/') || k.startsWith('/mock/documents/notes/')) {
      mockBakStore.delete(k);
    }
  }
}

test('createBackup → wipe → restoreBackup reproduces file content + notes', async () => {
  await SecureCryptoService.setupMasterKey(VAULT_PASS);
  await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');
  await NotesService.createNote('Titel', 'Geheimer Inhalt 🔑', 'privat', ['x']);

  const backupId = await BackupService.createBackup(BACKUP_PASS);
  expect(backupId).toBeTruthy();

  // Wipe all vault + note content (master key stays).
  wipeVaultContent();
  expect((await FileManager.getFiles()).length).toBe(0);
  expect((await NotesService.getNotes()).length).toBe(0);

  const ok = await BackupService.restoreBackup(BACKUP_PASS, backupId);
  expect(ok).toBe(true);

  const files = await FileManager.getFiles();
  expect(files.length).toBe(1);
  expect(files[0].originalName).toBe('secret.txt');
  expect(await FileManager.getFileContent(files[0].id)).toBe(FILE_CONTENT_B64);

  const notes = await NotesService.getNotes();
  expect(notes.length).toBe(1);
  expect(notes[0].title).toBe('Titel');
  expect(notes[0].content).toBe('Geheimer Inhalt 🔑');
}, 120000);

test('restoreBackup with wrong passphrase fails and imports nothing', async () => {
  await SecureCryptoService.setupMasterKey(VAULT_PASS);
  await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');

  const backupId = await BackupService.createBackup(BACKUP_PASS);
  wipeVaultContent();

  const ok = await BackupService.restoreBackup('wrong-backup-pass', backupId);
  expect(ok).toBe(false);
  expect((await FileManager.getFiles()).length).toBe(0);
}, 120000);
