/**
 * R-02: Key rotation with full content re-encryption — power-loss simulation.
 *
 * The vault encrypts file + note content DIRECTLY with the master key (there is no
 * per-file-key layer in practice). Rotating the master key therefore means
 * re-encrypting every content blob. Rotation is crash-safe:
 *   - commit (installMasterKey) runs LAST, so a crash leaves the OLD master stored;
 *   - resumeRotationIfNeeded(passphrase), called after the next unlock, finishes the
 *     migration idempotently (CryptoService.recryptBlob detects each blob's key);
 *   - a stale WAL after a completed commit is detected and cleared.
 *
 * Verifies:
 *   1. Full rotation: content survives, stored blobs are re-encrypted, re-login reads them.
 *   2. Crash mid-rotation (files migrated, notes not, no commit) → resume completes.
 *   3. Stale WAL after commit → resume clears it, content intact.
 *   4. Wrong passphrase → rotation aborts, nothing changed.
 */

const secureStore = require('../__mocks__/expo-secure-store');

const WAL_KEY = 'filevault_keyrotation_wal';

// ── Stateful in-memory filesystem (the global mock is a no-op stub). The factory
//    functions close over `mockFsStore`, so statefulness survives the ESM-interop copy. ──
const mockFsStore = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockFsStore.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockFsStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockFsStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockFsStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockFsStore.get(from);
    if (v !== undefined) { mockFsStore.set(to, v); mockFsStore.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockFsStore.has(p) || [...mockFsStore.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'),
    size: (mockFsStore.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockFsStore.keys()) {
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
  mockFsStore.clear();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { KeyRotationService } from '../src/services/KeyRotationService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';

const PASSPHRASE = 'TestPassphrase42!';
const FILE_CONTENT_B64 = Buffer.from('top-secret-file-bytes 🔐').toString('base64');
const NOTE_TITLE = 'Geheime Notiz';
const NOTE_BODY = 'Inhalt mit Ümläüten und Emoji 🔑';

async function seedVault(): Promise<void> {
  await SecureCryptoService.setupMasterKey(PASSPHRASE);
  await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');
  await NotesService.createNote(NOTE_TITLE, NOTE_BODY, 'privat', ['a', 'b']);
}

async function readBackContent(): Promise<{ fileContent: string; noteBody: string }> {
  const files = await FileManager.getFiles();
  const fileContent = await FileManager.getFileContent(files[0].id);
  const notes = await NotesService.getNotes();
  return { fileContent, noteBody: notes[0].content };
}

test('full rotation: content survives, blobs re-encrypted, re-login reads them', async () => {
  await seedVault();
  const oldMaster = (await SecureCryptoService.getMasterKey())!;

  // Snapshot a stored file-content blob to prove it gets re-encrypted.
  const files = await FileManager.getFiles();
  const ctBefore = mockFsStore.get(`/mock/documents/vault/${files[0].name}`)!;

  await KeyRotationService.performSecureRotation(PASSPHRASE);

  const newMaster = (await SecureCryptoService.getMasterKey())!;
  expect(newMaster).not.toBe(oldMaster);
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);

  // Stored ciphertext changed and is no longer readable with the old master key.
  const ctAfter = mockFsStore.get(`/mock/documents/vault/${files[0].name}`)!;
  expect(ctAfter).not.toBe(ctBefore);
  const metaAfter = JSON.parse(mockFsStore.get(`/mock/documents/vault/${files[0].name}.meta.enc`)!);
  await expect(
    SecureCryptoService.decryptDataWith(ctAfter, metaAfter.iv, metaAfter.mac, oldMaster)
  ).rejects.toThrow();

  // Content still decrypts with the (new) current master.
  let rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);

  // Simulate a fresh process: drop caches and unlock with the SAME passphrase.
  SecureCryptoService.clearAllCaches();
  const unlocked = await SecureCryptoService.unlock(PASSPHRASE);
  expect(unlocked).toBe(true);
  expect(await SecureCryptoService.getMasterKey()).toBe(newMaster);

  rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);
}, 120000);

test('crash mid-rotation (files migrated, notes not, no commit) → resume completes', async () => {
  await seedVault();
  const oldMaster = (await SecureCryptoService.getMasterKey())!;

  // Begin a rotation by hand and crash before committing: WAL written, file blobs
  // migrated, note blobs NOT migrated, master NOT installed (still old).
  const newMasterBuf = await SecureCryptoService.generateSecureBytes(32);
  const newMaster = SecureCryptoService.bufferToHex(newMasterBuf);
  const newMasterWrapped = await SecureCryptoService.encryptFileKeyWith(newMaster, oldMaster);
  await secureStore.setItemAsync(WAL_KEY, JSON.stringify({ newMasterWrapped, startedAt: Date.now() }));
  await FileManager.reencryptAll(oldMaster, newMaster); // files now under new master
  // notes intentionally left under old master; no installMasterKey → cache still old

  expect(await SecureCryptoService.getMasterKey()).toBe(oldMaster);

  // Resume after unlock finishes notes, installs the new master, clears the WAL.
  await KeyRotationService.resumeRotationIfNeeded(PASSPHRASE);

  expect(await SecureCryptoService.getMasterKey()).toBe(newMaster);
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);

  const rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);

  // Re-running resume is a harmless no-op (WAL already gone).
  await KeyRotationService.resumeRotationIfNeeded(PASSPHRASE);
  expect(await SecureCryptoService.getMasterKey()).toBe(newMaster);
}, 120000);

test('stale WAL after commit → resume clears it, content intact', async () => {
  await seedVault();

  // Complete a real rotation first.
  await KeyRotationService.performSecureRotation(PASSPHRASE);
  const committedMaster = (await SecureCryptoService.getMasterKey())!;

  // Simulate a crash AFTER install but BEFORE the WAL was deleted: a WAL whose
  // newMasterWrapped was wrapped with some OLD key the current master cannot unwrap.
  const bogusOld = 'b'.repeat(64);
  const phantomNew = 'c'.repeat(64);
  const newMasterWrapped = await SecureCryptoService.encryptFileKeyWith(phantomNew, bogusOld);
  await secureStore.setItemAsync(WAL_KEY, JSON.stringify({ newMasterWrapped, startedAt: Date.now() }));

  await KeyRotationService.resumeRotationIfNeeded(PASSPHRASE);

  // WAL cleared, master unchanged, content still readable.
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);
  expect(await SecureCryptoService.getMasterKey()).toBe(committedMaster);
  const rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);
}, 120000);

test('stale WAL (>24h) is warned about, then resumed (W-05)', async () => {
  await seedVault();
  const oldMaster = (await SecureCryptoService.getMasterKey())!;

  const newMasterBuf = await SecureCryptoService.generateSecureBytes(32);
  const newMaster = SecureCryptoService.bufferToHex(newMasterBuf);
  const newMasterWrapped = await SecureCryptoService.encryptFileKeyWith(newMaster, oldMaster);
  // WAL started 25h ago.
  await secureStore.setItemAsync(WAL_KEY, JSON.stringify({
    newMasterWrapped, startedAt: Date.now() - 25 * 60 * 60 * 1000,
  }));

  const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  await KeyRotationService.resumeRotationIfNeeded(PASSPHRASE);

  expect(warnSpy.mock.calls.some(c => String(c[0]).includes('STALE'))).toBe(true);
  warnSpy.mockRestore();

  // Resume still completed the rotation (per-blob idempotency makes it safe).
  expect(await SecureCryptoService.getMasterKey()).toBe(newMaster);
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);
  const rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);
}, 120000);

test('wrong passphrase aborts rotation, nothing changed', async () => {
  await seedVault();
  const oldMaster = (await SecureCryptoService.getMasterKey())!;

  await expect(
    KeyRotationService.performSecureRotation('definitely-wrong')
  ).rejects.toThrow();

  expect(await SecureCryptoService.getMasterKey()).toBe(oldMaster);
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);
  const rb = await readBackContent();
  expect(rb.fileContent).toBe(FILE_CONTENT_B64);
  expect(rb.noteBody).toBe(NOTE_BODY);
}, 120000);
