/**
 * A3Rollback.test.ts — monotonic version counter / rollback protection.
 *
 * Model: a blob's version is bound into its AAD (`id:role:vN`) and stored in the
 * plaintext metadata; SecureStore holds the monotonic FLOOR. A read rejects any blob
 * whose version is below the floor (rollback) and any blob whose plaintext version was
 * raised without re-encryption (AAD/MAC mismatch).
 */

const secureStore = require('../__mocks__/expo-secure-store');

const mockA3Store = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockA3Store.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockA3Store.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockA3Store.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockA3Store.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockA3Store.get(from);
    if (v !== undefined) { mockA3Store.set(to, v); mockA3Store.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockA3Store.has(p) || [...mockA3Store.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'), size: (mockA3Store.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockA3Store.keys()) {
      if (k.startsWith(dir)) { const rest = k.slice(dir.length); if (rest.length && !rest.includes('/')) names.add(rest); }
    }
    return [...names];
  }),
}));

beforeEach(() => {
  secureStore._reset();
  mockA3Store.clear();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { NotesService } from '../src/services/NotesService';
import { KeyRotationService } from '../src/services/KeyRotationService';
import { BlobVersionService } from '../src/services/BlobVersionService';

const PASS = 'A3TestPassphrase!';

// ─────────────────────────────── crypto-level version binding ───────────────────────────────

test('version is bound into the AAD — decrypt with a different version is rejected', async () => {
  (SecureCryptoService as any)._masterKeyCache = 'a'.repeat(64);
  const enc = await SecureCryptoService.encryptData('secret', 'fileA:content:v1');
  expect(await SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:content:v1')).toBe('secret');
  await expect(SecureCryptoService.decryptData(enc.encryptedData, enc.iv, enc.mac, 'fileA:content:v2')).rejects.toThrow();
});

// ─────────────────────────────── BlobVersionService unit ───────────────────────────────

test('counter floor is monotonic (never lowers)', async () => {
  expect(await BlobVersionService.getFloor('obj')).toBe(0);
  expect(await BlobVersionService.nextVersion('obj')).toBe(1);
  await BlobVersionService.advanceTo('obj', 3);
  expect(await BlobVersionService.getFloor('obj')).toBe(3);
  await BlobVersionService.advanceTo('obj', 2); // lower ignored
  expect(await BlobVersionService.getFloor('obj')).toBe(3);
  expect(await BlobVersionService.nextVersion('obj')).toBe(4);
});

// ─────────────────────────────── note rollback integration ───────────────────────────────

test('rolling a note back to an older blob is rejected (version < floor)', async () => {
  await SecureCryptoService.setupMasterKey(PASS);
  await NotesService.createNote('title', 'body v1');
  const id = (await NotesService.getNotes())[0].id;
  const path = `/mock/documents/notes/note_${id}`;
  const v1Blob = mockA3Store.get(path)!; // snapshot the v1 ciphertext

  await NotesService.updateNote(id, { content: 'body v2' });
  expect((await NotesService.getNotes())[0].content).toBe('body v2');
  expect(await BlobVersionService.getFloor(id)).toBe(2);

  // Attacker (FS write) restores the old v1 blob. Floor in Keystore is still 2.
  mockA3Store.set(path, v1Blob);
  const after = await NotesService.getNotes();
  expect(after.length).toBe(0); // v1 < floor 2 → skipped, stale content not surfaced
});

test('raising the plaintext version without re-encrypting fails the AAD check', async () => {
  await SecureCryptoService.setupMasterKey(PASS);
  await NotesService.createNote('t', 'body'); // v1, floor 1
  const id = (await NotesService.getNotes())[0].id;
  const path = `/mock/documents/notes/note_${id}`;

  const note = JSON.parse(mockA3Store.get(path)!);
  note.version = 99; // claim a higher version without re-encrypting the blobs
  mockA3Store.set(path, JSON.stringify(note));

  // version 99 >= floor 1 (not a rollback), but blobs are v1 → AAD mismatch → skipped.
  expect((await NotesService.getNotes()).length).toBe(0);
});

// ─────────────────────────────── rotation preserves version ───────────────────────────────

test('key rotation preserves the version; note stays readable afterwards', async () => {
  await SecureCryptoService.setupMasterKey(PASS);
  await NotesService.createNote('t', 'body v1');
  const id = (await NotesService.getNotes())[0].id;
  await NotesService.updateNote(id, { content: 'body v2' });
  expect(await BlobVersionService.getFloor(id)).toBe(2);

  await KeyRotationService.performSecureRotation(PASS);

  const after = await NotesService.getNotes();
  expect(after.length).toBe(1);
  expect(after[0].content).toBe('body v2');
  expect(await BlobVersionService.getFloor(id)).toBe(2); // unchanged by rotation
}, 120000);
