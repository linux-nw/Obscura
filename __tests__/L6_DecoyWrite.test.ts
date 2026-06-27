/**
 * Layer 6 — guest (decoy) vault is WRITABLE, isolated, and leaks no cross-vault metadata.
 *
 * Device-found bug (manual test on SM-S906B, confirmed via logcat):
 *   'Error saving file:',   [Error: Dateiverschlüsselung fehlgeschlagen]
 *   'Error creating note:', [Error: Kann Metadaten nicht verschlüsseln]
 * Reads in the decoy view worked, but every WRITE failed: the editor/file-import paths
 * called the real NotesService / FileManager, which encrypt with the MASTER key. In a
 * decoy session only the guest content key is derived (the master key is intentionally
 * unreachable), so those encryptions threw. The decoy vault had read shims but no write
 * path — and the harness never caught it because the regression suite only covered reads.
 *
 * The fix routes guest writes through DecoyVaultService.{saveNote,saveFile} (sealed with the
 * guest key into guest/). This suite covers the WRITE path that was missing, plus the two
 * extra requirements:
 *   - cross-vault isolation: a guest entry never appears in the real vault, and vice-versa;
 *   - metadata isolation: the guest write shares NO counter / id namespace with the real
 *     vault (no BlobVersionService floor, no SecureStore key carrying the guest id), so
 *     nothing on the guest side is correlatable with the real vault (§15.2 boundary).
 *
 * Real CryptoService / Argon2idService / NotesService run against an in-memory fs +
 * SecureStore, so the AEAD round-trips and the isolation are genuine, not stubbed.
 */

const mockFiles = new Map<string, string>();

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(async (uri: string) => {
    if (mockFiles.has(uri)) return { exists: true, isDirectory: false, size: mockFiles.get(uri)!.length, uri };
    return { exists: false, isDirectory: uri.endsWith('/'), size: 0, uri };
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  writeAsStringAsync: jest.fn(async (uri: string, data: string) => { mockFiles.set(uri, data); }),
  readAsStringAsync: jest.fn(async (uri: string) => {
    if (!mockFiles.has(uri)) throw new Error('ENOENT ' + uri);
    return mockFiles.get(uri)!;
  }),
  deleteAsync: jest.fn(async (uri: string) => { mockFiles.delete(uri); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    if (!mockFiles.has(from)) throw new Error('ENOENT ' + from);
    mockFiles.set(to, mockFiles.get(from)!);
    mockFiles.delete(from);
  }),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const out: string[] = [];
    for (const k of mockFiles.keys()) {
      if (k.startsWith(dir)) {
        const rest = k.slice(dir.length);
        if (!rest.includes('/')) out.push(rest);
      }
    }
    return out;
  }),
}));

const secureStore = require('../__mocks__/expo-secure-store');

import { DecoyVaultService } from '../src/services/DecoyVaultService';
import { NotesService } from '../src/services/NotesService';
import { SecureCryptoService } from '../src/services/CryptoService';

const GUEST_PIN = '13571357';
const REAL_MASTER_KEY = 'a'.repeat(64); // synthetic 32-byte master key (hex)

const GUEST_DIR = '/mock/documents/guest/';
const NOTES_DIR = '/mock/documents/notes/';

beforeEach(() => {
  secureStore._reset();
  mockFiles.clear();
  DecoyVaultService.clearDecoyCache();
  (SecureCryptoService as any)._masterKeyCache = null;
});

async function openGuest() {
  await DecoyVaultService.enableDecoyVault();
  await DecoyVaultService.setDecoyPin(GUEST_PIN); // derives + caches the guest content key
}

describe('Layer 6: guest vault writes', () => {
  test('fail-closed: a guest write without the content key throws and writes no plaintext', async () => {
    DecoyVaultService.clearDecoyCache(); // no guest key cached
    await expect(DecoyVaultService.saveNote('t', 'c')).rejects.toThrow();
    await expect(
      DecoyVaultService.saveFile('data:text/plain;base64,QUJD', 'document', 'x.txt'),
    ).rejects.toThrow();

    const guestBlobs = [...mockFiles.keys()].filter(k => k.startsWith(GUEST_DIR));
    expect(guestBlobs).toEqual([]); // nothing hit disk
  }, 60000);

  test('note: write -> reopen -> read; on-disk blob is sealed ciphertext', async () => {
    await openGuest();
    const saved = await DecoyVaultService.saveNote('Shopping', 'milk, eggs', 'Home');

    // Simulate logout + a fresh guest login (key re-derived from the persisted KDF salt).
    DecoyVaultService.clearDecoyCache();
    await DecoyVaultService.unlockDecoyContent(GUEST_PIN);

    const got = (await DecoyVaultService.getFakeNotes()).find(n => n.id === saved.id);
    expect(got).toBeTruthy();
    expect(got!.title).toBe('Shopping');
    expect(got!.content).toBe('milk, eggs');
    expect(got!.category).toBe('Home');

    const blob = mockFiles.get(`${GUEST_DIR}note_${saved.id}`)!;
    expect(blob).not.toContain('Shopping');
    expect(blob).not.toContain('milk');
    const env = JSON.parse(blob);
    expect(typeof env.c).toBe('string');
    expect(env.c.length).toBeGreaterThan(0);
  }, 60000);

  test('file: write -> read content + metadata; sealed on disk', async () => {
    await openGuest();
    const b64 = Buffer.from('hello guest file payload').toString('base64');
    const saved = await DecoyVaultService.saveFile(
      `data:application/octet-stream;base64,${b64}`,
      'document',
      'note.txt',
    );

    DecoyVaultService.clearDecoyCache();
    await DecoyVaultService.unlockDecoyContent(GUEST_PIN);

    const got = (await DecoyVaultService.getFakeFiles()).find(f => f.id === saved.id);
    expect(got).toBeTruthy();
    expect(got!.originalName).toBe('note.txt');
    expect(got!.type).toBe('document');
    expect(await DecoyVaultService.getFakeFileContent(saved.id)).toBe(b64);

    const content = mockFiles.get(`${GUEST_DIR}file_${saved.id}`)!;
    const meta = mockFiles.get(`${GUEST_DIR}file_${saved.id}.meta`)!;
    expect(content).not.toContain(b64);
    expect(meta).not.toContain('note.txt');
  }, 60000);
});

describe('Layer 6: cross-vault isolation', () => {
  test('a guest entry never appears in the real vault, and vice-versa', async () => {
    // Real vault unlocked (master key present).
    (SecureCryptoService as any)._masterKeyCache = REAL_MASTER_KEY;
    await NotesService.initialize();
    const real = await NotesService.createNote('REAL_SECRET_TITLE', 'real body');

    // Guest vault (master key still set, but guest path must not use it).
    await openGuest();
    const guest = await DecoyVaultService.saveNote('GUEST_NOTE', 'guest body');

    const guestTitles = (await DecoyVaultService.getFakeNotes()).map(n => n.title);
    expect(guestTitles).toContain('GUEST_NOTE');
    expect(guestTitles).not.toContain('REAL_SECRET_TITLE');

    const realTitles = (await NotesService.getNotes()).map(n => n.title);
    expect(realTitles).toContain('REAL_SECRET_TITLE');
    expect(realTitles).not.toContain('GUEST_NOTE');

    // Disjoint on-disk directories.
    const guestPaths = [...mockFiles.keys()].filter(k => k.startsWith(GUEST_DIR));
    const notePaths = [...mockFiles.keys()].filter(k => k.startsWith(NOTES_DIR));
    expect(guestPaths.some(p => p.includes(guest.id))).toBe(true);
    expect(notePaths.some(p => p.includes(real.id))).toBe(true);
    expect(notePaths.some(p => p.includes(guest.id))).toBe(false);
    expect(guestPaths.some(p => p.includes(real.id))).toBe(false);
  }, 60000);

  test('metadata isolation: guest write shares no counter / id namespace with the real vault', async () => {
    (SecureCryptoService as any)._masterKeyCache = REAL_MASTER_KEY;
    await NotesService.initialize();
    const real = await NotesService.createNote('R', 'r');

    await openGuest();
    const guest = await DecoyVaultService.saveNote('G', 'g');

    const keys = [...secureStore._store.keys()];
    // The real note registered a monotonic blob-version floor...
    expect(keys).toContain(`filevault_blobver_${real.id}`);
    // ...the guest note did NOT (no shared version counter)...
    expect(keys).not.toContain(`filevault_blobver_${guest.id}`);
    // ...and the guest id appears in NO SecureStore key at all (nothing correlatable).
    expect(keys.some(k => k.includes(guest.id))).toBe(false);
  }, 60000);
});
