/**
 * Layer 6 — guest (decoy) vault content is encrypted at rest.
 *
 * Before L6 the decoy stored 'fake_data_placeholder' + plaintext JSON metadata/notes on
 * disk, while the real vault stores XChaCha20-Poly1305 ciphertext. That differential made
 * the decoy instantly identifiable as the fake one — and, by elimination, proved the real
 * vault is the hidden one. L6 encrypts the guest content with a key derived (Argon2id) from
 * the guest PIN, never stored, so on disk the guest blobs are opaque ciphertext like the
 * real vault's.
 *
 * This proves:
 *  1. setup writes JSON envelopes of ciphertext — no plaintext marker, filename or note body.
 *  2. the correct guest PIN re-derives the key and decrypts everything (and originalName,
 *     a pre-L6 bug, is now present).
 *  3. a wrong PIN (or no cached key) decrypts nothing — the content is really encrypted.
 *
 * Uses an explicit jest.mock factory for expo-file-system/legacy (an in-memory fs) because
 * jest-expo overrides the global moduleNameMapper. The REAL CryptoService / Argon2idService
 * run (against their own global mocks) so the AEAD roundtrip is genuine.
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

const PIN = '13571357';
const WRONG = '24682468';

async function setupGuestVault() {
  await DecoyVaultService.enableDecoyVault();
  await DecoyVaultService.setDecoyPin(PIN); // derives + caches the guest content key
  await DecoyVaultService.createFakeFiles();
  await DecoyVaultService.createFakeNotes();
}

beforeEach(() => {
  secureStore._reset();
  mockFiles.clear();
  DecoyVaultService.clearDecoyCache();
});

describe('Layer 6: guest vault content encryption', () => {
  test('setup writes opaque ciphertext, never plaintext fakes', async () => {
    await setupGuestVault();

    const blobs = Array.from(mockFiles.entries()).filter(([k]) => k.includes('/guest/'));
    // 3 file blobs + 3 meta blobs + 3 note blobs.
    expect(blobs.length).toBe(9);

    const all = blobs.map(([, v]) => v).join('\n');
    expect(all).not.toContain('fake_data_placeholder');
    expect(all).not.toContain('holiday_photo.jpg');
    expect(all).not.toContain('Bank Account');
    expect(all).not.toContain('hunter2');

    // Every on-disk blob is a JSON envelope of ciphertext {c, iv, mac}.
    for (const [, v] of blobs) {
      const env = JSON.parse(v);
      expect(typeof env.c).toBe('string');
      expect(typeof env.iv).toBe('string');
      expect(typeof env.mac).toBe('string');
      expect(env.c.length).toBeGreaterThan(0);
    }
  }, 60000);

  test('correct PIN decrypts (originalName present); wrong PIN / locked decrypts nothing', async () => {
    await setupGuestVault();

    // Simulate logout, then a guest login with the correct PIN.
    DecoyVaultService.clearDecoyCache();
    await DecoyVaultService.unlockDecoyContent(PIN);

    const files = await DecoyVaultService.getFakeFiles();
    expect(files.length).toBe(3);
    for (const f of files) {
      expect(f.originalName).toBeTruthy(); // L6: was undefined (never written) pre-fix
      expect(typeof f.size).toBe('number');
    }
    expect(files.map(f => f.originalName).sort())
      .toEqual(['family_clip.mp4', 'holiday_photo.jpg', 'work_document.pdf']);

    const notes = await DecoyVaultService.getFakeNotes();
    expect(notes.map(n => n.title).sort())
      .toEqual(['Bank Account', 'Password List', 'Secret Recipe']);

    // Wrong PIN → different key → AEAD verification fails → nothing readable.
    DecoyVaultService.clearDecoyCache();
    await DecoyVaultService.unlockDecoyContent(WRONG);
    expect(await DecoyVaultService.getFakeFiles()).toEqual([]);
    expect(await DecoyVaultService.getFakeNotes()).toEqual([]);

    // No cached key at all (locked) → nothing readable.
    DecoyVaultService.clearDecoyCache();
    expect(await DecoyVaultService.getFakeFiles()).toEqual([]);
    expect(await DecoyVaultService.getFakeNotes()).toEqual([]);
  }, 60000);
});
