/**
 * Attack_Data_Files — red-team attacks on FileManager / NotesService / BlobVersionService with
 * REAL crypto: planted/tampered metadata, rollback + replay, field swapping, version-floor
 * bypass, plaintext temp residue and path-escape through percent-encoded URIs.
 */
const secureStore = require('../__mocks__/expo-secure-store');
const mockStore = new Map<string, string>();
let mockFailWriteMatch: RegExp | null = null;

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, d: string) => {
    if (mockFailWriteMatch && mockFailWriteMatch.test(p)) throw new Error('ENOSPC');
    mockStore.set(p, d);
  }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockStore.get(from);
    if (v !== undefined) { mockStore.set(to, v); mockStore.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockStore.has(p) || [...mockStore.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'),
    size: (mockStore.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockStore.keys()) {
      if (k.startsWith(dir)) {
        const rest = k.slice(dir.length);
        if (rest.length && !rest.includes('/')) names.add(rest);
      }
    }
    return [...names];
  }),
}));

import { SecureCryptoService } from '../src/services/CryptoService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import { BlobVersionService } from '../src/services/BlobVersionService';

const FS = require('expo-file-system/legacy');
const V = '/mock/documents/vault/';
const N = '/mock/documents/notes/';
const C = '/mock/cache/';
const B64 = Buffer.from('SECRET-PLAINTEXT-MARKER').toString('base64');

beforeEach(async () => {
  secureStore._reset();
  mockStore.clear();
  mockFailWriteMatch = null;
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
  await SecureCryptoService.setupMasterKey('VaultPass123!');
}, 120000);

const readJson = (p: string) => JSON.parse(mockStore.get(p)!);
const writeJson = (p: string, o: unknown) => mockStore.set(p, JSON.stringify(o));

describe('Attack_Data_Files: planted / tampered file metadata', () => {
  test('meta with id/filename mismatch, traversal id, huge id is never listed or deletable', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.txt');
    const real = readJson(`${V}file_${f.id}.meta.enc`);
    for (const id of ['../../notes/note_x', 'a/b', 'x'.repeat(65), '', 5, null, { a: 1 }, ['x']]) {
      mockStore.set(`${V}file_evil.meta.enc`, JSON.stringify({ ...real, id }));
      const ids = (await FileManager.getFiles()).map((x) => x.id);
      expect(ids).toEqual([f.id]);
    }
    // a copy of a valid meta under another filename must not masquerade as another entry
    mockStore.set(`${V}file_copy_0000000000000000.meta.enc`, JSON.stringify(real));
    expect((await FileManager.getFiles()).length).toBe(1);
  }, 60000);

  test('unauthenticated `name` in meta cannot redirect content reads or deletes', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.txt');
    const victim = await FileManager.importFile(B64, 'document', 'victim.txt');
    const meta = readJson(`${V}file_${f.id}.meta.enc`);
    writeJson(`${V}file_${f.id}.meta.enc`, { ...meta, name: `file_${victim.id}` });
    FS.deleteAsync.mockClear();
    await FileManager.deleteFile(f.id);
    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deleted.every((p: string) => !p.includes(victim.id))).toBe(true);
    expect(mockStore.has(`${V}file_${victim.id}`)).toBe(true);
  }, 60000);

  test('swapping content blobs between two files fails the AAD/MAC check', async () => {
    const a = await FileManager.importFile(Buffer.from('AAAA').toString('base64'), 'document', 'a.txt');
    const b = await FileManager.importFile(Buffer.from('BBBB').toString('base64'), 'document', 'b.txt');
    const ca = mockStore.get(`${V}file_${a.id}`)!;
    mockStore.set(`${V}file_${a.id}`, mockStore.get(`${V}file_${b.id}`)!);
    mockStore.set(`${V}file_${b.id}`, ca);
    await expect(FileManager.getFileContent(a.id)).rejects.toThrow();
    await expect(FileManager.getFileContent(b.id)).rejects.toThrow();
  }, 60000);

  test('metadata (name/type) swapped between files is rejected', async () => {
    const a = await FileManager.importFile(B64, 'document', 'a.txt');
    const b = await FileManager.importFile(B64, 'image', 'b.png');
    const ma = readJson(`${V}file_${a.id}.meta.enc`);
    const mb = readJson(`${V}file_${b.id}.meta.enc`);
    writeJson(`${V}file_${a.id}.meta.enc`, { ...ma, originalName: mb.originalName, type: mb.type });
    const ids = (await FileManager.getFiles()).map((x) => x.id);
    expect(ids).toEqual([b.id]);
  }, 60000);

  test('forged version values: <floor, 0, negative, fraction, string, huge, NaN, stripped', async () => {
    const n = await NotesService.createNote('t', 'c');
    await NotesService.updateNote(n.id, { content: 'c2' }); // floor = 2
    const path = `${N}note_${n.id}`;
    const orig = readJson(path);
    for (const v of [1, 0, -1, 1.5, '2', 1e308, Number.MAX_SAFE_INTEGER + 2, null, undefined, 3, [2], { x: 1 }]) {
      const forged: any = { ...orig, version: v };
      if (v === undefined) delete forged.version;
      writeJson(path, forged);
      expect((await NotesService.getNotes()).length).toBe(0);
    }
    writeJson(path, orig);
    expect((await NotesService.getNotes()).length).toBe(1);
  }, 60000);

  test('tampered unauthenticated size / createdAt cannot poison storage accounting or sorting', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.txt');
    const g = await FileManager.importFile(B64, 'document', 'b.txt');
    const m = readJson(`${V}file_${f.id}.meta.enc`);
    writeJson(`${V}file_${f.id}.meta.enc`, { ...m, size: '99999999999999999999', createdAt: 'garbage' });
    const u = await FileManager.getStorageUsage();
    expect(typeof u.used).toBe('number');
    expect(Number.isFinite(u.used)).toBe(true);
    const files = await FileManager.getFiles();
    for (const x of files) {
      expect(Number.isFinite(x.createdAt.getTime())).toBe(true);
      expect(typeof x.size).toBe('number');
      expect(x.size).toBeGreaterThanOrEqual(0);
    }
    expect(files.length).toBe(2);
    void g;
  }, 60000);

  test('tampered note createdAt/updatedAt does not yield Invalid Date', async () => {
    const n = await NotesService.createNote('t', 'c');
    const p = `${N}note_${n.id}`;
    writeJson(p, { ...readJson(p), createdAt: {}, updatedAt: 'nope' });
    const got = await NotesService.getNotes();
    expect(got.length).toBe(1);
    expect(Number.isFinite(got[0].createdAt.getTime())).toBe(true);
    expect(Number.isFinite(got[0].updatedAt.getTime())).toBe(true);
  }, 60000);
});

describe('Attack_Data_Files: notes rollback / replay / swapping', () => {
  test('replaying an older note version (or older single fields) is rejected', async () => {
    const n = await NotesService.createNote('title-v1', 'content-v1');
    const p = `${N}note_${n.id}`;
    const v1 = mockStore.get(p)!;
    await NotesService.updateNote(n.id, { content: 'content-v2' });
    const v2 = mockStore.get(p)!;
    // whole-file rollback
    mockStore.set(p, v1);
    expect((await NotesService.getNotes()).length).toBe(0);
    // Frankenstein: v2 envelope with v1 content field
    writeJson(p, { ...JSON.parse(v2), content: JSON.parse(v1).content });
    expect((await NotesService.getNotes()).length).toBe(0);
    // Frankenstein: v1 envelope declaring v2 (MAC binds the version)
    writeJson(p, { ...JSON.parse(v1), version: 2 });
    expect((await NotesService.getNotes()).length).toBe(0);
    mockStore.set(p, v2);
    expect((await NotesService.getNotes())[0].content).toBe('content-v2');
  }, 60000);

  test('swapping fields between two notes is rejected', async () => {
    const a = await NotesService.createNote('A', 'a-secret');
    const b = await NotesService.createNote('B', 'b-secret');
    const pa = `${N}note_${a.id}`;
    writeJson(pa, { ...readJson(pa), content: readJson(`${N}note_${b.id}`).content });
    const ids = (await NotesService.getNotes()).map((x) => x.id);
    expect(ids).toEqual([b.id]);
  }, 60000);

  test('same-version field transplant within one note (title <-> category) is rejected', async () => {
    const a = await NotesService.createNote('Title', 'c', 'Cat');
    const p = `${N}note_${a.id}`;
    const o = readJson(p);
    writeJson(p, { ...o, title: o.category, category: o.title });
    expect((await NotesService.getNotes()).length).toBe(0);
  }, 60000);

  test('file-id / note-id confusion: a file meta copied into notes/ and vice versa is ignored', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.txt');
    mockStore.set(`${N}note_${f.id}`, mockStore.get(`${V}file_${f.id}.meta.enc`)!);
    expect((await NotesService.getNotes()).length).toBe(0);
  }, 60000);

  test('note ids in public API are validated (traversal, wrong prefix)', async () => {
    const n = await NotesService.createNote('t', 'c');
    FS.deleteAsync.mockClear();
    for (const id of ['../x', 'note_../../vault/file_a', '', 'abc', 'note_' + 'x'.repeat(70), 'note_a/b']) {
      await expect(NotesService.updateNote(id, { title: 'x' })).rejects.toThrow();
      expect(await NotesService.deleteNote(id)).toBe(false);
    }
    expect(FS.deleteAsync).not.toHaveBeenCalled();
    expect((await NotesService.getNotes()).length).toBe(1);
    void n;
  }, 60000);

  test('updateNote enforces the same size cap as createNote', async () => {
    const n = await NotesService.createNote('t', 'c');
    await expect(NotesService.updateNote(n.id, { content: 'x'.repeat(8 * 1024 * 1024 + 1) })).rejects.toThrow();
    await expect(NotesService.updateNote(n.id, { title: 'x'.repeat(8 * 1024 * 1024 + 1) })).rejects.toThrow();
    expect((await NotesService.getNotes())[0].content).toBe('c');
  }, 60000);

  test('update failure mid-write keeps the previous version readable and the floor unchanged', async () => {
    const n = await NotesService.createNote('t', 'c1');
    mockFailWriteMatch = /notes\//;
    await expect(NotesService.updateNote(n.id, { content: 'c2' })).rejects.toThrow();
    mockFailWriteMatch = null;
    expect(await BlobVersionService.getFloor(n.id)).toBe(1);
    expect((await NotesService.getNotes())[0].content).toBe('c1');
  }, 60000);

  test('concurrent updates never leave a note that cannot be decrypted', async () => {
    const n = await NotesService.createNote('t', 'c0');
    await Promise.all([1, 2, 3, 4].map((i) => NotesService.updateNote(n.id, { content: `c${i}` }).catch(() => null)));
    const got = await NotesService.getNotes();
    expect(got.length).toBe(1);
    expect(/^c[1-4]$/.test(got[0].content)).toBe(true);
  }, 60000);

  test('DOCUMENTED RESIDUAL: delete removes the floor, so replaying a pre-delete copy resurrects the note', async () => {
    const n = await NotesService.createNote('t', 'c');
    const p = `${N}note_${n.id}`;
    const copy = mockStore.get(p)!;
    await NotesService.deleteNote(n.id);
    mockStore.set(p, copy);
    // Known design limit (random ids are never reused, floor is dropped to avoid unbounded
    // keystore growth). An attacker holding an old copy AND write access can resurrect it.
    expect((await NotesService.getNotes()).length).toBe(1);
  }, 60000);
});

describe('Attack_Data_Files: failed writes leave no listable orphan', () => {
  test('content write failure after meta commit leaves nothing behind (saveFile)', async () => {
    mockFailWriteMatch = /vault\/file_[^.]*\.tmp$/;
    // meta ends with .meta.enc.tmp so it is not matched by the regex above; content tmp is.
    await expect(FileManager.saveFile(`data:text/plain;base64,${B64}`, 'document', 'a.txt')).rejects.toThrow();
    mockFailWriteMatch = null;
    expect([...mockStore.keys()].filter((k) => k.startsWith(V))).toEqual([]);
    expect(await FileManager.getFiles()).toEqual([]);
  }, 60000);
});

describe('Attack_Data_Files: temp plaintext residue + path escape', () => {
  test('export -> delete leaves nothing; delete overwrites before unlink', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.pdf');
    const uri = await FileManager.exportToTempFile(f.id);
    expect(mockStore.get(uri)).toBe(B64);
    await FileManager.deleteTempFile(uri);
    expect(mockStore.has(uri)).toBe(false);
    const writes = FS.writeAsStringAsync.mock.calls.filter((c: any[]) => c[0] === uri).map((c: any[]) => c[1]);
    expect(writes[writes.length - 1]).not.toBe(B64);
  }, 60000);

  test('export write failure leaves no partial plaintext in cache', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.pdf');
    mockFailWriteMatch = /vault_view_/;
    await expect(FileManager.exportToTempFile(f.id)).rejects.toThrow();
    mockFailWriteMatch = null;
    expect([...mockStore.keys()].filter((k) => k.startsWith(C))).toEqual([]);
  }, 60000);

  test('export of a corrupted/tampered blob writes NO plaintext and surfaces a generic error', async () => {
    const f = await FileManager.importFile(B64, 'document', 'a.pdf');
    const p = `${V}file_${f.id}`;
    mockStore.set(p, mockStore.get(p)!.replace(/.$/, (c) => (c === '0' ? '1' : '0')));
    await expect(FileManager.exportToTempFile(f.id)).rejects.toThrow();
    expect([...mockStore.keys()].filter((k) => k.startsWith(C))).toEqual([]);
  }, 60000);

  test.each([
    `${C}vault_view_%2e%2e%2f%2e%2e%2fdocuments%2fvault%2ffile_x`,
    `${C}vault_view_..%2f..%2fdocuments`,
    `${C}vault_view_/../../documents/vault/file_x`,
    `${C}vault_view_a\\..\\b`,
    `${C}vault_view_%5c..%5cx`,
    `${C}x/../vault_view_ok`,
  ])('deleteTempFile refuses escaping uri %s', async (uri) => {
    mockStore.set(uri, 'victim');
    FS.deleteAsync.mockClear();
    FS.writeAsStringAsync.mockClear();
    await FileManager.deleteTempFile(uri);
    expect(FS.deleteAsync).not.toHaveBeenCalled();
    expect(FS.writeAsStringAsync).not.toHaveBeenCalled();
    expect(mockStore.get(uri)).toBe('victim');
  });

  test('picker cache-copy cleanup refuses percent-encoded traversal out of the cache dir', async () => {
    const evil = `${C}%2e%2e/documents/vault/file_victim`;
    mockStore.set(evil, B64);
    FS.deleteAsync.mockClear();
    await FileManager.saveFile(evil, 'document', 'a.txt').catch(() => {});
    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deleted).not.toContain(evil);
  }, 60000);

  test('picker plaintext cache copy is removed even when the import FAILS', async () => {
    const src = `${C}picked_doc.pdf`;
    mockStore.set(src, B64);
    mockFailWriteMatch = /vault\//;
    await expect(FileManager.saveFile(src, 'document', 'a.pdf')).rejects.toThrow();
    mockFailWriteMatch = null;
    expect(mockStore.has(src)).toBe(false);
  }, 60000);

  test('picker plaintext cache copy is removed when validation rejects the name', async () => {
    const src = `${C}picked_2.pdf`;
    mockStore.set(src, B64);
    await expect(FileManager.saveFile(src, 'document', '../evil')).rejects.toThrow();
    expect(mockStore.has(src)).toBe(false);
  }, 60000);

  test('user-storage originals outside the cache are never deleted, even on failure', async () => {
    const src = '/mock/documents/user_original.pdf';
    mockStore.set(src, B64);
    await expect(FileManager.saveFile(src, 'document', '../evil')).rejects.toThrow();
    expect(mockStore.has(src)).toBe(true);
  }, 60000);

  test('cleanupViewTemps sweeps only vault_view_* and survives hostile names', async () => {
    mockStore.set(`${C}vault_view_a.pdf`, 'p1');
    mockStore.set(`${C}vault_view_%2e%2e`, 'p2');
    mockStore.set(`${C}other.txt`, 'keep');
    await FileManager.cleanupViewTemps();
    expect([...mockStore.keys()].filter((k) => k.startsWith(C))).toEqual([`${C}other.txt`]);
  });
});

describe('Attack_Data_Files: no secrets in logs / errors', () => {
  test('failure paths never log or throw plaintext, keys or passphrases', async () => {
    const logged: string[] = [];
    const cap = (...a: unknown[]) => logged.push(a.map((x) => (x instanceof Error ? `${x.message}\n${x.stack}` : typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
    const spies = (['log', 'warn', 'error', 'info', 'debug'] as const).map((m) => jest.spyOn(console, m).mockImplementation(cap));
    const thrown: string[] = [];
    const t = async (fn: () => Promise<unknown>) => { try { await fn(); } catch (e: any) { thrown.push(String(e?.message)); } };

    const f = await FileManager.importFile(B64, 'document', 'SECRETNAME.txt');
    const n = await NotesService.createNote('SECRET-TITLE', 'SECRET-BODY');
    // corrupt everything then poke every read/write path
    const fp = `${V}file_${f.id}`;
    mockStore.set(fp, 'zz' + mockStore.get(fp)!.slice(2));
    const np = `${N}note_${n.id}`;
    mockStore.set(np, mockStore.get(np)!.replace('"mac":"', '"mac":"00'));
    await t(() => FileManager.getFileContent(f.id));
    await t(() => FileManager.exportToTempFile(f.id));
    await t(() => FileManager.deleteFile('nope'));
    await t(() => FileManager.importFile('x', 'document', '../SECRETNAME'));
    await t(async () => { await NotesService.getNotes(); });
    await t(() => NotesService.updateNote(n.id, { title: 'SECRET-TITLE-2' }));
    await t(async () => { await (await import('../src/services/BackupService')).BackupService.restoreBackup('PASSPHRASE-XYZ-123', 'nope'); });

    spies.forEach((s) => s.mockRestore());
    const hay = [...logged, ...thrown].join('\n');
    for (const needle of ['SECRET-PLAINTEXT-MARKER', B64, 'SECRET-BODY', 'SECRET-TITLE', 'PASSPHRASE-XYZ-123', 'VaultPass123!']) {
      expect(hay).not.toContain(needle);
    }
    // no 64-hex (32-byte key) material in messages either
    expect(hay).not.toMatch(/\b[0-9a-f]{64}\b/);
  }, 120000);
});
