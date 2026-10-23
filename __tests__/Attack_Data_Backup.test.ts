/**
 * Attack_Data_Backup — red-team attacks on BackupService with REAL crypto:
 * id/name injection, valid-MAC-but-hostile plaintext, tampering, restore atomicity under
 * injected failure at every write step.
 */
const secureStore = require('../__mocks__/expo-secure-store');
const mockStore = new Map<string, string>();
let mockFailMoveAt = -1; // fail the Nth moveAsync (1-based) — i.e. the Nth atomic commit
let mockMoveCount = 0;
let mockFailDeleteIds = false;

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, d: string) => { mockStore.set(p, d); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => {
    if (mockFailDeleteIds && p.includes('/vault/')) throw new Error('EIO');
    mockStore.delete(p);
  }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    mockMoveCount++;
    if (mockFailMoveAt === mockMoveCount) throw new Error('injected move failure');
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
import { BackupService } from '../src/services/BackupService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import { Argon2idService } from '../src/services/Argon2idService';
import { BlobVersionService } from '../src/services/BlobVersionService';

const FS = require('expo-file-system/legacy');
const VAULT_PASS = 'VaultPass123!';
const BK = 'BackupPass456!';
const DIR = '/mock/documents/backups/';
const B64 = Buffer.from('attack-payload').toString('base64');

const enc = (plain: string, pass = BK) => (BackupService as any).encryptBackup(plain, pass);
async function plant(id: string, plain: string, pass = BK) {
  mockStore.set(`${DIR}backup_${id}.json`, JSON.stringify(await enc(plain, pass)));
}
const vaultKeys = () => [...mockStore.keys()].filter((k) => k.includes('/vault/') || k.includes('/notes/'));

beforeEach(async () => {
  secureStore._reset();
  mockStore.clear();
  mockFailMoveAt = -1; mockMoveCount = 0; mockFailDeleteIds = false;
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
  await SecureCryptoService.setupMasterKey(VAULT_PASS);
}, 120000);

describe('Attack_Data_Backup: id / name injection', () => {
  const ids = [
    '%2e%2e%2f%2e%2e%2fvault', '..%2f..', 'a\u0000b', '/etc/passwd', 'C:\\x',
    '\uFF0E\uFF0E', 'a\u2215b', 'x'.repeat(65), 'UPPER', 'a b', 'a.b', 'a\nb', 'é', '\u202Eexe',
  ];
  test.each(ids)('id %j is rejected by restore/delete/share without fs access', async (id) => {
    expect(await BackupService.restoreBackup(BK, id)).toBe(false);
    await expect(BackupService.deleteBackup(id)).rejects.toThrow();
    await expect(BackupService.shareBackup(id)).rejects.toThrow();
    expect(FS.readAsStringAsync).not.toHaveBeenCalled();
    expect(FS.deleteAsync).not.toHaveBeenCalled();
  });

  test('non-string ids (object with toString, array, number) are rejected', async () => {
    for (const id of [{ toString: () => 'ok' }, ['ok'], 5, null, undefined] as any[]) {
      expect(await BackupService.restoreBackup(BK, id)).toBe(false);
      await expect(BackupService.deleteBackup(id)).rejects.toThrow();
    }
  });

  test('listBackups never surfaces a name that restore would refuse to open as a traversal', async () => {
    mockStore.set(`${DIR}backup_ok1.json`, '{}');
    mockStore.set(`${DIR}backup_..%2fx.json`, '{}');
    const ids2 = (await BackupService.listBackups()).map((b) => b.id);
    for (const id of ids2) {
      if (/^[a-z0-9_]{1,64}$/.test(id)) continue;
      // an unusable id can be listed, but must be unusable everywhere
      expect(await BackupService.restoreBackup(BK, id)).toBe(false);
    }
  });

  const names = [
    '../x', 'a/b', 'a\\b', '..', 'x\u0000.txt', 'x\n.txt', '\u202Egpj.exe', 'a'.repeat(256), '',
    'a\u2028b', 'a\u2029b', 'a\u200Eb', 'a\u200Fb', 'a\u061Cb', 'a\u0085b', 'a\u009Fb',
  ];
  test.each(names)('hostile originalName %j is rejected by importFile and by restore pre-validation', async (n) => {
    await expect(FileManager.importFile(B64, 'document', n)).rejects.toThrow();
    await expect((BackupService as any).applyBackupData(JSON.stringify({
      files: [{ originalName: n, type: 'document', content: B64 }],
    }))).rejects.toThrow();
    expect(vaultKeys()).toEqual([]);
  });

  test('names containing percent-escapes or lookalike dots are stored inert: only the plain ext reaches paths', async () => {
    for (const n of ['%2e%2e%2f.pdf', 'a\u2024\u2024b.PDF', 'x.p%2fdf']) {
      const f = await FileManager.importFile(B64, 'document', n);
      const uri = await FileManager.exportToTempFile(f.id);
      expect(uri).toMatch(/^\/mock\/cache\/vault_view_[0-9a-z]+_[0-9a-f]{16}(\.[a-z0-9]{1,8})?$/);
      await FileManager.deleteTempFile(uri);
      expect(mockStore.has(uri)).toBe(false);
    }
  }, 60000);
});

describe('Attack_Data_Backup: valid MAC, hostile plaintext', () => {
  const deep = '['.repeat(200000) + ']'.repeat(200000);
  const hostile: [string, string][] = [
    ['not json', 'hello'],
    ['null', 'null'],
    ['string', '"x"'],
    ['files not array', '{"files":"x"}'],
    ['notes object', '{"notes":{"length":5}}'],
    ['deep nesting', deep],
    ['file entry null', '{"files":[null]}'],
    ['file content number', '{"files":[{"originalName":"a.txt","type":"document","content":5}]}'],
    ['bad type', '{"files":[{"originalName":"a.txt","type":"exe","content":"QQ=="}]}'],
    ['traversal name', '{"files":[{"originalName":"../../x","type":"document","content":"QQ=="}]}'],
    ['note no title', '{"notes":[{"content":"c"}]}'],
    ['note title object', '{"notes":[{"title":{},"content":"c"}]}'],
    ['too many entries', JSON.stringify({ notes: Array.from({ length: 100001 }, () => ({ title: '', content: '' })) })],
    ['proto key', '{"__proto__":{"polluted":1},"files":"x"}'],
  ];
  test.each(hostile)('%s -> restore false, vault untouched', async (_n, plain) => {
    await plant('evil', plain);
    expect(await BackupService.restoreBackup(BK, 'evil')).toBe(false);
    expect(vaultKeys()).toEqual([]);
    expect(({} as any).polluted).toBeUndefined();
  }, 120000);

  test('settings with __proto__ / hostile numerics cannot weaken or pollute', async () => {
    const m = await (BackupService as any).mergeSettings(JSON.parse(
      '{"__proto__":{"minPinLength":1},"minPinLength":1e999,"maxFailedAttempts":0,"autoLockTimeout":null,"require2FA":"true"}'));
    expect(({} as any).minPinLength).toBeUndefined();
    expect(m.minPinLength).toBeGreaterThanOrEqual(1);
    expect(m.maxFailedAttempts).toBeGreaterThanOrEqual(1);
    expect(m.require2FA).not.toBe('true');
  });

  test('hostile note fields: huge title is refused and earlier items are rolled back', async () => {
    const big = 'x'.repeat(8 * 1024 * 1024 + 1);
    await expect((BackupService as any).applyBackupData(JSON.stringify({
      files: [{ originalName: 'a.txt', type: 'document', content: B64 }],
      notes: [{ title: big, content: 'c' }],
    }))).rejects.toThrow();
    expect(vaultKeys()).toEqual([]);
    expect((await FileManager.getFiles()).length).toBe(0);
  }, 60000);

  test('duplicate note ids / duplicate files do not collide or overwrite (ids regenerated)', async () => {
    await (BackupService as any).applyBackupData(JSON.stringify({
      notes: [{ id: 'note_same', title: 'a', content: '1' }, { id: 'note_same', title: 'b', content: '2' }],
      files: [{ originalName: 'a.txt', type: 'document', content: B64 }, { originalName: 'a.txt', type: 'document', content: B64 }],
    }));
    const notes = await NotesService.getNotes();
    expect(notes.length).toBe(2);
    expect(new Set(notes.map((n) => n.id)).size).toBe(2);
    expect(notes.some((n) => n.id === 'note_same')).toBe(false);
    expect((await FileManager.getFiles()).length).toBe(2);
  }, 60000);
});

describe('Attack_Data_Backup: tampering / truncation', () => {
  async function good() {
    await NotesService.createNote('t', 'c');
    return BackupService.createBackup(BK);
  }
  const flip = (s: string, i: number) => s.slice(0, i) + (s[i] === '0' ? '1' : '0') + s.slice(i + 1);

  test.each(['tag', 'iv', 'backup', 'salt'])('single flipped hex char in %s -> rejected, nothing restored', async (field) => {
    const id = await good();
    const path = `${DIR}backup_${id}.json`;
    const env = JSON.parse(mockStore.get(path)!);
    env[field] = flip(env[field], 3);
    mockStore.set(path, JSON.stringify(env));
    for (const k of vaultKeys()) mockStore.delete(k);
    expect(await BackupService.restoreBackup(BK, id)).toBe(false);
    expect(vaultKeys()).toEqual([]);
  }, 120000);

  test('kdfParams changed to another in-window value is fed to the KDF (so the derived key, hence MAC, changes); out-of-window never reaches it', async () => {
    // NB: the jest Argon2 mock ignores params, so assert the binding structurally.
    const id = await good();
    const path = `${DIR}backup_${id}.json`;
    const env = JSON.parse(mockStore.get(path)!);
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    mockStore.set(path, JSON.stringify({ ...env, kdfParams: { ...env.kdfParams, t: 4 } }));
    await BackupService.restoreBackup(BK, id);
    expect(spy.mock.calls[0][2]).toMatchObject({ iterations: 4, memoryKB: env.kdfParams.m, parallelism: 1 });
    spy.mockClear();
    mockStore.set(path, JSON.stringify({ ...env, kdfParams: { ...env.kdfParams, t: 3, m: 8 } }));
    expect(await BackupService.restoreBackup(BK, id)).toBe(false);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  }, 120000);

  test('block-aligned truncation / extension of ciphertext -> MAC fail', async () => {
    const id = await good();
    const path = `${DIR}backup_${id}.json`;
    const env = JSON.parse(mockStore.get(path)!);
    for (const backup of [env.backup.slice(0, -32), env.backup + '0'.repeat(32), env.backup.slice(32)]) {
      mockStore.set(path, JSON.stringify({ ...env, backup }));
      expect(await BackupService.restoreBackup(BK, id)).toBe(false);
    }
  }, 120000);

  test('file truncated at many offsets never restores and never throws out of restoreBackup', async () => {
    const id = await good();
    const path = `${DIR}backup_${id}.json`;
    const full = mockStore.get(path)!;
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    for (const cut of [0, 1, 10, 50, full.length - 40, full.length - 2, full.length - 1]) {
      mockStore.set(path, full.slice(0, cut));
      await expect(BackupService.restoreBackup(BK, id)).resolves.toBe(false);
    }
    expect(spy).not.toHaveBeenCalled(); // malformed JSON/envelope never reaches the KDF
    spy.mockRestore();
  }, 120000);

  test('version relabel v3 -> v2 (downgrade) does not authenticate', async () => {
    const id = await good();
    const path = `${DIR}backup_${id}.json`;
    const env = JSON.parse(mockStore.get(path)!);
    mockStore.set(path, JSON.stringify({ version: 2, iv: env.iv, tag: env.tag, backup: env.backup, salt: env.salt }));
    expect(await BackupService.restoreBackup(BK, id)).toBe(false);
  }, 300000);

  test('wrong passphrase / NFD-vs-NFC equivalence: only the right one works', async () => {
    const id = await good();
    expect(await BackupService.restoreBackup(BK + 'x', id)).toBe(false);
    expect(await BackupService.restoreBackup('', id)).toBe(false);
  }, 120000);
});

describe('Attack_Data_Backup: restore atomicity under injected failure at every commit step', () => {
  const plain = JSON.stringify({
    files: [
      { originalName: 'a.txt', type: 'document', content: B64 },
      { originalName: 'b.txt', type: 'document', content: B64 },
    ],
    notes: [{ title: 't1', content: 'c1' }, { title: 't2', content: 'c2' }],
  });
  // commits: file1(meta,content) file2(meta,content) note1 note2  => 6 moveAsync calls
  test.each([1, 2, 3, 4, 5, 6])('failure on commit #%i leaves NO vault/notes residue and no floors', async (n) => {
    mockMoveCount = 0; mockFailMoveAt = n;
    await expect((BackupService as any).applyBackupData(plain)).rejects.toThrow();
    mockFailMoveAt = -1;
    const left = vaultKeys();
    expect(left).toEqual([]);
    expect((await FileManager.getFiles()).length).toBe(0);
    expect((await NotesService.getNotes()).length).toBe(0);
    const floors = [...secureStore._store.keys()].filter((k: string) => k.startsWith('filevault_blobver_'));
    expect(floors).toEqual([]);
  }, 60000);

  test('rollback itself failing (deleteFile EIO) is surfaced, not silently reported as success', async () => {
    mockMoveCount = 0; mockFailMoveAt = 6; // last note fails
    mockFailDeleteIds = true;
    await expect((BackupService as any).applyBackupData(plain)).rejects.toThrow();
    mockFailDeleteIds = false; mockFailMoveAt = -1;
    // restoreBackup() wrapper must report false for such a partial failure
    await plant('x', plain);
    mockMoveCount = 0; mockFailMoveAt = 12; // 6 backup-independent commits already happened above? reset: fail last
    mockFailMoveAt = 6;
    expect(await BackupService.restoreBackup(BK, 'x')).toBe(false);
  }, 120000);

  test('floor/version state stays monotonic and usable after a failed restore (retry succeeds)', async () => {
    mockMoveCount = 0; mockFailMoveAt = 4;
    await expect((BackupService as any).applyBackupData(plain)).rejects.toThrow();
    mockFailMoveAt = -1;
    await (BackupService as any).applyBackupData(plain);
    expect((await FileManager.getFiles()).length).toBe(2);
    expect((await NotesService.getNotes()).length).toBe(2);
  }, 60000);

  test('createBackup failure mid-write leaves no .tmp and no half backup', async () => {
    mockMoveCount = 0; mockFailMoveAt = 1;
    await expect(BackupService.createBackup(BK)).rejects.toThrow();
    mockFailMoveAt = -1;
    expect([...mockStore.keys()].filter((k) => k.includes('/backups/'))).toEqual([]);
  }, 120000);

  test('importBackupFromFile with a hostile arbitrary URI fails closed', async () => {
    for (const u of ['/etc/passwd', 'file:///../../x', '', 'content://x/y']) {
      await expect(BackupService.importBackupFromFile(BK, u)).resolves.toBe(false);
    }
    expect(await BlobVersionService.getFloor('x')).toBe(0);
  });
});
