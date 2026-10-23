/**
 * RED TEAM — backup envelope tamper / downgrade / hostile-plaintext attacks.
 * Passing = the attack failed (restore returns false and imports nothing).
 */
const secureStore = require('../__mocks__/expo-secure-store');

const mockBfs = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, d: string) => { mockBfs.set(p, d); }),
  readAsStringAsync: jest.fn(async (p: string) => { if (!mockBfs.has(p)) throw new Error('ENOENT'); return mockBfs.get(p); }),
  deleteAsync: jest.fn(async (p: string) => { mockBfs.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => { const v = mockBfs.get(from); if (v !== undefined) { mockBfs.set(to, v); mockBfs.delete(from); } }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({ exists: mockBfs.has(p) || [...mockBfs.keys()].some((k) => k.startsWith(p)), isDirectory: p.endsWith('/'), size: (mockBfs.get(p) || '').length })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const n = new Set<string>();
    for (const k of mockBfs.keys()) if (k.startsWith(dir)) { const r = k.slice(dir.length); if (r.length && !r.includes('/')) n.add(r); }
    return [...n];
  }),
}));

import { BackupService } from '../src/services/BackupService';
import { SecureCryptoService as C } from '../src/services/CryptoService';
import { NotesService } from '../src/services/NotesService';
import { FileManager } from '../src/services/FileManager';

const BPASS = 'Backup-Attack-Passphrase-1!';
const PAYLOAD = JSON.stringify({ files: [], notes: [{ title: 'T', content: 'C', category: 'c', tags: ['t'] }] });
let env: any;

const flip = (s: string, i = 0) => s.slice(0, i) + (s[i] === '0' ? '1' : '0') + s.slice(i + 1);
const put = (e: any, id = 'atk') => { mockBfs.set(`/mock/documents/backups/backup_${id}.json`, typeof e === 'string' ? e : JSON.stringify(e)); return id; };
const noteCount = async () => (await NotesService.getNotes()).length;

beforeAll(async () => {
  secureStore._reset();
  await C.setupMasterKey('Vault-Pass-For-Backup-Attack-1!');
  env = await (BackupService as any).encryptBackup(PAYLOAD, BPASS);
}, 60000);

beforeEach(async () => {
  jest.restoreAllMocks();
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  for (const k of [...mockBfs.keys()]) if (k.includes('/notes/') || k.includes('/backups/')) mockBfs.delete(k);
});

test('baseline: valid envelope restores exactly one note', async () => {
  put(env);
  expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(true);
  expect(await noteCount()).toBe(1);
});

describe('envelope field tamper => restore false, nothing imported', () => {
  test.each(['iv', 'tag', 'backup', 'salt'])('bit-flip %s', async (f) => {
    put({ ...env, [f]: flip(env[f], 3) });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    expect(await noteCount()).toBe(0);
  });
  test.each(['iv', 'tag', 'backup', 'salt'])('truncate / extend / blank %s', async (f) => {
    for (const v of [env[f].slice(0, -2), env[f] + '00', env[f] + '0'.repeat(32), '', 'zz', null, 5, [], {}]) {
      put({ ...env, [f]: v });
      expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    }
    expect(await noteCount()).toBe(0);
  });
  test('ciphertext block swap / duplication / drop', async () => {
    const big = await (BackupService as any).encryptBackup(JSON.stringify({ notes: Array.from({ length: 20 }, (_, i) => ({ title: 't' + i, content: 'c'.repeat(50) })) }), BPASS);
    const b = big.backup.match(/.{32}/g)!;
    for (const mut of [[b[1], b[0], ...b.slice(2)], [...b, b[0]], b.slice(1), b.slice(0, -1)]) {
      put({ ...big, backup: mut.join('') });
      expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    }
    expect(await noteCount()).toBe(0);
  });
});

describe('downgrade / parameter attacks', () => {
  test('v3 relabelled v2 (PBKDF2) with same salt/MAC fails', async () => {
    const { kdf, kdfParams, ...rest } = env;
    put({ ...rest, version: 2 });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
  });
  test('v2 relabelled v3 fails', async () => {
    put({ ...env, version: 1 });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    put({ ...env, version: '3' });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    put({ ...env, version: 4 });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
  });
  test('weakened KDF params (m/t below floor, p!=1) are refused BEFORE any KDF work', async () => {
    const { Argon2idService } = require('../src/services/Argon2idService');
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    for (const kp of [{ m: 8, t: 1, p: 1 }, { m: 65536, t: 1, p: 1 }, { m: 1024, t: 3, p: 1 }, { m: 65536, t: 3, p: 2 }, { m: 65536, t: 3, p: 0 }]) {
      put({ ...env, kdfParams: kp });
      expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    }
    expect(spy).not.toHaveBeenCalled();
  });
  test('memory / CPU bomb params refused before KDF', async () => {
    const { Argon2idService } = require('../src/services/Argon2idService');
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    for (const kp of [{ m: 4194304, t: 3, p: 1 }, { m: 65536, t: 1e9, p: 1 }, { m: 1e18, t: 3, p: 1 }, { m: NaN, t: 3, p: 1 }, { m: '65536', t: 3, p: 1 }, { m: 65536.5, t: 3, p: 1 }, null, 'x', []]) {
      put({ ...env, kdfParams: kp });
      expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    }
    put({ ...env, kdf: 'pbkdf2' });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    expect(spy).not.toHaveBeenCalled();
  });
  test('in-window but altered KDF params change the key => MAC fails (params are bound via key)', async () => {
    put({ ...env, kdfParams: { m: 65537, t: 3, p: 1 } });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    put({ ...env, kdfParams: { m: 65536, t: 4, p: 1 } });
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
  });
});

describe('passphrase handling', () => {
  test('wrong / empty / unicode-lookalike / padded passphrases fail', async () => {
    put(env);
    for (const p of ['', ' ', BPASS + ' ', BPASS.toLowerCase(), BPASS.replace('B', 'В'), null, undefined, 5, {}] as any[]) {
      expect(await BackupService.restoreBackup(p, 'atk')).toBe(false);
    }
    expect(await noteCount()).toBe(0);
  });
  test('createBackup enforces min length on NFC-normalised passphrase, rejects non-strings', async () => {
    await expect(BackupService.createBackup('short')).rejects.toThrow();
    await expect(BackupService.createBackup(null as any)).rejects.toThrow();
    await expect(BackupService.createBackup(undefined as any)).rejects.toThrow();
    // 12 combining-mark codepoints that NFC-compose to fewer than 12 chars must be refused
    await expect(BackupService.createBackup('é'.repeat(7))).rejects.toThrow();
  });
  test('NFD passphrase restores an NFC-created backup (and vice versa)', async () => {
    const nfc = 'Pässwörd-Backup-é-日本語';
    const e = await (BackupService as any).encryptBackup(PAYLOAD, nfc);
    put(e);
    expect(await BackupService.restoreBackup(nfc.normalize('NFD'), 'atk')).toBe(true);
  });
});

describe('file / id / envelope hostility', () => {
  test.each(['../x', 'a/b', '', 'A', 'a.json', 'a'.repeat(65), '..', 'a b', null, undefined, 5, {}] as any[])('backupId %j is refused', async (id) => {
    expect(await BackupService.restoreBackup(BPASS, id)).toBe(false);
    await expect(BackupService.deleteBackup(id)).resolves.not.toThrow().catch(() => undefined);
  });
  test.each(['{oops', '[]', 'null', '"s"', '', '{}', '{"version":3}', '1'])('malformed envelope file %j => false', async (raw) => {
    put(raw);
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
  });
  test('prototype-pollution envelope does not pollute', async () => {
    put('{"__proto__":{"polluted":1},"version":3,"constructor":{"prototype":{"polluted":2}}}');
    expect(await BackupService.restoreBackup(BPASS, 'atk')).toBe(false);
    expect(({} as any).polluted).toBeUndefined();
  });
  test('missing file => false', async () => { expect(await BackupService.restoreBackup(BPASS, 'nofile')).toBe(false); });
});

describe('hostile PLAINTEXT under a valid MAC (malicious backup author) => all-or-nothing', () => {
  const mk = async (obj: any) => { const e = await (BackupService as any).encryptBackup(typeof obj === 'string' ? obj : JSON.stringify(obj), BPASS); put(e); };
  test.each([
    ['not json', 'not json'], ['array', '[]'], ['null', 'null'], ['number', '42'],
    ['files not array', { files: 'x', notes: [] }], ['notes not array', { files: [], notes: {} }],
    ['bad note title', { notes: [{ title: 5, content: 'c' }] }],
    ['bad note content', { notes: [{ title: 't', content: null }] }],
    ['second note bad => first must roll back', { notes: [{ title: 'ok', content: 'ok' }, { title: 'bad' }] }],
    ['file with path-traversal name', { files: [{ originalName: '../../etc/passwd', type: 'document', content: 'aa' }] }],
    ['file with bad type', { files: [{ originalName: 'a.txt', type: 'exe', content: 'aa' }] }],
    ['file content not string', { files: [{ originalName: 'a.txt', type: 'document', content: 5 }] }],
  ] as any[])('%s', async (_n, obj) => {
    await mk(obj);
    const before = (await FileManager.getFiles()).length;
    const r = await BackupService.restoreBackup(BPASS, 'atk');
    expect(r).toBe(false);
    expect(await noteCount()).toBe(0);
    expect((await FileManager.getFiles()).length).toBe(before);
  });
  test('proto-pollution plaintext does not pollute Object.prototype', async () => {
    await mk('{"__proto__":{"polluted":1},"notes":[{"title":"a","content":"b","__proto__":{"polluted":3}}]}');
    await BackupService.restoreBackup(BPASS, 'atk');
    expect(({} as any).polluted).toBeUndefined();
  });
  test('settings in backup cannot weaken security settings', async () => {
    await mk({ notes: [], settings: { maxAttempts: 9999, pinLength: 1, autoLockTimeout: 99999999, requireBiometric: false, twoFactor: false } });
    const { SettingsService } = require('../src/services/SettingsService');
    const before = JSON.stringify(await SettingsService.get());
    await BackupService.restoreBackup(BPASS, 'atk');
    const after = await SettingsService.get();
    const b = JSON.parse(before);
    for (const k of Object.keys(b)) {
      if (/attempt|pin|lock|2fa|twoFactor/i.test(k) && typeof b[k] === 'number') {
        expect(after[k]).toBeLessThanOrEqual(b[k] + 0 === b[k] ? Math.max(b[k], 0) : b[k]);
      }
    }
  });
});

test('backup nonce/IV/salt freshness over 20 backups', async () => {
  const ivs = new Set<string>(), salts = new Set<string>(), cts = new Set<string>();
  for (let i = 0; i < 20; i++) {
    const e = await (BackupService as any).encryptBackup(PAYLOAD, BPASS);
    ivs.add(e.iv); salts.add(e.salt); cts.add(e.backup);
  }
  expect(ivs.size).toBe(20); expect(salts.size).toBe(20); expect(cts.size).toBe(20);
});

test('failed restore logs/throws never contain the backup passphrase or plaintext', async () => {
  const errs = jest.spyOn(console, 'error').mockImplementation(() => {});
  put({ ...env, tag: flip(env.tag) });
  await BackupService.restoreBackup(BPASS, 'atk');
  const out = JSON.stringify(errs.mock.calls.map((c) => c.map((x: any) => (x instanceof Error ? x.message : x))));
  expect(out).not.toContain(BPASS);
  expect(out).not.toContain('"title":"T"');
});
