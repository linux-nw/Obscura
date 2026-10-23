/**
 * Sec_Data_Backup — untrusted backup input: id traversal, envelope/KDF-param bombs,
 * oversize files, all-or-nothing restore, settings never weakened.
 */
const mockFs = new Map<string, string>();
const mockSizes = new Map<string, number>();

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(async (uri: string) => {
    if (mockFs.has(uri)) return { exists: true, isDirectory: false, size: mockSizes.get(uri) ?? mockFs.get(uri)!.length, uri };
    return { exists: false, isDirectory: uri.endsWith('/'), size: 0, uri };
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  writeAsStringAsync: jest.fn(async (u: string, d: string) => { mockFs.set(u, d); }),
  readAsStringAsync: jest.fn(async (u: string) => {
    if (!mockFs.has(u)) throw new Error('ENOENT ' + u);
    return mockFs.get(u)!;
  }),
  deleteAsync: jest.fn(async (u: string) => { mockFs.delete(u); }),
  moveAsync: jest.fn(async ({ from, to }: any) => { mockFs.set(to, mockFs.get(from)!); mockFs.delete(from); }),
  readDirectoryAsync: jest.fn(async () => []),
}));
jest.mock('expo-sharing', () => ({ shareAsync: jest.fn(async () => {}) }));

const secureStore = require('../__mocks__/expo-secure-store');
const fsMock = require('expo-file-system/legacy');

import { BackupService } from '../src/services/BackupService';
import { Argon2idService } from '../src/services/Argon2idService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import { SettingsService } from '../src/services/SettingsService';

const DIR = '/mock/documents/backups/';
const goodV3 = (over: any = {}) => ({
  version: 3, kdf: 'argon2id', kdfParams: { m: 65536, t: 3, p: 1 },
  salt: 'a'.repeat(32), iv: 'b'.repeat(32), tag: 'c'.repeat(64), backup: 'd'.repeat(64), ...over,
});

beforeEach(() => {
  secureStore._reset();
  mockFs.clear();
  mockSizes.clear();
  jest.clearAllMocks();
});

describe('Sec_Data: backup id path traversal', () => {
  const bad = ['../../vault/file_x', '..', 'a/b', 'a\\b', '', 'x.json', 'A B'];
  test.each(bad)('restore/delete/share reject id %p without touching fs', async (id) => {
    expect(await BackupService.restoreBackup('whatever-passphrase', id)).toBe(false);
    await expect(BackupService.deleteBackup(id)).rejects.toThrow();
    await expect(BackupService.shareBackup(id)).rejects.toThrow();
    expect(fsMock.readAsStringAsync).not.toHaveBeenCalled();
    expect(fsMock.deleteAsync).not.toHaveBeenCalled();
  });
});

describe('Sec_Data: untrusted envelope', () => {
  const spy = () => jest.spyOn(Argon2idService, 'deriveKey');

  test.each([
    ['memory bomb', goodV3({ kdfParams: { m: 4 * 1024 * 1024, t: 3, p: 1 } })],
    ['time bomb', goodV3({ kdfParams: { m: 65536, t: 1e9, p: 1 } })],
    ['weakened m', goodV3({ kdfParams: { m: 8, t: 3, p: 1 } })],
    ['weakened t', goodV3({ kdfParams: { m: 65536, t: 1, p: 1 } })],
    ['p != 1', goodV3({ kdfParams: { m: 65536, t: 3, p: 8 } })],
    ['non-integer', goodV3({ kdfParams: { m: '65536', t: 3, p: 1 } })],
    ['wrong kdf', goodV3({ kdf: 'pbkdf2' })],
    ['non-hex salt', goodV3({ salt: 'z'.repeat(32) })],
    ['short iv', goodV3({ iv: 'ab' })],
    ['short tag', goodV3({ tag: 'ab' })],
    ['non-hex body', goodV3({ backup: 'x'.repeat(64) })],
    ['body not block aligned', goodV3({ backup: 'd'.repeat(30) })],
    ['empty body', goodV3({ backup: '' })],
    ['v1', { version: 1 }],
    ['v4', goodV3({ version: 4 })],
    ['null', null],
  ])('%s is rejected before any KDF runs', async (_n, env) => {
    mockFs.set(`${DIR}backup_ok.json`, JSON.stringify(env));
    const s = spy();
    expect(await BackupService.restoreBackup('long-enough-passphrase', 'ok')).toBe(false);
    expect(s).not.toHaveBeenCalled();
    s.mockRestore();
  });

  test('oversize backup file is rejected without being read', async () => {
    mockFs.set(`${DIR}backup_big.json`, JSON.stringify(goodV3()));
    mockSizes.set(`${DIR}backup_big.json`, 600 * 1024 * 1024);
    expect(await BackupService.restoreBackup('long-enough-passphrase', 'big')).toBe(false);
    expect(fsMock.readAsStringAsync).not.toHaveBeenCalled();
  });

  test('importBackupFromFile applies the same limits', async () => {
    mockFs.set('file:///x/b.json', JSON.stringify(goodV3({ kdfParams: { m: 1e9, t: 3, p: 1 } })));
    const s = spy();
    expect(await BackupService.importBackupFromFile('long-enough-passphrase', 'file:///x/b.json')).toBe(false);
    expect(s).not.toHaveBeenCalled();
    s.mockRestore();
  });
});

describe('Sec_Data: restore is all-or-nothing', () => {
  test('a malformed entry aborts BEFORE anything is imported', async () => {
    const imp = jest.spyOn(FileManager, 'importFile');
    const payload = JSON.stringify({
      files: [
        { originalName: 'ok.txt', type: 'document', content: 'QUJD' },
        { originalName: '../../etc/passwd', type: 'document', content: 'QUJD' },
      ],
    });
    await expect((BackupService as any).applyBackupData(payload)).rejects.toThrow();
    expect(imp).not.toHaveBeenCalled();
    imp.mockRestore();
  });

  test('failure mid-import rolls back already-created items', async () => {
    const created: string[] = [];
    const imp = jest.spyOn(FileManager, 'importFile').mockImplementation(async () => {
      created.push('f1');
      return { id: 'f1' } as any;
    });
    const del = jest.spyOn(FileManager, 'deleteFile').mockResolvedValue(undefined as any);
    jest.spyOn(NotesService, 'createNote').mockRejectedValue(new Error('boom'));
    const payload = JSON.stringify({
      files: [{ originalName: 'a.txt', type: 'document', content: 'QUJD' }],
      notes: [{ title: 't', content: 'c' }],
    });
    await expect((BackupService as any).applyBackupData(payload)).rejects.toThrow('boom');
    expect(del).toHaveBeenCalledWith('f1');
    jest.restoreAllMocks();
  });
});

describe('Sec_Data: restored settings never weaken security', () => {
  test('only stricter values are adopted; unknown keys dropped', async () => {
    await SettingsService.save({
      biometricsEnabled: false, bioAutoTrigger: false, require2FA: false,
      autoLockTimeout: 60, maxFailedAttempts: 5, maxFailedAttemptsAction: 'wipe', minPinLength: 8,
    });
    const weak = await (BackupService as any).mergeSettings({
      minPinLength: 4, maxFailedAttempts: 1000, autoLockTimeout: -1, maxFailedAttemptsAction: 'lock', evil: 1,
    });
    expect(weak).toMatchObject({ minPinLength: 8, maxFailedAttempts: 5, autoLockTimeout: 60, maxFailedAttemptsAction: 'wipe' });
    expect((weak as any).evil).toBeUndefined();
    const strong = await (BackupService as any).mergeSettings({ minPinLength: 12, maxFailedAttempts: 3, autoLockTimeout: 30, require2FA: true });
    expect(strong).toMatchObject({ minPinLength: 12, maxFailedAttempts: 3, autoLockTimeout: 30, require2FA: true });
  });
});
