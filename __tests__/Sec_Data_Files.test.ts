/**
 * Sec_Data_Files — FileManager/NotesService/fsAtomic: unauthenticated metadata cannot
 * redirect paths, filename validation, temp-file plaintext handling, sweep/race behaviour.
 */
const mockFs = new Map<string, string>();
const mockDeleted: string[] = [];

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(async (uri: string) => {
    if (mockFs.has(uri)) return { exists: true, isDirectory: false, size: mockFs.get(uri)!.length, uri };
    return { exists: uri.endsWith('/'), isDirectory: uri.endsWith('/'), size: 0, uri };
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  writeAsStringAsync: jest.fn(async (u: string, d: string) => { mockFs.set(u, d); }),
  readAsStringAsync: jest.fn(async (u: string) => {
    if (!mockFs.has(u)) throw new Error('ENOENT ' + u);
    return mockFs.get(u)!;
  }),
  deleteAsync: jest.fn(async (u: string) => { mockDeleted.push(u); mockFs.delete(u); }),
  moveAsync: jest.fn(async ({ from, to }: any) => {
    if (!mockFs.has(from)) throw new Error('ENOENT ' + from);
    mockFs.set(to, mockFs.get(from)!); mockFs.delete(from);
  }),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const out: string[] = [];
    for (const k of mockFs.keys()) if (k.startsWith(dir) && !k.slice(dir.length).includes('/')) out.push(k.slice(dir.length));
    return out;
  }),
}));

jest.mock('../src/services/CryptoService', () => ({
  SecureCryptoService: {
    clearAllCaches: jest.fn(),
    encryptFile: jest.fn(async (d: string) => ({ encryptedData: d, iv: '0'.repeat(32), mac: 'f'.repeat(64) })),
    decryptFile: jest.fn(async (d: string) => d),
    encryptMetadata: jest.fn(async (v: string) => ({ encryptedData: v, iv: '0'.repeat(32), mac: 'f'.repeat(64) })),
    decryptMetadata: jest.fn(async (e: { data: string }) => e.data),
    encryptData: jest.fn(async (v: string) => ({ encryptedData: v, iv: '0'.repeat(32), mac: 'f'.repeat(64) })),
    decryptData: jest.fn(async (d: string) => d),
  },
}));

const secureStore = require('../__mocks__/expo-secure-store');
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import { writeFileAtomic, cleanupTempFiles } from '../src/services/fsAtomic';
import { BlobVersionService, parseBlobVersion } from '../src/services/BlobVersionService';

const V = '/mock/documents/vault/';
const N = '/mock/documents/notes/';
const meta = (id: string, over: any = {}) => JSON.stringify({
  id, name: `file_${id}`, version: 1,
  originalName: { data: 'a.txt', iv: '', mac: '' }, type: { data: 'document', iv: '', mac: '' },
  size: 1, createdAt: new Date().toISOString(), iv: '0'.repeat(32), mac: 'f'.repeat(64), ...over,
});

beforeEach(() => { mockFs.clear(); mockDeleted.length = 0; secureStore._reset(); jest.clearAllMocks(); });

describe('Sec_Data: vault metadata is untrusted', () => {
  test('tampered `name` cannot redirect content read/delete outside the vault dir', async () => {
    mockFs.set(`${V}file_abc_1.meta.enc`, meta('abc_1', { name: '../../shared_prefs/secret' }));
    mockFs.set(`${V}file_abc_1`, 'cipher');
    mockFs.set('/mock/shared_prefs/secret', 'victim');
    const files = await FileManager.getFiles();
    expect(files).toHaveLength(1);
    expect(files[0].name).toBe('file_abc_1'); // derived from id, not from the stored name
    await FileManager.deleteFile('abc_1');
    expect(mockDeleted.every(p => p.startsWith(V))).toBe(true);
    expect(mockFs.get('/mock/shared_prefs/secret')).toBe('victim');
  });

  test('id with path chars, or id that does not match the meta filename, is skipped', async () => {
    mockFs.set(`${V}file_x.meta.enc`, meta('../../evil'));
    mockFs.set(`${V}file_a_1.meta.enc`, meta('b_2')); // copied/renamed meta
    expect(await FileManager.getFiles()).toHaveLength(0);
  });

  test('non-integer / negative / string versions are rejected', () => {
    for (const v of [0, -1, 1.5, '1', NaN, null, {}]) expect(() => parseBlobVersion(v)).toThrow();
    expect(parseBlobVersion(undefined)).toBe(1);
    expect(parseBlobVersion(7)).toBe(7);
  });

  test('meta with string version is skipped (AAD/floor confusion)', async () => {
    mockFs.set(`${V}file_a_1.meta.enc`, meta('a_1', { version: '1' }));
    expect(await FileManager.getFiles()).toHaveLength(0);
  });

  test('rollback below the floor is still rejected', async () => {
    await BlobVersionService.advanceTo('a_1', 3);
    mockFs.set(`${V}file_a_1.meta.enc`, meta('a_1', { version: 2 }));
    expect(await FileManager.getFiles()).toHaveLength(0);
  });
});

describe('Sec_Data: import filename/type/size validation', () => {
  test.each(['a/b.txt', 'a\\b.txt', '..', 'x\u0000.txt', 'x\n.txt', 'evil‮txt.exe', '', 'a'.repeat(256)])(
    'importFile rejects name %p', async (name) => {
      await expect(FileManager.importFile('QUJD', 'document', name)).rejects.toThrow();
    });
  test('importFile rejects unknown type and oversize content', async () => {
    await expect(FileManager.importFile('QUJD', 'exe' as any, 'a.txt')).rejects.toThrow();
    await expect(FileManager.importFile('A'.repeat(150 * 1024 * 1024), 'document', 'a.txt')).rejects.toThrow();
  });
  test('invalid createdAt does not throw / poison metadata', async () => {
    const m = await FileManager.importFile('QUJD', 'document', 'ok.txt', 'not-a-date');
    expect(isNaN(m.createdAt.getTime())).toBe(false);
  });
  test('saveFile refuses a picked file above the size cap before reading it', async () => {
    const fsm = require('expo-file-system/legacy');
    mockFs.set('/mock/cache/big.bin', 'x');
    fsm.getInfoAsync.mockImplementationOnce(async () => ({ exists: true, size: 1 }));  // initialize dir
    fsm.getInfoAsync.mockImplementationOnce(async () => ({ exists: true, size: 500 * 1024 * 1024 }));
    await expect(FileManager.saveFile('/mock/cache/big.bin', 'document', 'big.bin')).rejects.toThrow();
    expect(fsm.readAsStringAsync).not.toHaveBeenCalledWith('/mock/cache/big.bin', expect.anything());
  });
});

describe('Sec_Data: plaintext temp files', () => {
  test('deleteTempFile only touches vault_view_ leaves directly in the cache dir', async () => {
    for (const u of ['/mock/cache/../documents/vault/file_a', '/mock/cache/other.tmp', '/mock/cache/vault_view_x/../../documents/keep', '/mock/documents/x']) {
      await FileManager.deleteTempFile(u);
    }
    expect(mockDeleted).toEqual([]);
    mockFs.set('/mock/cache/vault_view_ok.txt', 'plain');
    await FileManager.deleteTempFile('/mock/cache/vault_view_ok.txt');
    expect(mockDeleted).toContain('/mock/cache/vault_view_ok.txt');
  });

  test('exportToTempFile does not leave partial plaintext when the write fails', async () => {
    await FileManager.importFile('QUJD', 'document', 'doc.txt');
    const fsm = require('expo-file-system/legacy');
    fsm.writeAsStringAsync.mockImplementationOnce(async (u: string, d: string) => { mockFs.set(u, d.slice(0, 1)); throw new Error('disk full'); });
    const id = (await FileManager.getFiles())[0].id;
    const before = mockDeleted.length;
    await expect(FileManager.exportToTempFile(id)).rejects.toThrow('disk full');
    expect(mockDeleted.length).toBeGreaterThan(before);
    expect([...mockFs.keys()].filter(k => k.startsWith('/mock/cache/vault_view_'))).toEqual([]);
  });

  test('getFiles()/initialize() no longer sweeps live view temps after startup', async () => {
    await FileManager.getFiles(); // first call = startup sweep
    mockFs.set('/mock/cache/vault_view_live.mp4', 'plain-being-played');
    await FileManager.getFiles();
    await FileManager.getFiles();
    expect(mockFs.has('/mock/cache/vault_view_live.mp4')).toBe(true);
    await FileManager.cleanupViewTemps(); // explicit lock/start sweep still works
    expect(mockFs.has('/mock/cache/vault_view_live.mp4')).toBe(false);
  });
});

describe('Sec_Data: atomic write races', () => {
  test('cleanupTempFiles never deletes the temp of an in-flight write', async () => {
    const fsm = require('expo-file-system/legacy');
    let release!: () => void;
    fsm.writeAsStringAsync.mockImplementationOnce(async (u: string, d: string) => {
      mockFs.set(u, d);
      await new Promise<void>(r => { release = r; });
    });
    const w = writeFileAtomic(`${V}file_r`, 'data');
    await new Promise(r => setImmediate(r));
    await cleanupTempFiles(V); // concurrent initialize()
    release();
    await w;
    expect(mockFs.get(`${V}file_r`)).toBe('data');
  });

  test('concurrent writers to one target are serialized (no shared-temp corruption)', async () => {
    await Promise.all([1, 2, 3, 4, 5].map(i => writeFileAtomic(`${V}file_s`, `v${i}`)));
    expect(mockFs.get(`${V}file_s`)).toBe('v5');
    expect([...mockFs.keys()].filter(k => k.endsWith('.tmp'))).toEqual([]);
  });

  test('failed write removes its temp and rejects', async () => {
    const fsm = require('expo-file-system/legacy');
    fsm.moveAsync.mockImplementationOnce(async () => { throw new Error('rename failed'); });
    await expect(writeFileAtomic(`${V}file_f`, 'x')).rejects.toThrow('rename failed');
    expect(mockFs.has(`${V}file_f.tmp`)).toBe(false);
    // queue is not poisoned by the failure
    await writeFileAtomic(`${V}file_f`, 'y');
    expect(mockFs.get(`${V}file_f`)).toBe('y');
  });
});

describe('Sec_Data: notes', () => {
  test('ids interpolated into paths are validated', async () => {
    expect(await NotesService.deleteNote('../../vault/file_x')).toBe(false);
    expect(await NotesService.deleteNote('x')).toBe(false);
    await expect(NotesService.updateNote('../x', { title: 't' })).rejects.toThrow();
    expect(mockDeleted).toEqual([]);
  });

  test('note file whose inner id does not match its filename, or with bad version, is skipped', async () => {
    const n = (id: string, over: any = {}) => JSON.stringify({
      id, version: 1, title: { data: 't' }, content: { data: 'c' }, category: { data: '' }, tags: { data: '[]' },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ...over,
    });
    mockFs.set(`${N}note_note_a_1`, n('note_a_1'));
    mockFs.set(`${N}note_note_copy`, n('note_a_1')); // duplicate/renamed copy
    mockFs.set(`${N}note_note_b_2`, n('note_b_2', { version: '1' }));
    mockFs.set(`${N}note_note_c_3.tmp`, 'partial');
    const notes = await NotesService.getNotes();
    expect(notes.map(x => x.id)).toEqual(['note_a_1']);
  });

  test('non-array tags payload cannot crash the list', async () => {
    mockFs.set(`${N}note_note_d_4`, JSON.stringify({
      id: 'note_d_4', version: 1, title: { data: 't' }, content: { data: 'c' }, category: { data: '' }, tags: { data: '{"a":1}' },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    }));
    const notes = await NotesService.getNotes();
    expect(notes).toHaveLength(1);
    expect(notes[0].tags).toBeUndefined();
  });
});
