/**
 * Sec_Data_Vault — decoy vault leaks, full wipe completeness, panic counter,
 * memory wiping, legacy "encryption" disabled.
 */
const mockFs = new Map<string, string>();
const mockDirs = new Set<string>();
const mockDeleted: string[] = [];

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(async (uri: string) => {
    if (mockFs.has(uri)) return { exists: true, isDirectory: false, size: mockFs.get(uri)!.length, uri };
    const d = uri.endsWith('/') ? uri : uri + '/';
    const has = mockDirs.has(d) || [...mockFs.keys()].some(k => k.startsWith(d));
    return { exists: has, isDirectory: has, size: 0, uri };
  }),
  makeDirectoryAsync: jest.fn(async (d: string) => { mockDirs.add(d.endsWith('/') ? d : d + '/'); }),
  writeAsStringAsync: jest.fn(async (u: string, d: string) => { mockFs.set(u, d); }),
  readAsStringAsync: jest.fn(async (u: string) => {
    if (!mockFs.has(u)) throw new Error('ENOENT ' + u);
    return mockFs.get(u)!;
  }),
  deleteAsync: jest.fn(async (u: string) => {
    mockDeleted.push(u);
    mockFs.delete(u);
    const d = u.endsWith('/') ? u : u + '/';
    mockDirs.delete(d);
    for (const k of [...mockFs.keys()]) if (k.startsWith(d)) mockFs.delete(k);
  }),
  moveAsync: jest.fn(async ({ from, to }: any) => { mockFs.set(to, mockFs.get(from)!); mockFs.delete(from); }),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const out = new Set<string>();
    for (const k of mockFs.keys()) if (k.startsWith(dir)) out.add(k.slice(dir.length).split('/')[0]);
    return [...out];
  }),
}));

const secureStore = require('../__mocks__/expo-secure-store');
import { DecoyVaultService } from '../src/services/DecoyVaultService';
import { Argon2idService } from '../src/services/Argon2idService';
import { SecureDeleteService, ALL_SECURE_KEYS } from '../src/services/SecureDeleteService';
import { PanicService } from '../src/services/PanicService';
import { SafeBuffer, ZeroingArrayBuffer, MemoryProtection } from '../src/services/MemorySafetyService';
import LegacyEncryptionService from '../src/services/LegacyEncryptionService';
import { BlobVersionService } from '../src/services/BlobVersionService';

const PIN = '13571357';
const GUEST = '/mock/documents/guest/';

beforeEach(() => {
  secureStore._reset();
  mockFs.clear(); mockDirs.clear(); mockDeleted.length = 0;
  jest.clearAllMocks();
  DecoyVaultService.clearDecoyCache();
});

async function openGuest() {
  await DecoyVaultService.enableDecoyVault();
  await DecoyVaultService.setDecoyPin(PIN);
}

describe('Sec_Data: decoy vault', () => {
  test('ids match the real vault shape <base36>_<16hex> (no Math.random shape distinguisher)', async () => {
    await openGuest();
    const n = await DecoyVaultService.saveNote('t', 'c');
    expect(n.id).toMatch(/^[0-9a-z]+_[0-9a-f]{16}$/);
    const ids = new Set<string>();
    for (let i = 0; i < 20; i++) ids.add((await DecoyVaultService.saveNote('t', 'c')).id);
    expect(ids.size).toBe(20);
  }, 60000);

  test('fake files carry plausible past creation dates, not "now"', async () => {
    await openGuest();
    await DecoyVaultService.createFakeFiles();
    const files = await DecoyVaultService.getFakeFiles();
    expect(files).toHaveLength(3);
    for (const f of files) expect(Date.now() - f.createdAt.getTime()).toBeGreaterThan(20 * 24 * 3600 * 1000);
  }, 60000);

  test('path-injecting ids are rejected', async () => {
    await openGuest();
    for (const id of ['../../vault/file_x', 'a/b', '..', '']) {
      await expect(DecoyVaultService.getFakeFileContent(id)).rejects.toThrow();
      await expect(DecoyVaultService.deleteFile(id)).rejects.toThrow();
      await expect(DecoyVaultService.deleteNote(id)).rejects.toThrow();
    }
    await expect(DecoyVaultService.saveNote('t', 'c', undefined, '../x')).rejects.toThrow();
  }, 60000);

  test('guest import validates the filename (it feeds a cache path)', async () => {
    await openGuest();
    await expect(DecoyVaultService.saveFile('data:text/plain;base64,QUJD', 'document', 'a./../../x')).rejects.toThrow();
    await expect(DecoyVaultService.saveFile('data:text/plain;base64,QUJD', 'document', 'a/b.txt')).rejects.toThrow();
  }, 60000);

  test('temp file extension is whitelisted — name cannot inject path segments', async () => {
    await openGuest();
    const f = await DecoyVaultService.saveFile('data:text/plain;base64,QUJD', 'document', 'report.PDF');
    const uri = await DecoyVaultService.exportFakeToTempFile(f.id);
    expect(uri).toMatch(/^\/mock\/cache\/vault_view_[0-9a-z]+_[0-9a-f]{16}\.pdf$/);
  }, 60000);

  test('destroy wipes credentials even when the guest dir is missing, and leaves no guest key behind', async () => {
    await openGuest();
    await secureStore.setItemAsync('filevault_guest_active', 'true');
    await secureStore.setItemAsync('filevault_guest_created', '1');
    mockFs.clear(); mockDirs.clear(); // dir gone → old code threw before deleting keys
    await DecoyVaultService.destroyDecoyVault();
    const left = [...secureStore._store.keys()].filter((k: string) => k.startsWith('filevault_guest'));
    expect(left).toEqual([]);
    expect(await DecoyVaultService.hasDecoyVault()).toBe(false);
  }, 60000);

  test('verifyDecoyPin with NO guest PIN still runs the Argon2id stretch (timing parity)', async () => {
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    expect(await DecoyVaultService.verifyDecoyPin('anything')).toBe(false);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  }, 60000);

  test('verifyPanicPin with NO panic PIN still runs the Argon2id stretch (timing parity)', async () => {
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    expect(await PanicService.verifyPanicPin('anything')).toBe(false);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  }, 60000);

  test('release builds do not log guest/panic activity', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    await openGuest();
    await DecoyVaultService.createFakeFiles();
    await PanicService.setPanicPin('panicpin123');
    await DecoyVaultService.destroyDecoyVault();
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  }, 60000);
});

describe('Sec_Data: secureWipeAll completeness', () => {
  test('removes guest dir, backups, panic/guest keys, blobver floors and view temps; no throw when vault dir is absent', async () => {
    for (const k of ALL_SECURE_KEYS) await secureStore.setItemAsync(k, 'x');
    await BlobVersionService.advanceTo('abc_1', 2);
    mockFs.set('/mock/documents/vault/file_abc_1.meta.enc', JSON.stringify({ id: 'abc_1' }));
    mockFs.set('/mock/documents/vault/file_abc_1', 'cipher');
    mockFs.set(`${GUEST}note_x`, 'sealed');
    mockFs.set('/mock/documents/backups/backup_a.json', '{}');
    mockFs.set('/mock/cache/vault_view_t.pdf', 'plain');
    // notes dir intentionally absent

    await SecureDeleteService.secureWipeAll();

    expect([...secureStore._store.keys()]).toEqual([]);
    expect([...mockFs.keys()]).toEqual([]);
  });

  test('a failing step does not abort the remaining steps; failure is reported', async () => {
    mockFs.set(`${GUEST}note_x`, 'sealed');
    mockFs.set('/mock/documents/vault/file_a', 'c');
    const fsm = require('expo-file-system/legacy');
    const orig = fsm.deleteAsync.getMockImplementation();
    fsm.deleteAsync.mockImplementation(async (u: string) => {
      if (u.includes('/vault/')) throw new Error('EIO');
      return orig!(u);
    });
    await expect(SecureDeleteService.secureWipeAll()).rejects.toThrow('Wipe unvollständig');
    expect(mockFs.has(`${GUEST}note_x`)).toBe(false); // later steps still ran
    fsm.deleteAsync.mockImplementation(orig);
  });

  test('overwrite does not read plaintext back and the random pass is not silently zeros', async () => {
    const fsm = require('expo-file-system/legacy');
    mockFs.set('/mock/documents/vault/file_a', 'A'.repeat(3000));
    const writes: string[] = [];
    fsm.writeAsStringAsync.mockImplementation(async (u: string, d: string) => { writes.push(d); mockFs.set(u, d); });
    await SecureDeleteService.secureDeleteVault('quick');
    expect(fsm.readAsStringAsync).not.toHaveBeenCalledWith('/mock/documents/vault/file_a', expect.anything());
    const last = Buffer.from(writes[writes.length - 1], 'base64');
    expect(last.length).toBe(3000);
    expect(last.some(b => b !== 0)).toBe(true);
    expect(new Set(last).size).toBeGreaterThan(50);
  });

  test('secureDeleteFileById rejects traversal ids', async () => {
    await expect(SecureDeleteService.secureDeleteFileById('../../x')).rejects.toThrow();
  });
});

describe('Sec_Data: panic counter', () => {
  test('concurrent increments are not lost (serialized read-modify-write)', async () => {
    await PanicService.setTriggerAction('lock');
    await Promise.all([PanicService.incrementFailedAttempts(), PanicService.incrementFailedAttempts()]);
    const s = JSON.parse((await secureStore.getItemAsync('filevault_panic_settings'))!);
    expect(s.failedAttempts).toBe(2);
  });

  test('tampered counter/threshold fields are sanitized', async () => {
    await secureStore.setItemAsync('filevault_panic_settings', JSON.stringify({
      triggerAction: 'lock', failedAttempts: -50, maxFailedAttempts: 1e9,
    }));
    await PanicService.incrementFailedAttempts();
    const s = JSON.parse((await secureStore.getItemAsync('filevault_panic_settings'))!);
    expect(s.maxFailedAttempts).toBe(3);
    expect(s.failedAttempts).toBe(1);
  });

  test('corrupt settings fail closed (counter not reset to 0)', async () => {
    await secureStore.setItemAsync('filevault_panic_settings', '{not json');
    const wipe = jest.spyOn(PanicService as any, 'lockAppPermanently').mockResolvedValue(undefined);
    await PanicService.incrementFailedAttempts();
    expect(wipe).toHaveBeenCalled(); // 2 (fail-closed) + 1 reaches the limit of 3
    wipe.mockRestore();
  });

  test('after a wipe nothing is written back to SecureStore', async () => {
    await PanicService.setTriggerAction('wipe');
    for (let i = 0; i < 3; i++) await PanicService.incrementFailedAttempts();
    expect(await secureStore.getItemAsync('filevault_panic_settings')).toBeNull();
  });

  test('lock action keeps the permanent lock after PIN-data deletion', async () => {
    await PanicService.setTriggerAction('lock');
    await PanicService.triggerPanicAction();
    expect(await secureStore.getItemAsync('filevault_lock_until')).toBe(String(Number.MAX_SAFE_INTEGER));
  });
});

describe('Sec_Data: memory wiping', () => {
  test('SafeBuffer.zeroize leaves ALL ZERO (was 0xFF)', () => {
    const b = new SafeBuffer(16);
    b.write('topsecretvalue!!');
    const inner = (b as any).buffer as Uint8Array;
    b.zeroize();
    expect([...inner].every(x => x === 0)).toBe(true);
    expect(b.isZeroized()).toBe(true);
  });
  test('SafeBuffer.write(string) does not throw on exact fit and returns byte length', () => {
    expect(new SafeBuffer(4).write('abcd')).toBe(4);
  });
  test('ZeroingArrayBuffer.read returns a copy, not a live alias', () => {
    const z = new ZeroingArrayBuffer(4);
    z.write(new Uint8Array([1, 2, 3, 4]));
    const r = z.read(0, 4);
    z.zeroize();
    expect([...r]).toEqual([1, 2, 3, 4]); // detached copy; internal buffer is zero
    expect([...z.read(0, 4)]).toEqual([0, 0, 0, 0]);
    expect(z.read().length).toBe(4);
  });
  test('MemoryProtection.zeroizeSecureStore covers every vault/panic/guest key', async () => {
    for (const k of ALL_SECURE_KEYS) await secureStore.setItemAsync(k, 'x');
    await MemoryProtection.aggressiveZeroization();
    expect([...secureStore._store.keys()]).toEqual([]);
  });
});

describe('Sec_Data: legacy base64 "encryption"', () => {
  test('can no longer produce new base64 pseudo-ciphertext; decrypt for migration still works', async () => {
    await expect(LegacyEncryptionService.encryptData('x')).rejects.toThrow();
    await expect(LegacyEncryptionService.encryptFile('x')).rejects.toThrow();
    expect(await LegacyEncryptionService.decryptData(Buffer.from('héllo', 'utf8').toString('base64'))).toBe('héllo');
  });
});
