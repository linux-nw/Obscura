/**
 * Attack_Data_Vault — red-team attacks on decoy ("guest") vault deniability, panic-PIN counter,
 * full-wipe completeness (real key material, real flows) and secrets-in-logs.
 */
const mockFs = new Map<string, string>();
const mockDirs = new Set<string>();

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
import { SecureCryptoService } from '../src/services/CryptoService';
import { DecoyVaultService } from '../src/services/DecoyVaultService';
import { Argon2idService } from '../src/services/Argon2idService';
import { SecureDeleteService, ALL_SECURE_KEYS } from '../src/services/SecureDeleteService';
import { PanicService } from '../src/services/PanicService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import { BackupService } from '../src/services/BackupService';
import { KeyRotationService } from '../src/services/KeyRotationService';

const FS = require('expo-file-system/legacy');
const GUEST = '/mock/documents/guest/';
const PIN = 'guestpin-8888';
const VAULT = 'VaultPass123!';
const B64 = Buffer.from('SECRET-PLAINTEXT-MARKER').toString('base64');

beforeEach(() => {
  secureStore._reset();
  mockFs.clear(); mockDirs.clear();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
  DecoyVaultService.clearDecoyCache();
});

describe('Attack_Data_Vault: decoy existence distinguishability', () => {
  test('a vault WITHOUT a guest profile has no guest SecureStore keys; one WITH has only guest-family names and never the word "decoy"', async () => {
    await SecureCryptoService.setupMasterKey(VAULT);
    await DecoyVaultService.initialize();
    expect([...secureStore._store.keys()].filter((k: string) => /guest|decoy/i.test(k))).toEqual([]);

    await DecoyVaultService.enableDecoyVault();
    await DecoyVaultService.setDecoyPin(PIN);
    await DecoyVaultService.createFakeFiles();
    await DecoyVaultService.createFakeNotes();
    await DecoyVaultService.saveNote('t', 'c');
    await DecoyVaultService.saveFile('data:text/plain;base64,QUJD', 'document', 'x.txt');
    const keys = [...secureStore._store.keys()];
    expect(keys.filter((k: string) => /decoy|fake|panic/i.test(k) && /decoy|fake/i.test(k))).toEqual([]);
    const paths = [...mockFs.keys()].filter((k) => k.startsWith(GUEST));
    expect(paths.length).toBeGreaterThan(0);
    for (const p of paths) expect(p).not.toMatch(/decoy|fake|hidden/i);
    // none of the stored VALUES leaks the word either
    for (const k of keys) expect(String(await secureStore.getItemAsync(k))).not.toMatch(/decoy/i);
  }, 120000);

  test('guest ids and the real vault ids share one shape; guest blobs are opaque (no plaintext fields)', async () => {
    await SecureCryptoService.setupMasterKey(VAULT);
    await DecoyVaultService.enableDecoyVault();
    await DecoyVaultService.setDecoyPin(PIN);
    await DecoyVaultService.createFakeFiles();
    const real = await FileManager.importFile(B64, 'document', 'a.txt');
    const shape = /^[0-9a-z]+_[0-9a-f]{16}$/;
    expect(real.id).toMatch(shape);
    for (const f of await DecoyVaultService.getFakeFiles()) expect(f.id).toMatch(shape);
    for (const p of [...mockFs.keys()].filter((k) => k.startsWith(GUEST))) {
      const raw = mockFs.get(p)!;
      expect(raw).not.toMatch(/holiday|family_clip|work_document|Bank|Password|originalName|SECRET/);
    }
  }, 120000);

  test('verify cost parity: unconfigured, configured+wrong, configured+right all run exactly one Argon2id (decoy and panic)', async () => {
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    const run = async (fn: () => Promise<boolean>) => { spy.mockClear(); await fn(); return spy.mock.calls.length; };
    const unconfD = await run(() => DecoyVaultService.verifyDecoyPin(PIN));
    const unconfP = await run(() => PanicService.verifyPanicPin(PIN));
    await DecoyVaultService.setDecoyPin(PIN);
    await PanicService.setPanicPin(PIN + 'p');
    const wrongD = await run(() => DecoyVaultService.verifyDecoyPin('x' + PIN));
    const rightD = await run(() => DecoyVaultService.verifyDecoyPin(PIN));
    const wrongP = await run(() => PanicService.verifyPanicPin('x' + PIN));
    const rightP = await run(() => PanicService.verifyPanicPin(PIN + 'p'));
    expect([unconfD, unconfP, wrongD, rightD, wrongP, rightP]).toEqual([1, 1, 1, 1, 1, 1]);
    spy.mockRestore();
  }, 120000);

  test('partial credential store (hash without salt / salt without hash) is treated as unconfigured, same cost', async () => {
    const spy = jest.spyOn(Argon2idService, 'deriveKey');
    await secureStore.setItemAsync('filevault_guest_pin_hash', 'ab'.repeat(32));
    spy.mockClear();
    expect(await DecoyVaultService.verifyDecoyPin(PIN)).toBe(false);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  }, 60000);

  test('sealed guest blobs are slot-bound: swapping or cross-replaying them yields nothing, never another slot\'s data', async () => {
    await DecoyVaultService.setDecoyPin(PIN);
    const a = await DecoyVaultService.saveNote('A', 'a-body');
    const b = await DecoyVaultService.saveNote('B', 'b-body');
    const pa = `${GUEST}note_${a.id}`, pb = `${GUEST}note_${b.id}`;
    const ba = mockFs.get(pa)!;
    mockFs.set(pa, mockFs.get(pb)!);
    mockFs.set(pb, ba);
    expect(await DecoyVaultService.getFakeNotes()).toEqual([]);
    // a note blob dropped into a file-meta slot
    mockFs.set(`${GUEST}file_zz_0000000000000000.meta`, ba);
    expect(await DecoyVaultService.getFakeFiles()).toEqual([]);
  }, 60000);

  test('guest operations are fail-closed without the content key and reject traversal ids', async () => {
    await expect(DecoyVaultService.saveNote('t', 'c')).rejects.toThrow();
    await expect(DecoyVaultService.saveFile('data:x;base64,QQ==', 'document', 'a.txt')).rejects.toThrow();
    await DecoyVaultService.setDecoyPin(PIN);
    FS.deleteAsync.mockClear();
    for (const id of ['../x', 'a/b', '', 'x'.repeat(65), '%2e%2e']) {
      await expect(DecoyVaultService.saveNote('t', 'c', 'cat', id)).rejects.toThrow();
      await expect(DecoyVaultService.deleteNote(id)).rejects.toThrow();
      await expect(DecoyVaultService.deleteFile(id)).rejects.toThrow();
      await expect(DecoyVaultService.getFakeFileContent(id)).rejects.toThrow();
    }
    await expect(DecoyVaultService.saveFile('data:x;base64,QQ==', 'document', '../a')).rejects.toThrow();
    expect(FS.deleteAsync).not.toHaveBeenCalled();
  }, 60000);

  test('guest export temp: hostile name keeps path inside cache and temp is removable', async () => {
    await DecoyVaultService.setDecoyPin(PIN);
    const f = await DecoyVaultService.saveFile('data:x;base64,QUJD', 'document', 'a.%2e%2e');
    const uri = await DecoyVaultService.exportFakeToTempFile(f.id);
    expect(uri).toMatch(/^\/mock\/cache\/vault_view_[0-9a-z]+_[0-9a-f]{16}$/);
    await FileManager.deleteTempFile(uri);
    expect(mockFs.has(uri)).toBe(false);
  }, 60000);

  test('guest import failure leaves no orphan sealed content without metadata', async () => {
    await DecoyVaultService.setDecoyPin(PIN);
    const orig = FS.writeAsStringAsync.getMockImplementation();
    FS.writeAsStringAsync.mockImplementation(async (u: string, d: string) => {
      if (u.endsWith('.meta')) throw new Error('ENOSPC');
      mockFs.set(u, d);
    });
    await expect(DecoyVaultService.saveFile('data:x;base64,QUJD', 'document', 'a.txt')).rejects.toThrow();
    FS.writeAsStringAsync.mockImplementation(orig);
    expect([...mockFs.keys()].filter((k) => k.startsWith(GUEST) && k.includes('/file_'))).toEqual([]);
  }, 60000);
});

describe('Attack_Data_Vault: panic PIN counter attacks', () => {
  const STORE = 'filevault_panic_settings';

  test.each([['[]'], ['[1,2,3]'], ['"str"'], ['5'], ['true'], ['null']])(
    'non-object stored settings %s cannot freeze the counter (lockout must still trigger within the limit)',
    async (raw) => {
      await secureStore.setItemAsync(STORE, raw);
      const lock = jest.spyOn(PanicService as any, 'lockAppPermanently').mockResolvedValue(undefined);
      for (let i = 0; i < 3; i++) await PanicService.incrementFailedAttempts();
      expect(lock).toHaveBeenCalled();
      lock.mockRestore();
    });

  test('tampered fields: string / float / negative counters and huge threshold cannot grant extra attempts', async () => {
    const lock = jest.spyOn(PanicService as any, 'lockAppPermanently').mockResolvedValue(undefined);
    for (const s of [
      { failedAttempts: '0', maxFailedAttempts: 3 },
      { failedAttempts: 0.5, maxFailedAttempts: 3 },
      { failedAttempts: -1e9, maxFailedAttempts: 1e12 },
      { failedAttempts: 0, maxFailedAttempts: -5 },
    ]) {
      await secureStore.setItemAsync(STORE, JSON.stringify({ triggerAction: 'lock', ...s }));
      lock.mockClear();
      for (let i = 0; i < 20; i++) await PanicService.incrementFailedAttempts();
      expect(lock).toHaveBeenCalled();
    }
    lock.mockRestore();
  });

  test('counter survives a "rewrite store with older snapshot" only as far as SecureStore does (DOCUMENTED: keystore-protected, not enforceable in JS)', async () => {
    await PanicService.setTriggerAction('lock');
    await PanicService.incrementFailedAttempts();
    await PanicService.incrementFailedAttempts();
    const snap = await secureStore.getItemAsync(STORE);
    expect(JSON.parse(snap!).failedAttempts).toBe(2);
    // An actor who can delete/rewrite the keystore entry can reset the counter; the vault master
    // key sits in the same keystore, so that actor already owns the vault. Nothing to fix here.
    await secureStore.deleteItemAsync(STORE);
    expect(await PanicService.getTriggerAction()).toBe('lock');
  });

  test('many concurrent failed attempts (wipe action): exactly one wipe, and nothing resurrected afterwards', async () => {
    await PanicService.setTriggerAction('wipe');
    await SecureCryptoService.setupMasterKey(VAULT);
    const wipe = jest.spyOn(SecureDeleteService, 'secureWipeAll');
    await Promise.all(Array.from({ length: 12 }, () => PanicService.incrementFailedAttempts()));
    expect(wipe.mock.calls.length).toBe(1);
    expect(await secureStore.getItemAsync(STORE)).toBeNull();
    expect([...secureStore._store.keys()].filter((k: string) => ALL_SECURE_KEYS.includes(k))).toEqual([]);
    wipe.mockRestore();
  }, 120000);

  test('lock action: concurrent attempts never lose the permanent lock', async () => {
    await PanicService.setTriggerAction('lock');
    await Promise.all(Array.from({ length: 9 }, () => PanicService.incrementFailedAttempts()));
    expect(await secureStore.getItemAsync('filevault_lock_until')).toBe(String(Number.MAX_SAFE_INTEGER));
  });

  test('guessing the panic PIN never reveals set/unset or right/wrong via thrown errors', async () => {
    await PanicService.setPanicPin('right-panic-pin');
    for (const g of ['', 'x', 'right-panic-pin', 'a'.repeat(100000), '\u0000', 'é']) {
      await expect(PanicService.verifyPanicPin(g)).resolves.toEqual(expect.any(Boolean));
    }
  }, 60000);
});

describe('Attack_Data_Vault: wipe completeness with REAL key material', () => {
  async function populate() {
    await SecureCryptoService.setupMasterKey(VAULT);
    await SecureCryptoService.setAppInitialized(true);
    await FileManager.importFile(B64, 'document', 'a.txt');
    await NotesService.createNote('t', 'c', 'cat', ['x']);
    await BackupService.createBackup('BackupPass456!');
    await DecoyVaultService.enableDecoyVault();
    await DecoyVaultService.setDecoyPin(PIN);
    await DecoyVaultService.createFakeFiles();
    await DecoyVaultService.createFakeNotes();
    await PanicService.setPanicPin('panicpin-1234');
    await PanicService.setTriggerAction('wipe');
    await PanicService.incrementFailedAttempts();
    await secureStore.setItemAsync('filevault_auth_attempts', '2');
    await secureStore.setItemAsync('filevault_guest_active', 'true');
    await secureStore.setItemAsync('filevault_last_backup', '1');
    const f = (await FileManager.getFiles())[0];
    await FileManager.exportToTempFile(f.id);
    await KeyRotationService.initialize().catch(() => {});
    await KeyRotationService.triggerManualRotation().catch(() => {});
  }

  const leftovers = () => ({
    keys: [...secureStore._store.keys()] as string[],
    files: [...mockFs.keys()],
  });

  test('PanicService wipe flow leaves no SecureStore key, no vault/notes/guest/backup file, no view temp', async () => {
    await populate();
    expect(leftovers().keys.length).toBeGreaterThan(10);
    await PanicService.triggerPanicAction();
    const left = leftovers();
    expect(left.keys).toEqual([]);
    expect(left.files).toEqual([]);
  }, 120000);

  test('secureWipeAll alone leaves no key and no file either', async () => {
    await populate();
    await SecureDeleteService.secureWipeAll();
    const left = leftovers();
    expect(left.keys).toEqual([]);
    expect(left.files).toEqual([]);
  }, 120000);

  test('after a wipe the app is NOT initialized, the master key is gone and old blobs are unreadable even if restored', async () => {
    await populate();
    const files = [...mockFs.entries()].filter(([k]) => k.includes('/vault/') || k.includes('/notes/'));
    await PanicService.triggerPanicAction();
    expect(await SecureCryptoService.isAppInitialized()).toBe(false);
    // attacker restores the ciphertext he copied earlier; with a fresh vault it must not decrypt
    for (const [k, v] of files) mockFs.set(k, v);
    SecureCryptoService.clearAllCaches();
    await SecureCryptoService.setupMasterKey('A-completely-new-pass-9!');
    expect((await FileManager.getFiles()).length).toBe(0);
    expect((await NotesService.getNotes()).length).toBe(0);
  }, 120000);

  test('wipe still destroys the key when a file deletion throws', async () => {
    await populate();
    const orig = FS.deleteAsync.getMockImplementation();
    FS.deleteAsync.mockImplementation(async (u: string) => {
      if (u.includes('/vault/')) throw new Error('EIO');
      return orig!(u);
    });
    await PanicService.triggerPanicAction().catch(() => {});
    FS.deleteAsync.mockImplementation(orig);
    expect(leftovers().keys).toEqual([]);
    expect(leftovers().files.filter((f) => f.includes('/guest/') || f.includes('/backups/') || f.includes('/cache/'))).toEqual([]);
  }, 120000);
});

describe('Attack_Data_Vault: no secrets in logs', () => {
  test('setup, backup, guest, panic and wipe flows never log PINs, passphrases, plaintext or 32-byte hex', async () => {
    const logged: string[] = [];
    const cap = (...a: unknown[]) => logged.push(a.map((x) => (x instanceof Error ? `${x.message}\n${x.stack}` : typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
    const spies = (['log', 'warn', 'error', 'info', 'debug'] as const).map((m) => jest.spyOn(console, m).mockImplementation(cap));

    await SecureCryptoService.setupMasterKey(VAULT);
    await FileManager.importFile(B64, 'document', 'SECRETNAME.txt');
    await NotesService.createNote('SECRET-TITLE', 'SECRET-BODY');
    await BackupService.createBackup('BackupPass456!');
    await BackupService.restoreBackup('WRONG-passphrase-777', 'nonexistent');
    await DecoyVaultService.setDecoyPin(PIN);
    await DecoyVaultService.verifyDecoyPin('wrong-guest-pin-1');
    await PanicService.setPanicPin('panicpin-1234');
    await PanicService.verifyPanicPin('wrong-panic-pin-1');
    await SecureCryptoService.unlock('wrong-vault-pass-12').catch(() => {});
    await PanicService.setTriggerAction('wipe');
    await PanicService.triggerPanicAction();

    spies.forEach((s) => s.mockRestore());
    const hay = logged.join('\n');
    for (const needle of [VAULT, PIN, 'BackupPass456!', 'WRONG-passphrase-777', 'wrong-guest-pin-1', 'panicpin-1234',
      'wrong-panic-pin-1', 'wrong-vault-pass-12', 'SECRET-PLAINTEXT-MARKER', B64, 'SECRET-BODY', 'SECRET-TITLE', 'SECRETNAME']) {
      expect(hay).not.toContain(needle);
    }
    expect(hay).not.toMatch(/\b[0-9a-f]{64}\b/);
  }, 180000);
});
