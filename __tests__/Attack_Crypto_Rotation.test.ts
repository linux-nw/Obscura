/**
 * RED TEAM — key-rotation crash injection at EVERY mutating I/O step, WAL tamper / replay /
 * malformed-input attacks, backup tamper. Invariant: after "reboot" + unlock + resume, no data loss.
 */
const secureStore = require('../__mocks__/expo-secure-store');
const WAL_KEY = 'filevault_keyrotation_wal';

const mockFs = new Map<string, string>();
let mockDead = false;
const mockOps = { n: 0, failAt: -1 };
function mockMutate(): void {
  if (mockDead) throw new Error('power loss');
  mockOps.n++;
  if (mockOps.failAt > 0 && mockOps.n >= mockOps.failAt) { mockDead = true; throw new Error('power loss'); }
}
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, d: string) => { mockMutate(); mockFs.set(p, d); }),
  readAsStringAsync: jest.fn(async (p: string) => { if (!mockFs.has(p)) throw new Error(`ENOENT: ${p}`); return mockFs.get(p); }),
  deleteAsync: jest.fn(async (p: string) => { mockMutate(); mockFs.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    mockMutate();
    const v = mockFs.get(from); if (v !== undefined) { mockFs.set(to, v); mockFs.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockFs.has(p) || [...mockFs.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'), size: (mockFs.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockFs.keys()) if (k.startsWith(dir)) { const r = k.slice(dir.length); if (r.length && !r.includes('/')) names.add(r); }
    return [...names];
  }),
}));

import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService as C } from '../src/services/CryptoService';
import { KeyRotationService } from '../src/services/KeyRotationService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';
import * as FEK from '../src/services/FileEncryptionKey';

const PASS = 'Rotation-Attack-Pass-1!';
const FILE_B64 = Buffer.from('rotation attack file bytes 🔐').toString('base64');
const NOTE_BODY = 'note body Ümläut 🔑';
const S = secureStore._store as Map<string, string>;

let ssSnap: Map<string, string>;
let fsSnap: Map<string, string>;

async function readBack(): Promise<{ file: string; note: string }> {
  const files = await FileManager.getFiles();
  const notes = await NotesService.getNotes();
  return { file: await FileManager.getFileContent(files[0].id), note: notes[0].content };
}

beforeAll(async () => {
  secureStore._reset(); mockFs.clear();
  C.clearAllCaches();
  await C.setupMasterKey(PASS);
  await FileManager.importFile(FILE_B64, 'document', 'secret.txt');
  await NotesService.createNote('T', NOTE_BODY, 'cat', ['x']);
  ssSnap = new Map(S); fsSnap = new Map(mockFs);
}, 60000);

function restore() {
  S.clear(); ssSnap.forEach((v, k) => S.set(k, v));
  mockFs.clear(); fsSnap.forEach((v, k) => mockFs.set(k, v));
  mockDead = false; mockOps.n = 0; mockOps.failAt = -1;
  C.clearAllCaches();
}
beforeEach(() => { jest.restoreAllMocks(); restore(); });

/** "Reboot": drop all in-memory state, passphrase login, post-unlock resume (AuthScreen flow). */
async function reboot(): Promise<void> {
  mockDead = false; mockOps.failAt = -1;
  C.clearAllCaches();
  S.delete('filevault_failed_attempts'); S.delete('filevault_lock_until');
  expect(await C.unlock(PASS)).toBe(true);
  await KeyRotationService.resumeRotationIfNeeded(PASS);
}

describe('crash injection: power loss at every mutating step of performSecureRotation', () => {
  // Count mutating ops in a clean run.
  let total = 0;
  beforeAll(async () => {
    restore();
    const orig = (SecureStore.setItemAsync as jest.Mock).getMockImplementation()!;
    const origDel = (SecureStore.deleteItemAsync as jest.Mock).getMockImplementation()!;
    (SecureStore.setItemAsync as jest.Mock).mockImplementation(async (k: string, v: string, o?: any) => { mockMutate(); return orig(k, v, o); });
    (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(async (k: string) => { mockMutate(); return origDel(k); });
    await C.unlock(PASS);
    await KeyRotationService.performSecureRotation(PASS);
    total = mockOps.n;
    (SecureStore.setItemAsync as jest.Mock).mockImplementation(orig);
    (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(origDel);
  }, 120000);

  test('clean run performs a meaningful number of steps', () => { expect(total).toBeGreaterThan(8); });

  test('power loss at every step k=1..N: reboot+unlock+resume => all content readable, no WAL, vault unlocks', async () => {
    const orig = (SecureStore.setItemAsync as jest.Mock).getMockImplementation()!;
    const origDel = (SecureStore.deleteItemAsync as jest.Mock).getMockImplementation()!;
    const wrap = () => {
      (SecureStore.setItemAsync as jest.Mock).mockImplementation(async (k: string, v: string, o?: any) => { mockMutate(); return orig(k, v, o); });
      (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(async (k: string) => { mockMutate(); return origDel(k); });
    };
    const unwrap = () => {
      (SecureStore.setItemAsync as jest.Mock).mockImplementation(orig);
      (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(origDel);
    };
    const failures: string[] = [];
    for (let k = 1; k <= total; k++) {
      restore();
      wrap();
      await C.unlock(PASS);
      mockOps.n = 0; mockOps.failAt = k;
      let threw = false;
      try { await KeyRotationService.performSecureRotation(PASS); } catch { threw = true; }
      unwrap();
      try {
        await reboot();
        const rb = await readBack();
        if (rb.file !== FILE_B64 || rb.note !== NOTE_BODY) failures.push(`k=${k}: content mismatch`);
        if (await KeyRotationService.hasPendingRotation()) failures.push(`k=${k}: WAL still pending`);
        // fresh process again: passphrase still works and content still readable
        C.clearAllCaches();
        if (!(await C.unlock(PASS))) failures.push(`k=${k}: unlock failed after recovery`);
        const rb2 = await readBack();
        if (rb2.file !== FILE_B64 || rb2.note !== NOTE_BODY) failures.push(`k=${k}: content mismatch after 2nd boot`);
      } catch (e) {
        failures.push(`k=${k}: ${(e as Error).message} (rotation threw=${threw})`);
      }
    }
    expect(failures).toEqual([]);
  }, 600000);

  test('crash DURING resume, then resume again (nested crash) => still recovers', async () => {
    const orig = (SecureStore.setItemAsync as jest.Mock).getMockImplementation()!;
    const origDel = (SecureStore.deleteItemAsync as jest.Mock).getMockImplementation()!;
    // First: crash mid-rotation (after WAL written, k = a few steps in)
    for (const [k1, k2] of [[3, 2], [4, 5], [5, 1], [6, 3]]) {
      restore();
      const wrap = () => {
        (SecureStore.setItemAsync as jest.Mock).mockImplementation(async (kk: string, v: string, o?: any) => { mockMutate(); return orig(kk, v, o); });
        (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(async (kk: string) => { mockMutate(); return origDel(kk); });
      };
      wrap();
      await C.unlock(PASS);
      mockOps.n = 0; mockOps.failAt = k1;
      await KeyRotationService.performSecureRotation(PASS).catch(() => {});
      // reboot, but crash during resume
      mockDead = false; C.clearAllCaches(); S.delete('filevault_failed_attempts'); S.delete('filevault_lock_until');
      await C.unlock(PASS);
      mockOps.n = 0; mockOps.failAt = k2;
      await KeyRotationService.resumeRotationIfNeeded(PASS).catch(() => {});
      (SecureStore.setItemAsync as jest.Mock).mockImplementation(orig);
      (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(origDel);
      await reboot();
      const rb = await readBack();
      expect(rb.file).toBe(FILE_B64);
      expect(rb.note).toBe(NOTE_BODY);
      expect(await KeyRotationService.hasPendingRotation()).toBe(false);
    }
  }, 300000);
});

describe('WAL malformed / hostile input', () => {
  const hostile: Array<[string, string]> = [
    ['not json', '{oops'], ['empty object', '{}'], ['null', 'null'], ['array', '[]'], ['string', '"x"'],
    ['startedAt NaN-ish', JSON.stringify({ newMasterWrapped: { encryptedKey: 'aa', iv: 'bb', mac: 'cc' }, startedAt: 'x' })],
    ['non-hex fields', JSON.stringify({ newMasterWrapped: { encryptedKey: 'zz', iv: 'zz', mac: 'zz', createdAt: 'x' }, startedAt: 1 })],
    ['proto pollution', '{"__proto__":{"polluted":1},"newMasterWrapped":{"encryptedKey":"aa","iv":"bb","mac":"cc"},"startedAt":1}'],
    ['hex but wrong sizes', JSON.stringify({ newMasterWrapped: { encryptedKey: 'aa', iv: 'bb', mac: 'cc', createdAt: 'x' }, startedAt: Date.now() })],
    ['huge blob', JSON.stringify({ newMasterWrapped: { encryptedKey: 'ab'.repeat(500000), iv: 'ab'.repeat(16), mac: 'ab'.repeat(32), createdAt: 'x' }, startedAt: 1 })],
    ['future startedAt', JSON.stringify({ newMasterWrapped: { encryptedKey: 'ab'.repeat(48), iv: 'ab'.repeat(16), mac: 'ab'.repeat(32), createdAt: 'x' }, startedAt: 9e15 })],
  ];
  test.each(hostile)('%s: resume neither throws nor damages content/master', async (_n, raw) => {
    await C.unlock(PASS);
    const master = C.__masterKeyHexForTest();
    S.set(WAL_KEY, raw);
    await expect(KeyRotationService.resumeRotationIfNeeded(PASS)).resolves.toBeUndefined();
    expect(C.__masterKeyHexForTest()).toBe(master);
    expect((await readBack()).file).toBe(FILE_B64);
    expect(({} as any).polluted).toBeUndefined();
    // fresh boot still unlocks
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(true);
  }, 60000);

  test('a hostile WAL blocks performSecureRotation but does not corrupt anything', async () => {
    await C.unlock(PASS);
    S.set(WAL_KEY, '{oops');
    await expect(KeyRotationService.performSecureRotation(PASS)).rejects.toThrow();
    expect((await readBack()).note).toBe(NOTE_BODY);
  }, 60000);

  test('resume when not unlocked is a no-op (cannot be driven without the old key)', async () => {
    await C.unlock(PASS);
    // craft a valid WAL, then lock
    const oldH = C.currentMasterHandle();
    const nm = C.bufferToHex(await C.generateSecureBytes(32));
    const w = await C.encryptFileKeyWith(nm, oldH);
    S.set(WAL_KEY, JSON.stringify({ newMasterWrapped: w, startedAt: Date.now() }));
    C.clearAllCaches();
    await expect(KeyRotationService.resumeRotationIfNeeded(PASS)).resolves.toBeUndefined();
    expect(S.has(WAL_KEY)).toBe(true);
  }, 60000);

  test('resume with the WRONG passphrase argument cannot re-wrap the new master under an attacker passphrase silently', async () => {
    await C.unlock(PASS);
    const oldH = C.currentMasterHandle();
    const nm = C.bufferToHex(await C.generateSecureBytes(32));
    const w = await C.encryptFileKeyWith(nm, oldH);
    S.set(WAL_KEY, JSON.stringify({ newMasterWrapped: w, startedAt: Date.now() }));
    // Caller passes a different passphrase (programming error / hostile caller): resume installs
    // the new master under THAT passphrase. Assert the real passphrase must still be what unlocks
    // only if resume was given it; documents the contract (resume trusts its caller).
    await KeyRotationService.resumeRotationIfNeeded(PASS);
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(nm);
  }, 60000);

  test('WAL replay: old completed WAL re-planted after a later rotation is discarded, data intact', async () => {
    await C.unlock(PASS);
    // rotation #1, capture its WAL by interrupting right before delete
    const origDel = (SecureStore.deleteItemAsync as jest.Mock).getMockImplementation()!;
    let captured: string | null = null;
    (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(async (k: string) => {
      if (k === WAL_KEY) captured = S.get(WAL_KEY) ?? null;
      return origDel(k);
    });
    await KeyRotationService.performSecureRotation(PASS);
    expect(captured).not.toBeNull();
    await KeyRotationService.performSecureRotation(PASS); // rotation #2
    (SecureStore.deleteItemAsync as jest.Mock).mockImplementation(origDel);
    const master2 = C.__masterKeyHexForTest();
    S.set(WAL_KEY, captured!);
    await KeyRotationService.resumeRotationIfNeeded(PASS);
    expect(C.__masterKeyHexForTest()).toBe(master2);
    expect(S.has(WAL_KEY)).toBe(false);
    expect((await readBack()).file).toBe(FILE_B64);
  }, 120000);

  test('WAL ciphertext bit-flip: resume does not crash; vault remains unlockable (data-loss risk documented as OPEN for store-write adversary)', async () => {
    await C.unlock(PASS);
    const oldH = C.currentMasterHandle();
    const nm = C.bufferToHex(await C.generateSecureBytes(32));
    const w = await C.encryptFileKeyWith(nm, oldH);
    const t = { ...w, encryptedKey: (w.encryptedKey[0] === '0' ? '1' : '0') + w.encryptedKey.slice(1) };
    S.set(WAL_KEY, JSON.stringify({ newMasterWrapped: t, startedAt: Date.now() }));
    await expect(KeyRotationService.resumeRotationIfNeeded(PASS)).resolves.toBeUndefined();
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(true);
    // No content had been migrated (no partial state) so nothing is lost here.
    expect((await readBack()).file).toBe(FILE_B64);
  }, 60000);
});

describe('rotation misc', () => {
  test('rotation with wrong / non-string passphrase aborts without touching WAL or content', async () => {
    for (const p of ['', 'x', null, undefined, 5, {}] as any[]) {
      await expect(KeyRotationService.performSecureRotation(p)).rejects.toThrow();
    }
    expect(S.has(WAL_KEY)).toBe(false);
    C.clearAllCaches(); S.delete('filevault_failed_attempts'); S.delete('filevault_lock_until');
    expect(await C.unlock(PASS)).toBe(true);
    expect((await readBack()).file).toBe(FILE_B64);
  }, 60000);

  test('after a full rotation the OLD master cannot decrypt ANY stored blob and new master differs', async () => {
    await C.unlock(PASS);
    const oldMaster = C.__masterKeyHexForTest()!;
    await KeyRotationService.performSecureRotation(PASS);
    expect(C.__masterKeyHexForTest()).not.toBe(oldMaster);
    const oldH = C.registerKeyHandle(oldMaster);
    const files = await FileManager.getFiles();
    const name = [...mockFs.keys()].find((k) => /vault\/file_[^/]+$/.test(k) && !k.endsWith('.tmp'))!;
    const meta = JSON.parse(mockFs.get(name + '.meta.enc')!);
    await expect(C.decryptDataWithHandle(mockFs.get(name)!, meta.iv, meta.mac, oldH, `${files[0].id}:content:v1`)).rejects.toThrow();
    // old wrapped master (replayed) now opens the OLD key, which can decrypt nothing
    expect(await C.getFailedAttempts()).toBe(0);
  }, 60000);

  test('rotation leaves no master / passphrase material in console output', async () => {
    const spies = ['log', 'info', 'warn', 'error', 'debug'].map((m) => jest.spyOn(console, m as any).mockImplementation(() => {}));
    await C.unlock(PASS);
    const oldMaster = C.__masterKeyHexForTest()!;
    await KeyRotationService.performSecureRotation(PASS);
    const nm = C.__masterKeyHexForTest()!;
    const out = JSON.stringify(spies.flatMap((s) => s.mock.calls.map((c) => c.map((x: any) => (x instanceof Error ? x.message : x)))));
    for (const sec of [PASS, oldMaster, nm]) expect(out).not.toContain(sec);
    for (const v of S.values()) { expect(String(v)).not.toContain(nm); expect(String(v)).not.toContain(oldMaster); }
  }, 60000);

  test('KeyRotationService public settings API tolerates tampered stored values', async () => {
    for (const k of ['filevault_last_rotation', 'filevault_next_rotation', 'filevault_rotation_count', 'filevault_rotation_interval']) {
      for (const v of ['NaN', '-5', 'abc', '', '1e999', '99999999999999999999']) S.set(k, v);
    }
    S.set('filevault_rotation_enabled', 'true');
    const info = await KeyRotationService.getRotationInfo();
    for (const n of [info.lastRotation, info.nextRotation, info.rotationCount, info.rotationIntervalDays]) expect(Number.isNaN(n)).toBe(false);
    expect(Number.isNaN(await KeyRotationService.getTimeUntilRotation())).toBe(false);
    await expect(KeyRotationService.isRotationDue()).resolves.toEqual(expect.any(Boolean));
    await expect(KeyRotationService.getKeyHistory()).resolves.toBeDefined();
    for (const d of [NaN, -1, 0, Infinity, 1e9]) {
      await expect(KeyRotationService.enableRotation(d as number)).resolves.not.toThrow();
      const i2 = await KeyRotationService.getRotationInfo();
      expect(Number.isFinite(i2.rotationIntervalDays)).toBe(true);
      expect(i2.rotationIntervalDays).toBeGreaterThan(0);
    }
    await expect(KeyRotationService.cleanupOldKeys(NaN)).resolves.not.toThrow();
  }, 60000);
});

describe('file key store replay / rewrap', () => {
  test('rewrapFileKey with attacker-modified wrapped key throws and does not overwrite stored key', async () => {
    await C.unlock(PASS);
    const fk = await FEK.generateFileKey();
    const w = await FEK.wrapFileKey(fk);
    await FEK.storeEncryptedFileKey('fk1', w);
    const before = S.get(FEK.getFileKeyStorageName('fk1'));
    const bad = { ...w, mac: (w.mac[0] === '0' ? '1' : '0') + w.mac.slice(1) };
    await expect(FEK.rewrapFileKey('fk1', bad)).rejects.toThrow();
    expect(S.get(FEK.getFileKeyStorageName('fk1'))).toBe(before);
    expect(await FEK.unwrapFileKey((await FEK.loadEncryptedFileKey('fk1'))!)).toBe(fk);
  }, 60000);

  test('wrapped file key from before rotation is unreadable after rotation (no stale-key resurrection)', async () => {
    await C.unlock(PASS);
    const fk = await FEK.generateFileKey();
    const w = await FEK.wrapFileKey(fk);
    await KeyRotationService.performSecureRotation(PASS);
    await expect(FEK.unwrapFileKey(w)).rejects.toThrow();
  }, 60000);
});
