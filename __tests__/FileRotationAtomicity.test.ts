/**
 * Regression test for the cross-file (content + meta) rotation atomicity fix in
 * FileManager.reencryptAll (security audit follow-up). Fast, in-process fault
 * injection - mirrors the established power-loss-simulation style already used in
 * KeyRotationWAL.test.ts, scoped specifically to the content/meta two-file commit.
 *
 * For an end-to-end proof against a REAL process kill (actual SIGKILL, real disk),
 * see scripts/crash-test/ (run via `node scripts/crash-test/orchestrate.js` - not part
 * of this suite, since it deliberately hangs a child process on purpose).
 *
 * Bug being guarded against: the old reencryptAll wrote new content directly to
 * contentPath, then new meta (with the matching new iv/mac) to metaPath. A crash
 * between those two writes left contentPath re-encrypted under the NEW key while
 * metaPath still named the OLD iv/mac - undecryptable under EITHER key, permanently.
 */

const secureStore = require('../__mocks__/expo-secure-store');

const mockFsStore = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockFsStore.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockFsStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockFsStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockFsStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockFsStore.get(from);
    if (v !== undefined) { mockFsStore.set(to, v); mockFsStore.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockFsStore.has(p) || [...mockFsStore.keys()].some((k) => k.startsWith(p)),
    isDirectory: p.endsWith('/'),
    size: (mockFsStore.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockFsStore.keys()) {
      if (k.startsWith(dir)) {
        const rest = k.slice(dir.length);
        if (rest.length && !rest.includes('/')) names.add(rest);
      }
    }
    return [...names];
  }),
}));

beforeEach(() => {
  secureStore._reset();
  mockFsStore.clear();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { FileManager } from '../src/services/FileManager';

const PASSPHRASE = 'RotationAtomicity-42!';

async function seedFiles(n: number): Promise<void> {
  await SecureCryptoService.setupMasterKey(PASSPHRASE);
  for (let i = 0; i < n; i++) {
    await FileManager.importFile(
      Buffer.from(`file #${i} content`).toString('base64'),
      'document',
      `f${i}.txt`
    );
  }
}

async function allFilesReadable(): Promise<{ id: string; content: string }[]> {
  const files = await FileManager.getFiles();
  const out = [];
  for (const f of files) {
    out.push({ id: f.id, content: await FileManager.getFileContent(f.id) });
  }
  return out;
}

test('crash between content-commit and meta-commit rename: next run still recovers cleanly', async () => {
  await seedFiles(3);
  const oldMaster = SecureCryptoService.__masterKeyHexForTest()!;
  const before = await allFilesReadable();

  const newMasterBuf = await SecureCryptoService.generateSecureBytes(32);
  const newMaster = SecureCryptoService.bufferToHex(newMasterBuf);
  const oldHandle = SecureCryptoService.registerKeyHandle(oldMaster);
  const newHandle = SecureCryptoService.registerKeyHandle(newMaster);

  // Let moveAsync run normally until the SECOND file's content-commit-rename, then
  // throw - simulating the process dying at exactly that point. Each file makes 4
  // moveAsync calls (writeFileAtomic's own tmp-rename for the content stage, same for
  // the meta stage, then the two commit-renames), so call #7 is file #2's content
  // commit and call #8 (its meta commit) never happens.
  const FileSystem = require('expo-file-system/legacy');
  const realMove = FileSystem.moveAsync.getMockImplementation();
  let calls = 0;
  FileSystem.moveAsync.mockImplementation(async (args: { from: string; to: string }) => {
    calls++;
    if (calls === 7) {
      await realMove(args);
      throw new Error('SIMULATED CRASH mid-rotation');
    }
    return realMove(args);
  });

  await expect(FileManager.reencryptAll(oldHandle, newHandle)).rejects.toThrow('SIMULATED CRASH');

  // Prove the exact inconsistent intermediate state actually exists right now: some
  // file's content is already under the new key while a meta '.rotnew' stage sits
  // un-renamed (this is the state that was previously unrecoverable).
  const staleMetaStage = [...mockFsStore.keys()].filter((k) => k.endsWith('.meta.enc.rotnew'));
  expect(staleMetaStage.length).toBeGreaterThan(0);

  // "Resume": moveAsync works normally again, call reencryptAll fresh (exactly what
  // KeyRotationService.resumeRotationIfNeeded does after the next successful unlock),
  // THEN commit by installing the new master key - reencryptAll only migrates content;
  // it's KeyRotationService's job to install afterward, and getFiles()/getFileContent()
  // decrypt using whichever master is currently installed/cached, not an explicit
  // handle. Skipping this step isn't a smaller check - it exercises the wrong key
  // entirely and every file would (correctly) fail to decrypt.
  FileSystem.moveAsync.mockImplementation(realMove);
  await FileManager.reencryptAll(oldHandle, newHandle);
  await SecureCryptoService.installMasterKey(newMaster, PASSPHRASE);

  // No leftover staging artifacts.
  const leftovers = [...mockFsStore.keys()].filter((k) => k.endsWith('.rotnew'));
  expect(leftovers).toEqual([]);

  // Every file, including the one caught mid-rename and the one never touched before
  // the crash, decrypts correctly under the new key and matches its original content.
  const after = await allFilesReadable();
  expect(after.map((f) => f.content).sort()).toEqual(before.map((f) => f.content).sort());

  // And really is under the new key now, not the old one.
  for (const f of await FileManager.getFiles()) {
    await expect(
      SecureCryptoService.decryptDataWithHandle(
        mockFsStore.get(`/mock/documents/vault/${f.name}`)!,
        f.iv,
        f.mac,
        oldHandle
      )
    ).rejects.toThrow();
  }
}, 60000);

test('crash before any staging for a file: original content/meta untouched, resume recomputes', async () => {
  await seedFiles(2);
  const oldMaster = SecureCryptoService.__masterKeyHexForTest()!;
  const before = await allFilesReadable();

  const newMasterBuf = await SecureCryptoService.generateSecureBytes(32);
  const newMaster = SecureCryptoService.bufferToHex(newMasterBuf);
  const oldHandle = SecureCryptoService.registerKeyHandle(oldMaster);
  const newHandle = SecureCryptoService.registerKeyHandle(newMaster);

  const FileSystem = require('expo-file-system/legacy');
  const realMove = FileSystem.moveAsync.getMockImplementation();
  let calls = 0;
  FileSystem.moveAsync.mockImplementation(async (args: { from: string; to: string }) => {
    calls++;
    if (calls === 1) throw new Error('SIMULATED CRASH before any commit');
    return realMove(args);
  });

  await expect(FileManager.reencryptAll(oldHandle, newHandle)).rejects.toThrow('SIMULATED CRASH');

  FileSystem.moveAsync.mockImplementation(realMove);
  await FileManager.reencryptAll(oldHandle, newHandle);
  await SecureCryptoService.installMasterKey(newMaster, PASSPHRASE);

  const after = await allFilesReadable();
  expect(after.map((f) => f.content).sort()).toEqual(before.map((f) => f.content).sort());
}, 60000);
