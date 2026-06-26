/**
 * F2_CacheCleanup.test.ts — proves imported plaintext cache copies are deleted.
 *
 * The F2 bug: expo-document-picker (copyToCacheDirectory:true) and image-picker
 * leave the plaintext original in the app cache. FileManager.saveFile must
 * delete that cache copy after encryption — but ONLY within cacheDirectory,
 * never user-storage originals.
 *
 * Uses an explicit jest.mock factory for expo-file-system/legacy so the test
 * does not depend on the global moduleNameMapper (which jest-expo overrides).
 */

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory:    '/mock/cache/',
  EncodingType:      { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync:      jest.fn(async () => ({ exists: true, isDirectory: true, size: 0 })),
  makeDirectoryAsync: jest.fn(async () => {}),
  readAsStringAsync:  jest.fn(async () => 'dGVzdA=='), // base64 'test'
  writeAsStringAsync: jest.fn(async () => {}),
  moveAsync:          jest.fn(async () => {}),
  deleteAsync:        jest.fn(async () => {}),
  readDirectoryAsync: jest.fn(async () => []),
}));

jest.mock('../src/services/CryptoService', () => ({
  SecureCryptoService: {
    getMasterKey:    jest.fn(async () => 'a'.repeat(64)),
    encryptFile:     jest.fn(async () => ({ encryptedData: 'deadbeef', iv: '0'.repeat(32), mac: 'f'.repeat(64) })),
    encryptMetadata: jest.fn(async (v: string) => ({ encryptedData: v, iv: '0'.repeat(32), mac: 'f'.repeat(64) })),
    decryptMetadata: jest.fn(async (enc: { data: string }) => enc.data),
  },
}));

const FS = require('expo-file-system/legacy');
const { FileManager } = require('../src/services/FileManager');

beforeEach(() => jest.clearAllMocks());

describe('F2: imported plaintext cache copy is deleted after save', () => {
  test('cache-dir source URI → deleteAsync called on it', async () => {
    const cacheUri = '/mock/cache/Import_abc.pdf';
    await FileManager.saveFile(cacheUri, 'document', 'secret.pdf');

    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deleted).toContain(cacheUri);
  });

  test('data: URI → no file deletion attempted', async () => {
    await FileManager.saveFile('data:application/pdf;base64,dGVzdA==', 'document', 'x.pdf');
    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deleted.every((u: string) => !u?.startsWith?.('data:'))).toBe(true);
  });

  test('source OUTSIDE cache dir (user storage) → NOT deleted', async () => {
    const userUri = '/mock/documents/user_original.pdf';
    await FileManager.saveFile(userUri, 'document', 'doc.pdf');

    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deleted).not.toContain(userUri);
  });
});
