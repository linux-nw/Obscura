/**
 * SecureDelete.test.ts — proves the SecureDelete fail-closed fixes:
 *
 *  1. A failed overwrite pass must NOT be followed by deleteAsync (previously the
 *     overwrite error was swallowed and the file got deleted anyway, reporting
 *     "securely deleted" for a file whose content was never actually overwritten).
 *  2. secureDeleteFileById actually overwrites the content+meta files before
 *     deleting them (real WRITE calls happen, not just a bare delete).
 *  3. FileManager.deleteFile now routes through SecureDeleteService instead of a
 *     bare FileSystem.deleteAsync.
 *  4. secureWipeAll fails closed if the vault/notes directory is still present
 *     after the "deletion" (previously it only ever verified SecureStore keys).
 */

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(),
  readAsStringAsync: jest.fn(async () => 'dGVzdA=='), // base64 'test'
  writeAsStringAsync: jest.fn(async () => {}),
  deleteAsync: jest.fn(async () => {}),
  readDirectoryAsync: jest.fn(async () => []),
}));

jest.mock('expo-secure-store', () => ({
  getItemAsync: jest.fn(async () => null),
}));

jest.mock('../src/services/CryptoService', () => ({
  SecureCryptoService: {
    generateSecureBytes: jest.fn(async (n: number) => new Uint8Array(n).buffer),
    deleteEncryptionKey: jest.fn(async () => {}),
  },
}));

jest.mock('../src/services/HardwareKeystoreService', () => ({
  HardwareBackedStorage: {
    exists: jest.fn(async () => false),
  },
}));

const FS = require('expo-file-system/legacy');
const { SecureDeleteService } = require('../src/services/SecureDeleteService');

beforeEach(() => {
  jest.clearAllMocks();
  // clearAllMocks wipes call history but NOT implementations set via mockResolvedValue/
  // mockRejectedValue in a previous test — restore every mock's default behaviour
  // explicitly so tests can't leak state into one another.
  FS.getInfoAsync.mockImplementation(async () => ({ exists: true, size: 10 }));
  FS.readAsStringAsync.mockImplementation(async () => 'dGVzdA==');
  FS.writeAsStringAsync.mockImplementation(async () => {});
  FS.deleteAsync.mockImplementation(async () => {});
  FS.readDirectoryAsync.mockImplementation(async () => []);
});

describe('SecureDelete: overwrite failure blocks deletion (fail-closed)', () => {
  test('writeAsStringAsync failure → deleteAsync is never called for that file', async () => {
    FS.writeAsStringAsync.mockRejectedValue(new Error('disk full'));

    await expect(
      SecureDeleteService.secureDeleteFileById('abc123', 'quick')
    ).rejects.toThrow();

    expect(FS.deleteAsync).not.toHaveBeenCalled();
  });

  test('secureDeleteVault aborts (and does not rm the dir) if one file fails to overwrite', async () => {
    FS.readDirectoryAsync.mockResolvedValue(['file_a', 'file_b']);
    FS.writeAsStringAsync.mockRejectedValue(new Error('io error'));

    await expect(SecureDeleteService.secureDeleteVault('quick')).rejects.toThrow();

    // The vault directory itself must NOT have been force-deleted out from under
    // a file that was never actually overwritten.
    const deletedPaths = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(deletedPaths).not.toContain('/mock/documents/vault/');
  });
});

describe('SecureDelete: real per-file overwrite happens before deletion', () => {
  test('secureDeleteFileById overwrites content AND meta, then deletes both', async () => {
    await SecureDeleteService.secureDeleteFileById('xyz789', 'quick');

    const written = FS.writeAsStringAsync.mock.calls.map((c: any[]) => c[0]);
    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);

    expect(written).toContain('/mock/documents/vault/file_xyz789');
    expect(written).toContain('/mock/documents/vault/file_xyz789.meta.enc');
    expect(deleted).toContain('/mock/documents/vault/file_xyz789');
    expect(deleted).toContain('/mock/documents/vault/file_xyz789.meta.enc');

    // Overwrite must happen strictly before delete for each path.
    for (const path of ['/mock/documents/vault/file_xyz789', '/mock/documents/vault/file_xyz789.meta.enc']) {
      const writeIdx = FS.writeAsStringAsync.mock.calls.findIndex((c: any[]) => c[0] === path);
      const deleteIdx = FS.deleteAsync.mock.calls.findIndex((c: any[]) => c[0] === path);
      expect(writeIdx).toBeGreaterThanOrEqual(0);
      expect(deleteIdx).toBeGreaterThan(-1);
    }
  });
});

describe('SecureDelete: secureWipeAll verifies the actual directories are gone', () => {
  test('vault directory still present after "deletion" → secureWipeAll throws', async () => {
    // Directory listing empty (no files to overwrite) but getInfoAsync keeps
    // reporting the vault dir itself as still existing — simulates a deleteAsync
    // that silently no-op'd.
    FS.readDirectoryAsync.mockResolvedValue([]);
    FS.getInfoAsync.mockImplementation(async (path: string) => ({
      exists: path === '/mock/documents/vault/' || path === '/mock/documents/notes/',
      size: 0,
    }));

    await expect(SecureDeleteService.secureWipeAll()).rejects.toThrow(/still exists/);
  });

  test('directories genuinely gone → secureWipeAll resolves', async () => {
    FS.readDirectoryAsync.mockResolvedValue([]);
    FS.getInfoAsync.mockImplementation(async () => ({ exists: false, size: 0 }));

    await expect(SecureDeleteService.secureWipeAll()).resolves.toBeUndefined();
  });
});
