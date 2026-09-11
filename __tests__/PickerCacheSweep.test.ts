/**
 * PickerCacheSweep.test.ts — proves the picker-cache startup sweep.
 *
 * saveFile() deletes the plaintext copy expo-document-picker/-image-picker leave
 * in cache right after import (deletePlaintextCacheCopy), but that delete is
 * itself only best-effort. Unlike vault_view_* temps (already swept on every
 * FileManager.initialize() via cleanupViewTemps), a crash between the picker's
 * copy and that post-import delete previously left the plaintext original behind
 * with no fallback sweep at all. cleanupPickerCacheTemps closes that gap by
 * sweeping the DocumentPicker/ and ImagePicker/ cache subdirectories on every
 * initialize() call.
 */

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  getInfoAsync: jest.fn(),
  readAsStringAsync: jest.fn(async () => ''),
  writeAsStringAsync: jest.fn(async () => {}),
  deleteAsync: jest.fn(async () => {}),
  readDirectoryAsync: jest.fn(),
  makeDirectoryAsync: jest.fn(async () => {}),
}));

jest.mock('../src/services/CryptoService', () => ({
  SecureCryptoService: { clearAllCaches: jest.fn(), initialize: jest.fn() },
}));

const FS = require('expo-file-system/legacy');
const { FileManager } = require('../src/services/FileManager');

beforeEach(() => {
  jest.clearAllMocks();
});

describe('FileManager.cleanupPickerCacheTemps', () => {
  test('overwrites then deletes a leftover file under DocumentPicker/', async () => {
    // /mock/cache/DocumentPicker/ exists and contains one leftover plaintext file;
    // /mock/cache/ImagePicker/ does not exist at all.
    FS.getInfoAsync.mockImplementation(async (path: string) => {
      if (path === '/mock/cache/DocumentPicker/') return { exists: true, isDirectory: true, size: 0 };
      if (path === '/mock/cache/DocumentPicker/leftover.pdf') return { exists: true, isDirectory: false, size: 5 };
      return { exists: false, isDirectory: false, size: 0 };
    });
    FS.readDirectoryAsync.mockImplementation(async (path: string) => {
      if (path === '/mock/cache/DocumentPicker/') return ['leftover.pdf'];
      return [];
    });

    await FileManager.cleanupPickerCacheTemps();

    const written = FS.writeAsStringAsync.mock.calls.map((c: any[]) => c[0]);
    const deleted = FS.deleteAsync.mock.calls.map((c: any[]) => c[0]);
    expect(written).toContain('/mock/cache/DocumentPicker/leftover.pdf');
    expect(deleted).toContain('/mock/cache/DocumentPicker/leftover.pdf');
    // The now-empty directory itself is removed too.
    expect(deleted).toContain('/mock/cache/DocumentPicker/');
  });

  test('neither subdirectory exists → no-op, no errors', async () => {
    FS.getInfoAsync.mockResolvedValue({ exists: false, isDirectory: false, size: 0 });
    FS.readDirectoryAsync.mockResolvedValue([]);

    await expect(FileManager.cleanupPickerCacheTemps()).resolves.toBeUndefined();
    expect(FS.deleteAsync).not.toHaveBeenCalled();
    expect(FS.writeAsStringAsync).not.toHaveBeenCalled();
  });

  test('initialize() runs the picker-cache sweep alongside the view-temp sweep', async () => {
    FS.getInfoAsync.mockResolvedValue({ exists: true, isDirectory: true, size: 0 });
    FS.readDirectoryAsync.mockResolvedValue([]);

    await FileManager.initialize();

    const listedDirs = FS.readDirectoryAsync.mock.calls.map((c: any[]) => c[0]);
    expect(listedDirs).toContain('/mock/cache/DocumentPicker/');
    expect(listedDirs).toContain('/mock/cache/ImagePicker/');
  });

  test('a pathological deep/self-referencing mock is still bounded (depth cap)', async () => {
    // Every path claims to be a directory containing exactly one child named
    // the same regardless of parent - this cannot happen on a real filesystem,
    // but the sweep must never hang or blow the stack if it somehow did.
    FS.getInfoAsync.mockResolvedValue({ exists: true, isDirectory: true, size: 0 });
    FS.readDirectoryAsync.mockResolvedValue(['child']);

    await expect(FileManager.cleanupPickerCacheTemps()).resolves.toBeUndefined();
  }, 10000);
});
