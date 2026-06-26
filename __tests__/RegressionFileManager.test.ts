/**
 * RegressionFileManager.test.ts
 *
 * R-C: getFiles() returns defined name for old metadata without name field (Bug 4)
 * R-D: saveFile() writes name field into the metadata JSON (Bug 4, write side)
 *
 * Uses mocked CryptoService (decryptMetadata returns value as-is) and
 * mocked expo-file-system so no real I/O or crypto happens.
 */

// ─── Module mocks (must be before imports) ───────────────────────────────────

jest.mock('../src/services/CryptoService', () => {
  // Preserve module shape but replace the crypto calls FileManager uses.
  // clearAllCaches and getMasterKey are left as stubs since the tests don't
  // exercise the full crypto pipeline.
  return {
    SecureCryptoService: {
      clearAllCaches: jest.fn(),
      initialize: jest.fn(),
      getMasterKey: jest.fn(async () => 'a'.repeat(64)),
      encryptFile: jest.fn(async () => ({
        encryptedData: 'deadbeef',
        iv: '0'.repeat(32),
        mac: 'f'.repeat(64),
      })),
      encryptMetadata: jest.fn(async (value: string) => ({
        encryptedData: value,
        iv: '0'.repeat(32),
        mac: 'f'.repeat(64),
      })),
      decryptMetadata: jest.fn(async (enc: { data: string }) => enc.data),
    },
  };
});

// ─── Imports ─────────────────────────────────────────────────────────────────

const fileSystemMock = require('../__mocks__/expo-file-system');

beforeEach(() => {
  jest.clearAllMocks();
  fileSystemMock.readDirectoryAsync.mockResolvedValue([]);
  fileSystemMock.getInfoAsync.mockResolvedValue({ exists: true, isDirectory: true, size: 0 });
  fileSystemMock.makeDirectoryAsync.mockResolvedValue(undefined);
});

// FileManager is imported AFTER mocks are set up
const { FileManager } = require('../src/services/FileManager');

// ─── R-C: Backward-compat — name derived from meta filename when absent ───────

describe('R-C: getFiles() handles old metadata without name field', () => {
  test('missing name field → name derived from metafile filename', async () => {
    fileSystemMock.readDirectoryAsync.mockResolvedValue(['file_abc123_def456.meta.enc']);
    fileSystemMock.readAsStringAsync.mockResolvedValue(
      JSON.stringify({
        id: 'abc123_def456',
        // name: intentionally absent — simulates pre-fix metadata
        originalName: { data: 'test.pdf', iv: '0'.repeat(32), mac: 'f'.repeat(64) },
        type:         { data: 'document', iv: '0'.repeat(32), mac: 'f'.repeat(64) },
        size: 1234,
        createdAt: new Date().toISOString(),
        iv: '0'.repeat(32),
        mac: 'f'.repeat(64),
      })
    );

    const files = await FileManager.getFiles();

    expect(files.length).toBe(1);
    // Fallback: derive from metafile name (strip .meta.enc)
    expect(files[0].name).toBeDefined();
    expect(files[0].name).not.toBe('');
    expect(files[0].name).not.toBeNull();
    expect(files[0].name).toBe('file_abc123_def456');
  });

  test('name field present → used as-is (new format)', async () => {
    const expectedName = 'file_xyz789_aabbcc';
    fileSystemMock.readDirectoryAsync.mockResolvedValue([`${expectedName}.meta.enc`]);
    fileSystemMock.readAsStringAsync.mockResolvedValue(
      JSON.stringify({
        id: 'xyz789_aabbcc',
        name: expectedName,  // name IS present
        originalName: { data: 'photo.jpg', iv: '0'.repeat(32), mac: 'f'.repeat(64) },
        type:         { data: 'image',     iv: '0'.repeat(32), mac: 'f'.repeat(64) },
        size: 999,
        createdAt: new Date().toISOString(),
        iv: '0'.repeat(32),
        mac: 'f'.repeat(64),
      })
    );

    const files = await FileManager.getFiles();
    expect(files[0].name).toBe(expectedName);
  });
});

// ─── R-D: saveFile() writes name field into the JSON ─────────────────────────

describe('R-D: saveFile() includes name field in written metadata JSON', () => {
  test('written .meta.enc JSON has non-empty name field starting with "file_"', async () => {
    fileSystemMock.getInfoAsync.mockResolvedValue({ exists: false });
    fileSystemMock.readAsStringAsync.mockResolvedValue('dGVzdA=='); // base64 'test'

    const writtenCalls: Array<{ path: string; content: string }> = [];
    fileSystemMock.writeAsStringAsync.mockImplementation(
      async (path: string, content: string) => {
        writtenCalls.push({ path, content });
      }
    );

    await FileManager.saveFile(
      'data:application/pdf;base64,dGVzdA==',
      'document',
      'test.pdf'
    );

    // Find the metadata write. H3: writes go via a `.tmp` sibling (atomic rename),
    // so strip a trailing `.tmp` before matching.
    const base = (p: string) => p.replace(/\.tmp$/, '');
    const metaWrite = writtenCalls.find(c => base(c.path).endsWith('.meta.enc'));
    expect(metaWrite).toBeDefined();

    const parsed = JSON.parse(metaWrite!.content);
    expect(parsed.name).toBeDefined();
    expect(typeof parsed.name).toBe('string');
    expect(parsed.name.length).toBeGreaterThan(5);
    expect(parsed.name).toMatch(/^file_/);
  });

  test('name in metadata JSON matches the actual content file path', async () => {
    fileSystemMock.getInfoAsync.mockResolvedValue({ exists: false });
    fileSystemMock.readAsStringAsync.mockResolvedValue('dGVzdA==');

    const writtenPaths: string[] = [];
    fileSystemMock.writeAsStringAsync.mockImplementation(async (path: string) => {
      writtenPaths.push(path);
    });

    await FileManager.saveFile('data:text/plain;base64,dGVzdA==', 'document', 'note.txt');

    // H3: atomic writes append `.tmp`; strip it before matching.
    const paths = writtenPaths.map(p => p.replace(/\.tmp$/, ''));
    const metaPath    = paths.find(p => p.endsWith('.meta.enc'))!;
    const contentPath = paths.find(p => !p.endsWith('.meta.enc'))!;

    expect(metaPath).toBeDefined();
    expect(contentPath).toBeDefined();

    // meta file is named "{name}.meta.enc", content file is named "{name}"
    const nameFromMeta    = metaPath.replace(/^.*\//, '').replace('.meta.enc', '');
    const nameFromContent = contentPath.replace(/^.*\//, '');
    expect(nameFromMeta).toBe(nameFromContent);
  });
});
