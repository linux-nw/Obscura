/**
 * BackupAtomicWrite.test.ts — createBackup() must write atomically (H3).
 *
 * Previously createBackup wrote the encrypted backup JSON directly with
 * writeAsStringAsync. A crash mid-write left a truncated, unparseable
 * backup_<id>.json at the final path with no indication anything was wrong.
 * It now goes through writeFileAtomic (temp file + rename), matching the
 * pattern already used for vault content/metadata writes.
 */

const secureStore = require('../__mocks__/expo-secure-store');

const mockStore = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockStore.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockStore.get(from);
    if (v !== undefined) { mockStore.set(to, v); mockStore.delete(from); }
  }),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async (p: string) => ({
    exists: mockStore.has(p),
    isDirectory: p.endsWith('/'),
    size: (mockStore.get(p) || '').length,
  })),
  readDirectoryAsync: jest.fn(async (dir: string) => {
    const names = new Set<string>();
    for (const k of mockStore.keys()) {
      if (k.startsWith(dir)) {
        const rest = k.slice(dir.length);
        if (rest.length && !rest.includes('/')) names.add(rest);
      }
    }
    return [...names];
  }),
}));

jest.mock('../src/services/FileManager', () => ({
  FileManager: { getFiles: jest.fn(async () => []) },
}));
jest.mock('../src/services/NotesService', () => ({
  NotesService: { getNotes: jest.fn(async () => []) },
}));

const FS = require('expo-file-system/legacy');
const { BackupService } = require('../src/services/BackupService');

beforeEach(() => {
  secureStore._reset();
  mockStore.clear();
  jest.clearAllMocks();
});

describe('BackupService.createBackup: atomic write', () => {
  test('writes to a .tmp sibling first, then renames to the final backup path', async () => {
    const id = await BackupService.createBackup('a-strong-passphrase-123');
    const finalPath = `/mock/documents/backups/backup_${id}.json`;

    const writtenPaths = FS.writeAsStringAsync.mock.calls.map((c: any[]) => c[0]);
    const movedFrom = FS.moveAsync.mock.calls.map((c: any[]) => c[0].from);
    const movedTo = FS.moveAsync.mock.calls.map((c: any[]) => c[0].to);

    expect(writtenPaths).toContain(`${finalPath}.tmp`);
    expect(writtenPaths).not.toContain(finalPath); // never written directly at the final path
    expect(movedFrom).toContain(`${finalPath}.tmp`);
    expect(movedTo).toContain(finalPath);

    // Final content is present and parseable.
    expect(mockStore.has(finalPath)).toBe(true);
    expect(() => JSON.parse(mockStore.get(finalPath)!)).not.toThrow();
  });

  test('a leftover .tmp from an interrupted write is swept by initialize()', async () => {
    mockStore.set('/mock/documents/backups/backup_stale.json.tmp', '{"truncated":');
    await BackupService.initialize();
    expect(mockStore.has('/mock/documents/backups/backup_stale.json.tmp')).toBe(false);
  });
});
