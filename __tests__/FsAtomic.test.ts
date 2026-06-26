/**
 * FsAtomic.test.ts — H3 atomic write + temp cleanup.
 */

const mockAtomicStore = new Map<string, string>();
jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  writeAsStringAsync: jest.fn(async (p: string, data: string) => { mockAtomicStore.set(p, data); }),
  readAsStringAsync: jest.fn(async (p: string) => {
    if (!mockAtomicStore.has(p)) throw new Error(`ENOENT: ${p}`);
    return mockAtomicStore.get(p);
  }),
  deleteAsync: jest.fn(async (p: string) => { mockAtomicStore.delete(p); }),
  moveAsync: jest.fn(async ({ from, to }: { from: string; to: string }) => {
    const v = mockAtomicStore.get(from);
    if (v !== undefined) { mockAtomicStore.set(to, v); mockAtomicStore.delete(from); }
  }),
  readDirectoryAsync: jest.fn(async (dir: string) =>
    [...mockAtomicStore.keys()].filter(k => k.startsWith(dir)).map(k => k.slice(dir.length))),
}));

import { writeFileAtomic, cleanupTempFiles } from '../src/services/fsAtomic';

beforeEach(() => mockAtomicStore.clear());

const DIR = '/mock/documents/vault/';

test('writeFileAtomic lands data at target, leaves no .tmp', async () => {
  await writeFileAtomic(`${DIR}file_1`, 'ciphertext');
  expect(mockAtomicStore.get(`${DIR}file_1`)).toBe('ciphertext');
  expect(mockAtomicStore.has(`${DIR}file_1.tmp`)).toBe(false);
});

test('cleanupTempFiles deletes a leftover .tmp and never promotes it', async () => {
  // Simulate a crash mid-write: a truncated .tmp with no committed target.
  mockAtomicStore.set(`${DIR}file_2.tmp`, 'truncated-partial');
  await cleanupTempFiles(DIR);
  expect(mockAtomicStore.has(`${DIR}file_2.tmp`)).toBe(false);
  expect(mockAtomicStore.has(`${DIR}file_2`)).toBe(false); // NOT promoted
});

test('cleanupTempFiles leaves committed targets untouched', async () => {
  mockAtomicStore.set(`${DIR}file_3`, 'committed');
  mockAtomicStore.set(`${DIR}file_3.tmp`, 'orphan');
  await cleanupTempFiles(DIR);
  expect(mockAtomicStore.get(`${DIR}file_3`)).toBe('committed');
  expect(mockAtomicStore.has(`${DIR}file_3.tmp`)).toBe(false);
});
