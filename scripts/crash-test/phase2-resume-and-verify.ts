/**
 * Crash-test phase 2: runs in a FRESH process (fresh module registry, fresh in-memory
 * state) against the SAME on-disk CRASH_TEST_DIR that phase1 was SIGKILLed in the
 * middle of writing to. Simulates "the app restarts" - unlocks with the original
 * passphrase (still the OLD master key at this point, since phase1 never reached
 * installMasterKey) and calls the real production resume path,
 * KeyRotationService.resumeRotationIfNeeded, then verifies every file is present and
 * decrypts to its original plaintext under the (now installed) NEW master key.
 *
 * No CRASH_TEST_HANG_ON_MOVE_CALL here - moveAsync runs unmodified so the resume can
 * actually finish.
 */

jest.mock('expo-file-system/legacy', () =>
  require('./diskMocks').makeFileSystemMock(process.env.CRASH_TEST_DIR)
);
jest.mock('expo-file-system', () =>
  require('./diskMocks').makeFileSystemMock(process.env.CRASH_TEST_DIR)
);
jest.mock('expo-secure-store', () =>
  require('./diskMocks').makeSecureStoreMock(process.env.CRASH_TEST_DIR)
);

import { SecureCryptoService } from '../../src/services/CryptoService';
import { FileManager } from '../../src/services/FileManager';
import { NotesService } from '../../src/services/NotesService';
import { KeyRotationService } from '../../src/services/KeyRotationService';

const fs = require('fs');
const path = require('path');

const CRASH_TEST_DIR = process.env.CRASH_TEST_DIR;

test('app "restarts" after the kill: resume finishes rotation, every file survives', async () => {
  if (!CRASH_TEST_DIR) throw new Error('CRASH_TEST_DIR must be set (run via orchestrate.js)');

  const { passphrase, expected, numFiles } = JSON.parse(
    fs.readFileSync(path.join(CRASH_TEST_DIR, 'expected.json'), 'utf8')
  );

  // Sanity: phase1 really did get killed mid-rotation, not complete cleanly.
  expect(fs.existsSync(path.join(CRASH_TEST_DIR, 'KILL_ME_NOW'))).toBe(true);

  // "App restart": cold module state, unlock with the passphrase (the OLD master key is
  // still what's installed on disk - phase1 was killed before installMasterKey ran).
  const unlocked = await SecureCryptoService.unlock(passphrase);
  expect(unlocked).toBe(true);

  expect(await KeyRotationService.hasPendingRotation()).toBe(true);

  // The real production resume path (same call AuthScreen.checkLoginPass makes after a
  // successful real-passphrase unlock).
  await KeyRotationService.resumeRotationIfNeeded(passphrase);

  // Rotation is now fully committed: WAL gone, new master installed.
  expect(await KeyRotationService.hasPendingRotation()).toBe(false);

  const files = await FileManager.getFiles();
  expect(files.length).toBe(numFiles);

  const failures: string[] = [];
  for (const f of files) {
    try {
      const content = await FileManager.getFileContent(f.id);
      if (content !== expected[f.id]) {
        failures.push(`${f.id}: content mismatch (got ${content.slice(0, 20)}..., want ${String(expected[f.id]).slice(0, 20)}...)`);
      }
    } catch (e) {
      failures.push(`${f.id}: threw on decrypt - ${(e as Error).message}`);
    }
  }
  expect(failures).toEqual([]);

  // The note (untouched by the file-level fix, but part of the same rotation) too.
  const notes = await NotesService.getNotes();
  expect(notes.length).toBe(1);
  expect(notes[0].title).toBe('Crash-Test-Notiz');
}, 60000);
