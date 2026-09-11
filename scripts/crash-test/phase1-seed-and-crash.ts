/**
 * Crash-test phase 1: seed a vault with several files, start a REAL key rotation, and
 * hang (after writing a marker file, via diskMocks.js's CRASH_TEST_HANG_ON_MOVE_CALL
 * support) at a point chosen to land exactly between one file's content-commit-rename
 * and its meta-commit-rename inside FileManager.reencryptAll - the precise crash window
 * the original audit finding described. The orchestrator (orchestrate.js) SIGKILLs this
 * process once it sees the marker, then runs phase2 against the same on-disk state to
 * prove recovery.
 *
 * Must be run via `node scripts/crash-test/orchestrate.js`, not `npm test` - see
 * jest.crashtest.config.js (not picked up by the default test suite).
 *
 * jest.mock() factories may only reference literals, globals, and fresh require()
 * calls - never an outer variable computed elsewhere in this file (babel-plugin-jest-hoist
 * hoists jest.mock() above other top-level code, including the `import`-derived
 * requires below, so an outer const wouldn't be initialized yet when the factory runs).
 * That's why CRASH_TEST_DIR is read from process.env directly inside each factory
 * instead of being captured from an outer variable.
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
const PASSPHRASE = 'CrashTest-Passphrase-42!';
const NUM_FILES = 4;

function fileContent(i: number): string {
  return Buffer.from(`crash-test file #${i} - top secret bytes 🔐`).toString('base64');
}

test('seed vault, start real rotation, hang mid-file for the orchestrator to SIGKILL', async () => {
  if (!CRASH_TEST_DIR) throw new Error('CRASH_TEST_DIR must be set (run via orchestrate.js)');
  if (!process.env.CRASH_TEST_HANG_ON_MOVE_CALL) {
    throw new Error('CRASH_TEST_HANG_ON_MOVE_CALL must be set (run via orchestrate.js)');
  }

  await SecureCryptoService.setupMasterKey(PASSPHRASE);

  for (let i = 0; i < NUM_FILES; i++) {
    await FileManager.importFile(fileContent(i), 'document', `secret-${i}.txt`);
  }
  await NotesService.createNote('Crash-Test-Notiz', 'Notiz-Inhalt', 'privat', []);

  // Record what each file SHOULD decrypt to after rotation, for phase2 (a fresh
  // process/module registry - it can't just share an in-memory value) to check against.
  const files = await FileManager.getFiles();
  const expected: Record<string, string> = {};
  for (const f of files) {
    expected[f.id] = await FileManager.getFileContent(f.id);
  }
  fs.writeFileSync(
    path.join(CRASH_TEST_DIR, 'expected.json'),
    JSON.stringify({ passphrase: PASSPHRASE, expected, numFiles: NUM_FILES }),
  );

  // reencryptAll makes 4 moveAsync calls per file (writeFileAtomic's own internal
  // .tmp-rename for the content stage, same for the meta stage, then the two
  // commit-renames). Arming here (counting from zero, not from process start - seeding
  // above already made its own moveAsync calls) means call #7 after this point is file
  // #2's content COMMIT rename; call #8 (its meta COMMIT rename) never happens. This
  // single kill point exercises BOTH scenarios the audit called out: file #2 caught
  // exactly between its two commit-renames, AND files #3/#4 never touched at all
  // (proving untouched siblings survive an interrupted rotation of their sibling).
  const hangAfter = parseInt(process.env.CRASH_TEST_HANG_ON_MOVE_CALL!, 10);
  require('./diskMocks').armHangAfterMoveCalls(hangAfter);

  await KeyRotationService.performSecureRotation(PASSPHRASE);

  // Should never get here - if we do, the hang point above never fired as expected.
  throw new Error('rotation completed without hitting the crash point - test harness bug');
}, 60000);
