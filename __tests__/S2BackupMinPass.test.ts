/**
 * S2: createBackup enforces a >= 12 character backup passphrase.
 *
 * The length gate runs before any vault access, so this needs no file/note setup. Restore
 * is intentionally NOT length-gated (older backups stay restorable) — covered by
 * BackupContent.test.ts / BackupRoundtrip.test.ts, which use >= 12 char passphrases.
 */

const secureStore = require('../__mocks__/expo-secure-store');
beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
});

import { BackupService } from '../src/services/BackupService';

describe('S2: backup passphrase floor', () => {
  test('11-char passphrase → rejected with a message naming the 12-char minimum', async () => {
    await expect(BackupService.createBackup('Short11char')).rejects.toThrow(/12/);
  });

  test('exactly 11 chars rejected, boundary', async () => {
    expect('Short11char'.length).toBe(11);
    await expect(BackupService.createBackup('Short11char')).rejects.toThrow();
  });
});
