/**
 * B5_BackupDecoyOperationLock.test.ts
 *
 * B.5 (AUDIT_2026-09-15-v2.md): BackupService.createBackup()/applyBackupData() and
 * DecoyVaultService.createFakeFiles()/createFakeNotes() are multi-step, master-key-keyed
 * operations that were NOT wrapped in AutoLockService.beginOperation()/endOperation() — the
 * same class of bug M2 fixed for FileManager.reencryptAll()/KeyRotationService. If the app
 * backgrounds mid-operation, auto-lock could fire and tear down the key while work is still
 * in flight.
 *
 * These tests prove the actual property (same pattern as F2_PickerLockSuppression.test.ts):
 * AutoLockService.triggerLock() is suppressed WHILE the operation is running, and fires again
 * once it has finished — for both the success path and (via `finally`) the error path.
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
    exists: mockStore.has(p) || [...mockStore.keys()].some((k) => k.startsWith(p)),
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

import { SecureCryptoService } from '../src/services/CryptoService';
import { AutoLockService } from '../src/services/AutoLockService';
import { BackupService } from '../src/services/BackupService';
import { DecoyVaultService } from '../src/services/DecoyVaultService';
import { FileManager } from '../src/services/FileManager';
import { NotesService } from '../src/services/NotesService';

const VAULT_PASS = 'VaultPass123!';
const BACKUP_PASS = 'BackupPass456!';
const GUEST_PIN = '13571357';
const FILE_CONTENT_B64 = Buffer.from('mid-operation-content').toString('base64');

beforeEach(() => {
  secureStore._reset();
  mockStore.clear();
  jest.restoreAllMocks();
  SecureCryptoService.clearAllCaches();
  DecoyVaultService.clearDecoyCache();
  (AutoLockService as any).operationCount = 0;
  (AutoLockService as any).operationStartedAt = 0;
});

describe('B.5: BackupService operations suppress auto-lock while running', () => {
  test('createBackup() suppresses triggerLock mid-flight, releases it once done', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASS);
    await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');

    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);

    const realGetFileContent = FileManager.getFileContent.bind(FileManager);
    jest.spyOn(FileManager, 'getFileContent').mockImplementation(async (id: string) => {
      // Simulate the app backgrounding WHILE createBackup is still reading file content.
      expect(AutoLockService.isOperationInProgress()).toBe(true);
      await AutoLockService.triggerLock();
      expect(cb).not.toHaveBeenCalled(); // suppressed: still inside beginOperation/endOperation
      return realGetFileContent(id);
    });

    await BackupService.createBackup(BACKUP_PASS);

    expect(AutoLockService.isOperationInProgress()).toBe(false);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1); // fires again once the backup is done

    AutoLockService.setLockCallback(() => {});
  }, 60000);

  test('applyBackupData() (via restoreBackup) suppresses triggerLock mid-flight', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASS);
    await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');
    await NotesService.createNote('Titel', 'Inhalt', 'privat', []);
    const backupId = await BackupService.createBackup(BACKUP_PASS);

    for (const k of [...mockStore.keys()]) {
      if (k.startsWith('/mock/documents/vault/') || k.startsWith('/mock/documents/notes/')) {
        mockStore.delete(k);
      }
    }

    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);

    const realImportFile = FileManager.importFile.bind(FileManager);
    jest.spyOn(FileManager, 'importFile').mockImplementation(async (...args: any[]) => {
      expect(AutoLockService.isOperationInProgress()).toBe(true);
      await AutoLockService.triggerLock();
      expect(cb).not.toHaveBeenCalled();
      return (realImportFile as any)(...args);
    });

    const ok = await BackupService.restoreBackup(BACKUP_PASS, backupId);
    expect(ok).toBe(true);

    expect(AutoLockService.isOperationInProgress()).toBe(false);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);

    AutoLockService.setLockCallback(() => {});
  }, 60000);

  test('applyBackupData() releases the operation lock even when a step throws (finally)', async () => {
    await SecureCryptoService.setupMasterKey(VAULT_PASS);
    await FileManager.importFile(FILE_CONTENT_B64, 'document', 'secret.txt');
    const backupId = await BackupService.createBackup(BACKUP_PASS);

    jest.spyOn(FileManager, 'importFile').mockImplementation(async () => {
      throw new Error('simulated failure mid-restore');
    });

    const ok = await BackupService.restoreBackup(BACKUP_PASS, backupId);
    expect(ok).toBe(false); // restoreBackup's own catch turns this into `false`

    // The finally in applyBackupData must have run despite the thrown error.
    expect(AutoLockService.isOperationInProgress()).toBe(false);
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);
    AutoLockService.setLockCallback(() => {});
  }, 60000);
});

describe('B.5: DecoyVaultService operations suppress auto-lock while running', () => {
  async function openGuest() {
    await DecoyVaultService.enableDecoyVault();
    await DecoyVaultService.setDecoyPin(GUEST_PIN);
  }

  test('createFakeFiles() suppresses triggerLock mid-flight, releases it once done', async () => {
    await openGuest();

    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);

    const fsLegacy = require('expo-file-system/legacy');
    const realWrite = fsLegacy.writeAsStringAsync.getMockImplementation();
    fsLegacy.writeAsStringAsync.mockImplementation(async (p: string, data: string) => {
      expect(AutoLockService.isOperationInProgress()).toBe(true);
      await AutoLockService.triggerLock();
      expect(cb).not.toHaveBeenCalled();
      return realWrite(p, data);
    });

    await DecoyVaultService.createFakeFiles();

    expect(AutoLockService.isOperationInProgress()).toBe(false);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);

    AutoLockService.setLockCallback(() => {});
  }, 60000);

  test('createFakeNotes() suppresses triggerLock mid-flight, releases it once done', async () => {
    await openGuest();

    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);

    const fsLegacy = require('expo-file-system/legacy');
    const realWrite = fsLegacy.writeAsStringAsync.getMockImplementation();
    fsLegacy.writeAsStringAsync.mockImplementation(async (p: string, data: string) => {
      expect(AutoLockService.isOperationInProgress()).toBe(true);
      await AutoLockService.triggerLock();
      expect(cb).not.toHaveBeenCalled();
      return realWrite(p, data);
    });

    await DecoyVaultService.createFakeNotes();

    expect(AutoLockService.isOperationInProgress()).toBe(false);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);

    AutoLockService.setLockCallback(() => {});
  }, 60000);
});
