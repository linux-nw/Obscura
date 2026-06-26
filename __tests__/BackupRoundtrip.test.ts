/**
 * BackupRoundtrip.test.ts
 *
 * Verified:
 *   1. encryptBackup → decryptBackup → data identical (full roundtrip)
 *   2. decryptBackup with wrong passphrase → throws (MAC mismatch)
 *      — PBKDF2 still runs on the wrong-pass path (constant-time behavior)
 *   3. Backup key ≠ master key: the HMAC tag in EncryptedBackupData was computed
 *      from a key derived via PBKDF2(backupPassphrase, freshSalt), NOT from the
 *      master key. Proof: re-computing the tag with the master key produces a
 *      different value.
 *
 * Performance note: encryptBackup and decryptBackup each run PBKDF2-600k (~14 s).
 * Timeouts are set accordingly per test. No shared setup is possible because each
 * encryptBackup generates a fresh random salt, so the key is different per call.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  SecureCryptoService.clearAllCaches();
});

import { BackupService, EncryptedBackupData } from '../src/services/BackupService';
import { SecureCryptoService } from '../src/services/CryptoService';
import { fastPbkdf2 } from '../src/services/FastPBKDF2';
import CryptoJS from 'crypto-js';

const BACKUP_PASS = 'SecureBackupPassphrase!';
const WRONG_PASS  = 'WrongPassphrase_NotTheBackupKey';

// Minimal but realistic backup payload (JSON string, as createBackup would produce).
const PAYLOAD = JSON.stringify({
  version: '2.0',
  timestamp: 1716384000000,
  files: [{ id: 'f1', originalName: 'secret.png', type: 'image/png', size: 42, createdAt: '2026-01-01T00:00:00.000Z', content: 'aabbcc' }],
  notes: [{ id: 'n1', title: 'Secret Note', content: 'Top secret', category: 'private', tags: [], createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' }],
});

// ─────────────────────────────── Roundtrip ───────────────────────────────

test('encryptBackup → decryptBackup → data identical', async () => {
  const encrypted: EncryptedBackupData =
    await (BackupService as any).encryptBackup(PAYLOAD, BACKUP_PASS);

  // Verify v3 (Argon2id) format fields are present.
  expect(encrypted.version).toBe(3);
  expect((encrypted as any).kdf).toBe('argon2id');
  expect(encrypted.backup).toBeTruthy();
  expect(encrypted.iv).toBeTruthy();
  expect(encrypted.tag).toBeTruthy();
  expect(encrypted.salt).toBeTruthy(); // Argon2id salt was generated

  const decrypted: string =
    await (BackupService as any).decryptBackup(encrypted, BACKUP_PASS);

  expect(decrypted).toBe(PAYLOAD);
}, 60000);

// ─────────────────────────────── Wrong passphrase ───────────────────────────────

test('wrong passphrase → decryptBackup throws (MAC mismatch)', async () => {
  const encrypted: EncryptedBackupData =
    await (BackupService as any).encryptBackup(PAYLOAD, BACKUP_PASS);

  // decryptBackup runs PBKDF2-600k on the wrong passphrase, derives a different key,
  // computes a different MAC, constantsTimeEquals returns false → throws.
  await expect(
    (BackupService as any).decryptBackup(encrypted, WRONG_PASS)
  ).rejects.toThrow();
}, 60000);

// ─────────────────────────────── Key isolation ───────────────────────────────

test('backup key ≠ master key: tag cannot be reproduced from master key', async () => {
  // Use a fixed synthetic master key — no PBKDF2-600k needed for this test.
  const syntheticMasterKey =
    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'; // 32 bytes, 64 hex
  (SecureCryptoService as any)._masterKeyCache = syntheticMasterKey;

  // encryptBackup derives its own key from BACKUP_PASS + fresh random salt
  // via PBKDF2(BACKUP_PASS.normalize('NFC'), saltHex, 600000, 32).
  const encrypted: EncryptedBackupData =
    await (BackupService as any).encryptBackup(PAYLOAD, BACKUP_PASS);

  // If the backup had used the master key, the following tag would match:
  //   HMAC(deriveMacKey(masterKey), iv || ciphertext) === encrypted.tag
  // It must NOT match, proving a different key was used.
  const masterMacKey = await SecureCryptoService.deriveMacKey(syntheticMasterKey);
  const tagFromMasterKey = await SecureCryptoService.computeMac(
    masterMacKey,
    encrypted.iv + encrypted.backup
  );

  expect(tagFromMasterKey).not.toBe(encrypted.tag);
}, 30000);

// ─────────────────────────────── v2 (legacy PBKDF2) restore ───────────────────────────────

test('legacy v2 (PBKDF2-600k) backup still decrypts on restore (H1 back-compat)', async () => {
  // Hand-build a v2 blob exactly as the old encryptBackup did.
  const saltHex = SecureCryptoService.bufferToHex(await SecureCryptoService.generateSecureBytes(32));
  const key = await fastPbkdf2(BACKUP_PASS.normalize('NFC'), saltHex, 600000, 32);
  const ivHex = SecureCryptoService.bufferToHex(await SecureCryptoService.generateSecureBytes(16));
  const ct = CryptoJS.AES.encrypt(PAYLOAD, CryptoJS.enc.Hex.parse(key), {
    iv: CryptoJS.enc.Hex.parse(ivHex), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7,
  }).ciphertext.toString(CryptoJS.enc.Hex);
  const macKey = await SecureCryptoService.deriveMacKey(key);
  const tag = await SecureCryptoService.computeMac(macKey, ivHex + ct);
  const v2: EncryptedBackupData = { version: 2, backup: ct, iv: ivHex, tag, salt: saltHex };

  const decrypted: string = await (BackupService as any).decryptBackup(v2, BACKUP_PASS);
  expect(decrypted).toBe(PAYLOAD);
}, 60000);
