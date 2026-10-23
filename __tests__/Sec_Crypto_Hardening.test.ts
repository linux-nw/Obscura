const secureStore = require('../__mocks__/expo-secure-store');
const rn = require('react-native');
const cryptoMock = require('../__mocks__/expo-crypto');

jest.mock('expo-file-system/legacy', () => ({
  documentDirectory: '/mock/documents/',
  cacheDirectory: '/mock/cache/',
  EncodingType: { UTF8: 'utf8', Base64: 'base64' },
  writeAsStringAsync: jest.fn(async () => {}),
  readAsStringAsync: jest.fn(async () => { throw new Error('ENOENT'); }),
  deleteAsync: jest.fn(async () => {}),
  moveAsync: jest.fn(async () => {}),
  makeDirectoryAsync: jest.fn(async () => {}),
  getInfoAsync: jest.fn(async () => ({ exists: false, isDirectory: false, size: 0 })),
  readDirectoryAsync: jest.fn(async () => []),
}));

import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from '../src/services/CryptoService';
import { KeyRotationService } from '../src/services/KeyRotationService';
import { fastPbkdf2, hkdfSha256 } from '../src/services/FastPBKDF2';
import { aesCbcEncryptRaw, aesCbcDecryptRaw } from '../src/services/AesCbcHmac';
import { Argon2idService, DEFAULT_ARGON2_PARAMS } from '../src/services/Argon2idService';
import { keyCustody } from '../src/services/KeyCustody';
import * as FEK from '../src/services/FileEncryptionKey';
import * as RNFileVault from '../src/native/RNFileVault';

const PASS = 'Sec-Crypto-Passphrase-1!';
const KEY = 'ab'.repeat(32);

beforeEach(() => {
  secureStore._reset();
  jest.restoreAllMocks();
  SecureCryptoService.clearAllCaches();
  delete rn.NativeModules.RNFileVault;
});

describe('AES-CBC+HMAC IV/ciphertext boundary malleability', () => {
  test('moving bytes from the ciphertext into the IV does not verify (file-key wrap)', async () => {
    const handle = SecureCryptoService.registerKeyHandle(KEY);
    const fileKey = 'cd'.repeat(32);
    const w = await SecureCryptoService.encryptFileKeyWith(fileKey, handle);
    expect(await SecureCryptoService.decryptFileKeyWith(w, handle)).toBe(fileKey);

    const shifted = { ...w, iv: w.iv + w.encryptedKey.slice(0, 32), encryptedKey: w.encryptedKey.slice(32) };
    await expect(SecureCryptoService.decryptFileKeyWith(shifted, handle)).rejects.toThrow();

    const shortIv = { ...w, iv: w.iv.slice(0, 30), encryptedKey: w.iv.slice(30) + w.encryptedKey };
    await expect(SecureCryptoService.decryptFileKeyWith(shortIv, handle)).rejects.toThrow();
  });

  test('moving bytes between iv and data is rejected on the content path', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    const e = await SecureCryptoService.encryptData('hello world', 'ctx');
    expect(await SecureCryptoService.decryptData(e.encryptedData, e.iv, e.mac, 'ctx')).toBe('hello world');
    const body = e.encryptedData.slice(2);
    await expect(
      SecureCryptoService.decryptData(e.encryptedData.slice(0, 2) + body.slice(32), e.iv + body.slice(0, 32), e.mac, 'ctx')
    ).rejects.toThrow();
    await expect(SecureCryptoService.decryptData(e.encryptedData, e.iv, e.mac.slice(0, 62), 'ctx')).rejects.toThrow();
  });

  test('malformed backend prefix such as "1z" is rejected, not parsed as 0x01', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    const e = await SecureCryptoService.encryptData('x', 'c');
    await expect(
      SecureCryptoService.decryptData('2z' + e.encryptedData.slice(2), e.iv, e.mac, 'c')
    ).rejects.toThrow();
  });

  test('XChaCha20 nonce and tag lengths are validated before reaching the native bridge', async () => {
    const decrypt = jest.fn(async () => 'AA==');
    rn.NativeModules.RNFileVault = { decrypt, encrypt: jest.fn(), verifyConstantTime: async () => ({ result: false }) };
    const h = SecureCryptoService.registerKeyHandle(KEY);
    await expect(
      SecureCryptoService.decryptDataWithHandle('01' + 'aa'.repeat(8), 'aa'.repeat(16), 'bb'.repeat(16), h)
    ).rejects.toThrow();
    await expect(
      SecureCryptoService.decryptDataWithHandle('01' + 'aa'.repeat(8), 'aa'.repeat(24), 'bb'.repeat(8), h)
    ).rejects.toThrow();
    expect(decrypt).not.toHaveBeenCalled();
  });
});

describe('strict hex handling', () => {
  test('hexToBuffer rejects odd length and non-hex characters', () => {
    expect(() => SecureCryptoService.hexToBuffer('abc')).toThrow();
    expect(() => SecureCryptoService.hexToBuffer('zz')).toThrow();
    expect(() => SecureCryptoService.hexToBuffer('+1-1')).toThrow();
    expect(new Uint8Array(SecureCryptoService.hexToBuffer('00ff'))).toEqual(new Uint8Array([0, 255]));
  });

  test('computeMac refuses a malformed MAC key instead of silently using empty key bytes', async () => {
    await expect(SecureCryptoService.computeMac('not-hex', 'data')).rejects.toThrow();
    const ok = await SecureCryptoService.computeMac('11'.repeat(32), 'data');
    expect(ok).toMatch(/^[0-9a-f]{64}$/);
  });

  test('deriveMacKey never caches the raw key as a Map key', async () => {
    await SecureCryptoService.deriveMacKey(KEY);
    expect((SecureCryptoService as any).macKeyCache.size).toBe(0);
  });

  test('master key installation requires exactly 64 hex chars', () => {
    expect(() => { (SecureCryptoService as any)._masterKeyCache = 'ab'.repeat(16); }).toThrow();
    expect(() => { (SecureCryptoService as any)._masterKeyCache = 'zz'.repeat(32); }).toThrow();
  });

  test('KeyCustody registerRawKey requires 32-byte keys', () => {
    expect(() => keyCustody.registerRawKey('ab'.repeat(16))).toThrow();
    expect(() => keyCustody.registerRawKey('ab'.repeat(33))).toThrow();
    const h = keyCustody.registerRawKey(KEY);
    expect(keyCustody.has(h)).toBe(true);
    keyCustody.close(h);
  });
});

describe('CSPRNG output checks', () => {
  test('all-zero or short RNG output is refused', async () => {
    cryptoMock.getRandomBytesAsync.mockImplementationOnce(async (n: number) => new Uint8Array(n));
    await expect(SecureCryptoService.generateSecureBytes(24)).rejects.toThrow();
    cryptoMock.getRandomBytesAsync.mockImplementationOnce(async () => new Uint8Array(8).fill(7));
    await expect(SecureCryptoService.generateSecureBytes(24)).rejects.toThrow();
    expect((await SecureCryptoService.generateSecureBytes(24)).byteLength).toBe(24);
  });
});

describe('wrapped-master write is crash-safe', () => {
  test('a crash part-way through changePassphrase rolls forward on next unlock', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    const master = SecureCryptoService.__masterKeyHexForTest();
    SecureCryptoService.clearAllCaches();

    const realSet = (SecureStore.setItemAsync as jest.Mock).getMockImplementation()!;
    let calls = 0;
    (SecureStore.setItemAsync as jest.Mock).mockImplementation(async (k: string, v: string, o?: any) => {
      calls++;
      if (calls > 4) throw new Error('simulated power loss');
      return realSet(k, v, o);
    });

    expect(await SecureCryptoService.changePassphrase(PASS, 'brand-new-pass')).toBe(false);
    expect(secureStore._store.has('filevault_master_txn')).toBe(true);

    (SecureStore.setItemAsync as jest.Mock).mockImplementation(realSet);
    SecureCryptoService.clearAllCaches();

    expect(await SecureCryptoService.unlock('brand-new-pass')).toBe(true);
    expect(SecureCryptoService.__masterKeyHexForTest()).toBe(master);
    expect(secureStore._store.has('filevault_master_txn')).toBe(false);
  }, 60000);

  test('a corrupt transaction record is discarded without bricking the vault', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    secureStore._store.set('filevault_master_txn', '{not json');
    SecureCryptoService.clearAllCaches();
    expect(await SecureCryptoService.unlock(PASS)).toBe(true);
    expect(secureStore._store.has('filevault_master_txn')).toBe(false);
  });

  test('a transaction with malformed fields is never applied', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    secureStore._store.set('filevault_master_txn', JSON.stringify({ kekSaltHex: 'zz', ivHex: 'zz', ctHex: 'zz', macHex: 'zz' }));
    SecureCryptoService.clearAllCaches();
    expect(await SecureCryptoService.unlock(PASS)).toBe(true);
  });
});

describe('lockout state tampering', () => {
  test('a non-numeric lock-until value locks instead of unlocking', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    SecureCryptoService.clearAllCaches();
    secureStore._store.set('filevault_lock_until', 'garbage');
    expect(await SecureCryptoService.unlock(PASS)).toBe(false);
    const st = await SecureCryptoService.getLockStatus();
    expect(st.locked).toBe(true);
    expect(Number(secureStore._store.get('filevault_lock_until'))).toBeGreaterThan(Date.now());
  });

  test('a non-numeric attempt counter cannot disable the lockout', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    SecureCryptoService.clearAllCaches();
    secureStore._store.set('filevault_failed_attempts', 'NaN');
    expect(await SecureCryptoService.unlock('wrong-1')).toBe(false);
    expect((await SecureCryptoService.getLockStatus()).locked).toBe(true);
  });

  test('concurrent wrong guesses are serialized and counted exactly', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    SecureCryptoService.clearAllCaches();
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => SecureCryptoService.unlock(`wrong-${i}`))
    );
    expect(results.every((r) => r === false)).toBe(true);
    expect(await SecureCryptoService.getFailedAttempts()).toBe(5);
    expect(await SecureCryptoService.unlock(PASS)).toBe(false);
  }, 60000);
});

describe('legacy plaintext-master-key paths are gone', () => {
  test('updatePinHash and rotateEncryptionKey refuse to run', async () => {
    secureStore._store.set('filevault_encryption_key', KEY);
    await expect(SecureCryptoService.updatePinHash('1234')).rejects.toThrow();
    await expect(SecureCryptoService.rotateEncryptionKey('1234')).rejects.toThrow();
    expect(secureStore._store.has('filevault_pin_key')).toBe(false);
  });
});

describe('key rotation WAL safety', () => {
  test('a malformed WAL is kept and blocks a new rotation instead of being overwritten', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    secureStore._store.set('filevault_keyrotation_wal', '{"broken":true}');
    await expect(KeyRotationService.performSecureRotation(PASS)).rejects.toThrow();
    expect(secureStore._store.get('filevault_keyrotation_wal')).toBe('{"broken":true}');
  }, 60000);

  test('a WAL that is unparseable is never deleted by resume', async () => {
    await SecureCryptoService.setupMasterKey(PASS);
    secureStore._store.set('filevault_keyrotation_wal', 'not json');
    await KeyRotationService.resumeRotationIfNeeded(PASS);
    expect(secureStore._store.get('filevault_keyrotation_wal')).toBe('not json');
  });

  test('rotation interval is validated', async () => {
    await expect(KeyRotationService.enableRotation(Number.NaN)).rejects.toThrow();
    await expect(KeyRotationService.enableRotation(-5)).rejects.toThrow();
    await expect(KeyRotationService.enableRotation(30)).resolves.toBeUndefined();
  });
});

describe('primitive input validation', () => {
  test('hkdfSha256 rejects bad length and malformed IKM', () => {
    expect(() => hkdfSha256(KEY, 'l', 0)).toThrow();
    expect(() => hkdfSha256(KEY, 'l', 64)).toThrow();
    expect(() => hkdfSha256('zz'.repeat(32), 'l', 32)).toThrow();
    expect(hkdfSha256(KEY, 'filevault-mac-v1', 32)).toMatch(/^[0-9a-f]{64}$/);
  });

  test('fastPbkdf2 rejects zero iterations, bad key length and bad salt', async () => {
    const salt = '00'.repeat(16);
    await expect(fastPbkdf2('p', salt, 0, 32)).rejects.toThrow();
    await expect(fastPbkdf2('p', salt, 10, 3)).rejects.toThrow();
    await expect(fastPbkdf2('p', 'xyz', 10, 32)).rejects.toThrow();
    await expect(fastPbkdf2('p', salt, 10, 32)).resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  test('aesCbc raw helpers reject malformed key, IV and ciphertext lengths', async () => {
    const iv = '01'.repeat(16);
    await expect(aesCbcEncryptRaw('x', 'ab'.repeat(16), iv)).rejects.toThrow();
    await expect(aesCbcEncryptRaw('x', KEY, '01'.repeat(8))).rejects.toThrow();
    await expect(aesCbcDecryptRaw('abcd', KEY, iv)).rejects.toThrow();
    await expect(aesCbcDecryptRaw('', KEY, iv)).rejects.toThrow();
    const ct = await aesCbcEncryptRaw('hello', KEY, iv);
    expect(await aesCbcDecryptRaw(ct, KEY, iv)).toBe('hello');
  });

  test('FileEncryptionKey validates file ids, stored shape and unwrapped key format', async () => {
    await expect(FEK.loadEncryptedFileKey('../../etc')).rejects.toThrow();
    await expect(FEK.storeEncryptedFileKey('a/b', {} as any)).rejects.toThrow();
    expect(() => FEK.getFileKeyStorageName('a b')).toThrow();
    secureStore._store.set('filevault_filekey_f1', '{"encryptedKey":1}');
    await expect(FEK.loadEncryptedFileKey('f1')).rejects.toThrow();
    await expect(FEK.wrapFileKey('short')).rejects.toThrow();
    await expect(FEK.unwrapFileKey({ encryptedKey: 'zz', iv: 'x', mac: 'y', createdAt: '' })).rejects.toThrow();

    await SecureCryptoService.setupMasterKey(PASS);
    const fk = await FEK.generateFileKey();
    const wrapped = await FEK.wrapFileKey(fk);
    expect(await FEK.unwrapFileKey(wrapped)).toBe(fk);
  });
});

describe('Argon2id service hardening', () => {
  const salt = new Uint8Array(16).fill(5).buffer;

  test('NFC and NFD forms of a passphrase derive the same key', async () => {
    const nfc = 'café';
    const nfd = 'café';
    const a = Buffer.from(await Argon2idService.deriveKey(nfc, salt, DEFAULT_ARGON2_PARAMS)).toString('hex');
    const b = Buffer.from(await Argon2idService.deriveKey(nfd, salt, DEFAULT_ARGON2_PARAMS)).toString('hex');
    expect(a).toBe(b);
  });

  test('absurd or malformed parameters and salts are rejected', async () => {
    await expect(Argon2idService.deriveKey('p', salt, { ...DEFAULT_ARGON2_PARAMS, memoryKB: 1 << 30 })).rejects.toThrow();
    await expect(Argon2idService.deriveKey('p', salt, { ...DEFAULT_ARGON2_PARAMS, iterations: 0 })).rejects.toThrow();
    await expect(Argon2idService.deriveKey('p', salt, { ...DEFAULT_ARGON2_PARAMS, iterations: 1e9 })).rejects.toThrow();
    await expect(Argon2idService.deriveKey('p', salt, { ...DEFAULT_ARGON2_PARAMS, type: 0 as any })).rejects.toThrow();
    await expect(Argon2idService.deriveKey('p', new ArrayBuffer(4), DEFAULT_ARGON2_PARAMS)).rejects.toThrow();
  });

  test('the native path refuses parameters below the cost floor and wrong output length', async () => {
    const argon2id = jest.fn(async () => Buffer.alloc(32, 1).toString('base64'));
    rn.NativeModules.RNFileVault = { argon2id };
    (global as any).__argon2_native_available = true;
    try {
      await expect(
        Argon2idService.deriveKey('p', salt, { ...DEFAULT_ARGON2_PARAMS, memoryKB: 1024, iterations: 1 })
      ).rejects.toThrow();
      expect(argon2id).not.toHaveBeenCalled();
      await expect(Argon2idService.deriveKey('p', salt, DEFAULT_ARGON2_PARAMS)).resolves.toBeDefined();
      expect(argon2id).toHaveBeenCalledTimes(1);
      argon2id.mockImplementationOnce(async () => Buffer.alloc(8, 1).toString('base64'));
      await expect(Argon2idService.deriveKey('p', salt, DEFAULT_ARGON2_PARAMS)).rejects.toThrow();
    } finally {
      delete (global as any).__argon2_native_available;
    }
  });

  test('the broken verify() helper (salt = hash) no longer exists', () => {
    expect((Argon2idService as any).verify).toBeUndefined();
  });
});

describe('RNFileVault bridge input validation', () => {
  test('encrypt/decrypt reject wrong key, nonce and tag sizes before calling native', async () => {
    const encrypt = jest.fn(async () => ({ encrypted: '', tag: '' }));
    const decrypt = jest.fn(async () => '');
    rn.NativeModules.RNFileVault = { encrypt, decrypt };
    const nonce = '00'.repeat(24);
    await expect(RNFileVault.encrypt('AA==', 'ab'.repeat(16), nonce)).rejects.toThrow();
    await expect(RNFileVault.encrypt('AA==', KEY, '00'.repeat(12))).rejects.toThrow();
    await expect(RNFileVault.encrypt('AA==', KEY, nonce, 'zz')).rejects.toThrow();
    await expect(RNFileVault.decrypt('abc', nonce, '00'.repeat(16), KEY)).rejects.toThrow();
    await expect(RNFileVault.decrypt('abcd', nonce, '00'.repeat(8), KEY)).rejects.toThrow();
    expect(encrypt).not.toHaveBeenCalled();
    expect(decrypt).not.toHaveBeenCalled();
    await expect(RNFileVault.encrypt('AA==', KEY, nonce, '01')).resolves.toBeDefined();
  });

  test('generateRandomBytes verifies bounds and returned length', async () => {
    rn.NativeModules.RNFileVault = { generateRandomBytes: jest.fn(async () => Buffer.alloc(16).toString('base64')) };
    await expect(RNFileVault.generateRandomBytes(0)).rejects.toThrow();
    await expect(RNFileVault.generateRandomBytes(1 << 20)).rejects.toThrow();
    await expect(RNFileVault.generateRandomBytes(32)).rejects.toThrow();
    await expect(RNFileVault.generateRandomBytes(16)).resolves.toBeDefined();
  });

  test('a missing native module is a clear error, not a TypeError on undefined', async () => {
    await expect(RNFileVault.generateRandomBytes(16)).rejects.toThrow('not available');
  });

  test('argon2id bridge rejects out-of-range parameters', async () => {
    rn.NativeModules.RNFileVault = { argon2id: jest.fn(async () => '') };
    await expect(RNFileVault.argon2id('p', 'AAAA', 0, 65536, 32)).rejects.toThrow();
    await expect(RNFileVault.argon2id('p', 'AAAA', 3, 65536, 4)).rejects.toThrow();
    await expect(RNFileVault.argon2id('p', 'AAAA', 3, 65536, 32)).resolves.toBe('');
  });
});
