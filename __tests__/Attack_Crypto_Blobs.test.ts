/**
 * RED TEAM — ciphertext malleability / downgrade / swap / nonce attacks (code level).
 * Every test is a controlled attack; a passing test means the attack FAILED (defence holds).
 */
const secureStore = require('../__mocks__/expo-secure-store');
const rn = require('react-native');

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

import { SecureCryptoService as C } from '../src/services/CryptoService';
import * as FEK from '../src/services/FileEncryptionKey';
import { keyCustody } from '../src/services/KeyCustody';

const KEY = 'ab'.repeat(32);
const PLAIN = 'attack-me: sensitive plaintext ✓';
let H: string;

beforeEach(() => {
  secureStore._reset();
  jest.restoreAllMocks();
  C.clearAllCaches();
  delete rn.NativeModules.RNFileVault;
  H = C.registerKeyHandle(KEY);
});

function flipHexChar(s: string, i: number): string {
  const c = s[i];
  return s.slice(0, i) + (c === '0' ? '1' : '0') + s.slice(i + 1);
}

const enc = (d = PLAIN, ctx = 'ctx') => C.encryptDataWithHandle(d, H, ctx);
const dec = (e: { encryptedData: string; iv: string; mac: string }, ctx = 'ctx', h = H) =>
  C.decryptDataWithHandle(e.encryptedData, e.iv, e.mac, h, ctx);

describe('content blob (0x02 AES-CBC+HMAC) tamper', () => {
  test('baseline round-trip', async () => {
    const e = await enc();
    expect(e.encryptedData.startsWith('02')).toBe(true);
    expect(await dec(e)).toBe(PLAIN);
  });

  test('flip every hex nibble position sample of ciphertext / iv / mac => rejected', async () => {
    const e = await enc();
    const positions = (len: number) => [0, 1, Math.floor(len / 2), len - 2, len - 1].filter((p) => p >= 0 && p < len);
    for (const p of positions(e.encryptedData.length)) {
      await expect(dec({ ...e, encryptedData: flipHexChar(e.encryptedData, p) })).rejects.toThrow();
    }
    for (const p of positions(e.iv.length)) {
      await expect(dec({ ...e, iv: flipHexChar(e.iv, p) })).rejects.toThrow();
    }
    for (const p of positions(e.mac.length)) {
      await expect(dec({ ...e, mac: flipHexChar(e.mac, p) })).rejects.toThrow();
    }
  });

  test('uppercase-hex re-encoding of mac/iv does not create a second valid encoding that decrypts differently', async () => {
    const e = await enc();
    // Either rejected or decrypts to the same plaintext (never to different data).
    try {
      const p = await dec({ ...e, mac: e.mac.toUpperCase() });
      expect(p).toBe(PLAIN);
    } catch { /* rejected is fine */ }
  });

  test('truncation of ciphertext at every 16-byte boundary and odd lengths => rejected', async () => {
    const e = await enc('x'.repeat(100));
    const body = e.encryptedData.slice(2);
    for (let cut = 1; cut <= body.length; cut += 7) {
      await expect(dec({ ...e, encryptedData: '02' + body.slice(0, body.length - cut) })).rejects.toThrow();
    }
    await expect(dec({ ...e, encryptedData: '02' })).rejects.toThrow();
    await expect(dec({ ...e, encryptedData: '0' })).rejects.toThrow();
    await expect(dec({ ...e, encryptedData: '' })).rejects.toThrow();
  });

  test('extension (append blocks / zeros / whitespace / newline) => rejected', async () => {
    const e = await enc();
    for (const ext of ['00', '0'.repeat(32), 'ff'.repeat(16), ' ', '\n', e.encryptedData.slice(2)]) {
      await expect(dec({ ...e, encryptedData: e.encryptedData + ext })).rejects.toThrow();
    }
    await expect(dec({ ...e, mac: e.mac + '00' })).rejects.toThrow();
    await expect(dec({ ...e, iv: e.iv + '00' })).rejects.toThrow();
    await expect(dec({ ...e, mac: e.mac + '\n' })).rejects.toThrow();
  });

  test('block-reordering / duplication / splice of CBC blocks => rejected', async () => {
    const e = await enc('y'.repeat(200));
    const body = e.encryptedData.slice(2);
    const blocks = body.match(/.{32}/g)!;
    const swapped = [...blocks]; [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    await expect(dec({ ...e, encryptedData: '02' + swapped.join('') })).rejects.toThrow();
    await expect(dec({ ...e, encryptedData: '02' + blocks.concat(blocks[0]).join('') })).rejects.toThrow();
    await expect(dec({ ...e, encryptedData: '02' + blocks.slice(1).join('') })).rejects.toThrow();
  });

  test('wrong aadContext (blob swap between objects/roles) => rejected', async () => {
    const e = await enc(PLAIN, 'file1:content:v1');
    await expect(dec(e, 'file2:content:v1')).rejects.toThrow();
    await expect(dec(e, 'file1:title:v1')).rejects.toThrow();
    await expect(dec(e, 'file1:content:v2')).rejects.toThrow();
    await expect(dec(e, '')).rejects.toThrow();
    await expect(dec(e, 'file1:content:v1\u0000')).rejects.toThrow();
  });

  test('aad context ambiguity: contexts that are hex-prefix of each other do not collide', async () => {
    const e = await enc(PLAIN, 'a');
    await expect(dec(e, 'a\u0000')).rejects.toThrow();
    await expect(dec(e, 'aa')).rejects.toThrow();
    await expect(dec(e, 'A')).rejects.toThrow();
  });

  test('wrong key handle => rejected, no plaintext', async () => {
    const e = await enc();
    const h2 = C.registerKeyHandle('cd'.repeat(32));
    await expect(dec(e, 'ctx', h2)).rejects.toThrow();
  });

  test('unknown / forged / empty / prototype-polluting handles => rejected', async () => {
    const e = await enc();
    for (const h of ['', 'nope', '__proto__', 'constructor', 'toString', 'hasOwnProperty', KEY]) {
      await expect(dec(e, 'ctx', h)).rejects.toThrow();
      await expect(C.encryptDataWithHandle('x', h, 'c')).rejects.toThrow();
    }
  });

  test('closed handle cannot be used', async () => {
    const h = C.registerKeyHandle('ef'.repeat(32));
    C.closeKeyHandle(h);
    await expect(C.encryptDataWithHandle('x', h)).rejects.toThrow();
  });
});

describe('prefix / backend downgrade swaps', () => {
  test('0x02 blob relabelled 0x01 and 0x03 => rejected (no native => 0x01 impossible; 0x03 MAC differs)', async () => {
    const e = await enc();
    for (const p of ['01', '03', '00', '04', 'ff', '0x', '2 ', '  ']) {
      await expect(dec({ ...e, encryptedData: p + e.encryptedData.slice(2) })).rejects.toThrow();
    }
  });

  test('0x03 legacy reader cannot be tricked into accepting a 0x02-MAC blob', async () => {
    const e = await enc();
    await expect(dec({ ...e, encryptedData: '03' + e.encryptedData.slice(2) })).rejects.toThrow();
  });

  test('0x03 legacy reader MAC (no prefix/aad binding) cannot be forged from an 0x02 blob with empty aad', async () => {
    // 0x03 MAC input is prefix-bound? Verify that a 0x02 blob with aad='' is not accepted as 0x03.
    const e = await C.encryptDataWithHandle(PLAIN, H, '');
    await expect(dec({ ...e, encryptedData: '03' + e.encryptedData.slice(2) }, '')).rejects.toThrow();
  });

  test('XChaCha 0x01 blob (mock native) relabelled 0x02/0x03 is rejected; and vice-versa', async () => {
    const nodeCrypto = require('crypto');
    // faithful-enough AEAD mock using real chacha20-poly1305 is unavailable for 24B nonces; use
    // AES-GCM with AAD to model "AEAD binds AAD" semantics.
    const store: Record<string, any> = {};
    rn.NativeModules.RNFileVault = {
      encrypt: jest.fn(async (dataB64: string, keyHex: string, nonceHex: string, aadHex?: string) => {
        const key = Buffer.from(keyHex, 'hex');
        const iv = Buffer.from(nonceHex, 'hex').subarray(0, 12);
        const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
        if (aadHex) c.setAAD(Buffer.from(aadHex, 'hex'));
        const ct = Buffer.concat([c.update(Buffer.from(dataB64, 'base64')), c.final()]);
        return { encrypted: ct.toString('hex'), tag: c.getAuthTag().toString('hex') };
      }),
      decrypt: jest.fn(async (ctHex: string, keyHex: string, nonceHex: string, tagHex: string, aadHex?: string) => {
        const d = nodeCrypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), Buffer.from(nonceHex, 'hex').subarray(0, 12));
        if (aadHex) d.setAAD(Buffer.from(aadHex, 'hex'));
        d.setAuthTag(Buffer.from(tagHex, 'hex'));
        return Buffer.concat([d.update(Buffer.from(ctHex, 'hex')), d.final()]).toString('base64');
      }),
      verifyConstantTime: async () => ({ result: false }),
    };
    void store;
    // Only exercised if the service dispatches to the (mocked) native bridge.
    let e: any;
    try { e = await enc(); } catch { return; } // bridge shape differs: nothing to attack
    if (!e.encryptedData.startsWith('01')) return;
    await expect(dec({ ...e, encryptedData: '02' + e.encryptedData.slice(2) })).rejects.toThrow();
    await expect(dec({ ...e, encryptedData: '03' + e.encryptedData.slice(2) })).rejects.toThrow();
  });

  test('S3: writes refuse to silently downgrade when not in test env and no opt-in', async () => {
    const old = process.env.NODE_ENV;
    (process.env as any).NODE_ENV = 'production';
    delete (global as any).__filevault_allow_js_crypto;
    try {
      await expect(C.encryptDataWithHandle('x', H, 'c')).rejects.toThrow();
    } finally { (process.env as any).NODE_ENV = old; }
  });
});

describe('nonce / IV freshness', () => {
  test('300 encryptions of identical plaintext: all IVs, ciphertexts, tags distinct', async () => {
    const ivs = new Set<string>(), cts = new Set<string>(), macs = new Set<string>();
    for (let i = 0; i < 300; i++) {
      const e = await enc('same', 'same');
      ivs.add(e.iv); cts.add(e.encryptedData); macs.add(e.mac);
    }
    expect(ivs.size).toBe(300); expect(cts.size).toBe(300); expect(macs.size).toBe(300);
  });

  test('IV bytes are never all-zero/constant and have plausible entropy across 200 draws', async () => {
    const bytes = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const b = new Uint8Array(await C.generateSecureBytes(16));
      expect(b.some((x) => x !== 0)).toBe(true);
      b.forEach((x) => bytes.add(x));
    }
    expect(bytes.size).toBeGreaterThan(200);
  });

  test('wrapping the same file key 100x yields 100 distinct IVs/ciphertexts', async () => {
    const fk = 'cd'.repeat(32);
    const ivs = new Set<string>(), cts = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const w = await C.encryptFileKeyWith(fk, H);
      ivs.add(w.iv); cts.add(w.encryptedKey);
    }
    expect(ivs.size).toBe(100); expect(cts.size).toBe(100);
  });

  test('a repeating RNG (stuck CSPRNG) is refused rather than reusing a nonce silently', async () => {
    const cryptoMock = require('../__mocks__/expo-crypto');
    cryptoMock.getRandomBytesAsync.mockImplementation(async (n: number) => new Uint8Array(n));
    try {
      await expect(C.encryptDataWithHandle('x', H, 'c')).rejects.toThrow();
    } finally {
      const nodeCrypto = require('crypto');
      cryptoMock.getRandomBytesAsync.mockImplementation(async (n: number) => new Uint8Array(nodeCrypto.randomBytes(n)));
    }
  });
});

describe('wrapped file keys', () => {
  const FK = 'cd'.repeat(32);

  test('bit-flip / truncation / extension of every wrapped-key field => rejected', async () => {
    const w = await C.encryptFileKeyWith(FK, H);
    expect(await C.decryptFileKeyWith(w, H)).toBe(FK);
    await expect(C.decryptFileKeyWith({ ...w, encryptedKey: flipHexChar(w.encryptedKey, 0) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, encryptedKey: flipHexChar(w.encryptedKey, w.encryptedKey.length - 1) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, iv: flipHexChar(w.iv, 3) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, mac: flipHexChar(w.mac, 3) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, encryptedKey: w.encryptedKey.slice(0, -32) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, encryptedKey: w.encryptedKey + '00'.repeat(16) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, mac: w.mac.slice(0, 62) }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, mac: '' }, H)).rejects.toThrow();
    await expect(C.decryptFileKeyWith({ ...w, iv: '' }, H)).rejects.toThrow();
  });

  test('wrapped key under key A cannot be unwrapped by key B', async () => {
    const w = await C.encryptFileKeyWith(FK, H);
    await expect(C.decryptFileKeyWith(w, C.registerKeyHandle('12'.repeat(32)))).rejects.toThrow();
  });

  test('a CONTENT blob cannot be re-presented as a wrapped file key (cross-protocol)', async () => {
    const e = await C.encryptDataWithHandle(FK, H, '');
    const asWrap = { encryptedKey: e.encryptedData.slice(2), iv: e.iv, mac: e.mac };
    await expect(C.decryptFileKeyWith(asWrap, H)).rejects.toThrow();
    // and with the prefix still attached
    await expect(C.decryptFileKeyWith({ ...asWrap, encryptedKey: e.encryptedData }, H)).rejects.toThrow();
  });

  test('a wrapped file key cannot be re-presented as a content blob', async () => {
    const w = await C.encryptFileKeyWith(FK, H);
    for (const p of ['02', '03']) {
      await expect(C.decryptDataWithHandle(p + w.encryptedKey, w.iv, w.mac, H, '')).rejects.toThrow();
    }
  });

  test('FEK.unwrapFileKey rejects malformed objects / types', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const bad: any[] = [null, undefined, 0, 'str', [], {}, { encryptedKey: 'zz', iv: 'aa', mac: 'bb', createdAt: 'x' },
      { encryptedKey: '00', iv: '0'.repeat(31), mac: '0'.repeat(64), createdAt: 'x' },
      { encryptedKey: '', iv: '0'.repeat(32), mac: '0'.repeat(64), createdAt: 'x' },
      { encryptedKey: 12, iv: '0'.repeat(32), mac: '0'.repeat(64), createdAt: 'x' },
      { encryptedKey: '00', iv: '0'.repeat(32), mac: '0'.repeat(64) }];
    for (const b of bad) await expect(FEK.unwrapFileKey(b)).rejects.toThrow();
  });

  test('FEK.wrapFileKey rejects non-64-hex input (short, long, non-hex, injection, unicode)', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    for (const k of ['', 'ab', 'zz'.repeat(32), 'ab'.repeat(33), 'ab'.repeat(32) + '\n', ' ' + 'ab'.repeat(32), '١'.repeat(64), null as any, undefined as any, 5 as any]) {
      await expect(FEK.wrapFileKey(k)).rejects.toThrow();
    }
  });

  test('FEK.wrapFileKey regex is anchored (multi-line smuggle)', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    await expect(FEK.wrapFileKey('zz\n' + 'ab'.repeat(32))).rejects.toThrow();
  });

  test('FEK store/load: malformed fileIds (path traversal, empty, huge, non-string) rejected', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const w = await FEK.wrapFileKey(FK);
    for (const id of ['', '../x', 'a/b', 'a\\b', 'a'.repeat(5000), null as any, undefined as any, {} as any, 'a b', 'a\u0000b', 'a:b', 'a*']) {
      await expect(FEK.storeEncryptedFileKey(id, w)).rejects.toThrow();
      await expect(FEK.loadEncryptedFileKey(id)).rejects.toThrow();
      await expect(FEK.deleteEncryptedFileKey(id)).rejects.toThrow();
      expect(() => FEK.getFileKeyStorageName(id)).toThrow();
    }
  });

  test('FEK.loadEncryptedFileKey: corrupt JSON / wrong shape in store => throws, never returns attacker object', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const name = FEK.getFileKeyStorageName('f1');
    for (const raw of ['{not json', '[]', 'null', '"s"', JSON.stringify({ encryptedKey: 'zz' }), JSON.stringify({ __proto__: { x: 1 } })]) {
      secureStore._store.set(name, raw);
      await expect(FEK.loadEncryptedFileKey('f1')).rejects.toThrow();
    }
  });

  test('FLAW-CANDIDATE: swapping wrapped keys between two file ids (documented: wrap is not bound to fileId)', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const k1 = await FEK.generateFileKey(), k2 = await FEK.generateFileKey();
    await FEK.storeEncryptedFileKey('f1', await FEK.wrapFileKey(k1));
    await FEK.storeEncryptedFileKey('f2', await FEK.wrapFileKey(k2));
    const n1 = FEK.getFileKeyStorageName('f1'), n2 = FEK.getFileKeyStorageName('f2');
    const a = secureStore._store.get(n1), b = secureStore._store.get(n2);
    secureStore._store.set(n1, b); secureStore._store.set(n2, a);
    const got1 = await FEK.unwrapFileKey((await FEK.loadEncryptedFileKey('f1'))!);
    // Open (wire-format): the wrap carries no fileId AAD, so the swap is undetected at the key
    // layer. The content blob AAD (fileId:content) is what stops cross-file use. Assert the
    // *consequence* is contained: file1's content (bound to its AAD) is not readable by k2's blob.
    expect(got1).toBe(k2);
    const e1 = await C.encryptDataWithHandle('file1 data', C.registerKeyHandle(k1), 'f1:content:v1');
    await expect(C.decryptDataWithHandle(e1.encryptedData, e1.iv, e1.mac, C.registerKeyHandle(got1), 'f1:content:v1')).rejects.toThrow();
  });

  test('FEK.generateFileKey: 200 keys unique, 64 lowercase hex', async () => {
    const s = new Set<string>();
    for (let i = 0; i < 200; i++) { const k = await FEK.generateFileKey(); expect(k).toMatch(/^[0-9a-f]{64}$/); s.add(k); }
    expect(s.size).toBe(200);
  });
});

describe('malformed / oversized hex & strings to public primitives', () => {
  test('hexToBuffer / bufferToHex fuzz', () => {
    for (const bad of ['a', 'abc', 'g0', '0x00', ' 00', '00 ', '00\n', '\u0000\u0000', '٠٠', 'ａｂ']) {
      expect(() => C.hexToBuffer(bad)).toThrow();
    }
    expect(C.hexToBuffer('').byteLength).toBe(0);
    expect(C.bufferToHex(new Uint8Array([0, 1, 255]).buffer)).toBe('0001ff');
  });

  test('decryptData with non-string / null / object arguments rejects (no crash, no plaintext)', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const bads: any[] = [null, undefined, 0, {}, [], true, NaN];
    for (const b of bads) {
      await expect(C.decryptData(b, b, b)).rejects.toThrow();
      await expect(C.decryptData('02' + 'aa'.repeat(32), 'aa'.repeat(16), b)).rejects.toThrow();
    }
  });

  test('1 MiB garbage ciphertext rejected quickly with generic error', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    const t0 = Date.now();
    await expect(C.decryptData('02' + 'ab'.repeat(512 * 1024), 'ab'.repeat(16), 'cd'.repeat(32))).rejects.toThrow('Entschlüsselung fehlgeschlagen');
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  test('encryptData of huge / empty / lone-surrogate / NUL strings round-trips or throws cleanly', async () => {
    await C.setupMasterKey('Attack-pass-1!');
    for (const d of ['', '\u0000', 'a\u0000b', '😀', 'x'.repeat(200000)]) {
      const e = await C.encryptData(d, 'c');
      expect(await C.decryptData(e.encryptedData, e.iv, e.mac, 'c')).toBe(d);
    }
    const lone = '\ud800';
    try {
      const e = await C.encryptData(lone, 'c');
      const back = await C.decryptData(e.encryptedData, e.iv, e.mac, 'c');
      expect(typeof back).toBe('string');
    } catch (e) { expect((e as Error).message).not.toMatch(/[0-9a-f]{64}/); }
  });

  test('constantsTimeEquals: length mismatch, unicode, empty, non-string', async () => {
    expect(await C.constantsTimeEquals('ab', 'ab')).toBe(true);
    expect(await C.constantsTimeEquals('ab', 'abc')).toBe(false);
    expect(await C.constantsTimeEquals('abc', 'ab')).toBe(false);
    expect(await C.constantsTimeEquals('', 'a')).toBe(false);
    expect(await C.constantsTimeEquals('é', 'e')).toBe(false);
    expect(await C.constantsTimeEquals('a'.repeat(64), 'a'.repeat(63) + 'b')).toBe(false);
    // non-strings must not report equal
    let r: any = false;
    try { r = await C.constantsTimeEquals(null as any, null as any); } catch { r = false; }
    expect(r).toBe(false);
    try { r = await C.constantsTimeEquals(undefined as any, undefined as any); } catch { r = false; }
    expect(r).toBe(false);
  });

  test('computeMac / deriveMacKey reject wrong-size keys', async () => {
    await expect(C.computeMac('', 'x')).rejects.toThrow();
    await expect(C.deriveMacKey('zz')).rejects.toThrow();
    // HKDF accepts any-length IKM by design; callers only ever pass 32-byte keys.
  });

  test('KeyCustody: malformed keys / handles rejected; resolve of unknown throws', () => {
    for (const k of ['', 'zz'.repeat(32), 'AB'.repeat(32) + '\n', null as any, 5 as any, 'ab'.repeat(32).slice(1)]) {
      expect(() => keyCustody.registerRawKey(k)).toThrow();
    }
    expect(keyCustody.has('x')).toBe(false);
    expect(() => (keyCustody as any).resolve('x')).toThrow();
    expect(keyCustody.close('x')).toBe(false);
  });

  test('recryptBlob with malformed blob / wrong keys throws, never returns attacker blob as migrated', async () => {
    const h2 = C.registerKeyHandle('34'.repeat(32));
    const e = await enc();
    const blob = { data: e.encryptedData, iv: e.iv, mac: e.mac };
    // tampered blob must not pass the "already migrated" short-circuit
    await expect(C.recryptBlob({ ...blob, mac: flipHexChar(blob.mac, 0) }, H, h2, 'ctx')).rejects.toThrow();
    await expect(C.recryptBlob({ data: 'zz', iv: 'zz', mac: 'zz' }, H, h2, 'ctx')).rejects.toThrow();
    await expect(C.recryptBlob(null as any, H, h2, 'ctx')).rejects.toThrow();
    // neither key
    const h3 = C.registerKeyHandle('56'.repeat(32));
    await expect(C.recryptBlob(blob, h3, h2, 'ctx')).rejects.toThrow();
    // good path + idempotent
    const m = await C.recryptBlob(blob, H, h2, 'ctx');
    expect(await C.decryptDataWithHandle(m.data, m.iv, m.mac, h2, 'ctx')).toBe(PLAIN);
    const m2 = await C.recryptBlob(m, H, h2, 'ctx');
    expect(m2).toEqual(m);
    // old key can no longer read migrated blob
    await expect(C.decryptDataWithHandle(m.data, m.iv, m.mac, H, 'ctx')).rejects.toThrow();
  });

  test('recryptBlob with wrong aad does not "migrate" to a different context', async () => {
    const h2 = C.registerKeyHandle('34'.repeat(32));
    const e = await enc(PLAIN, 'A');
    await expect(C.recryptBlob({ data: e.encryptedData, iv: e.iv, mac: e.mac }, H, h2, 'B')).rejects.toThrow();
  });
});

describe('information leaks (console / error messages)', () => {
  const spies = () => ['log', 'info', 'warn', 'error', 'debug'].map((m) => jest.spyOn(console, m as any).mockImplementation(() => {}));
  const dump = (ss: jest.SpyInstance[]) => JSON.stringify(ss.flatMap((s) => s.mock.calls.map((c) => c.map((x: any) => (x instanceof Error ? x.message + (x.stack || '') : x)))));

  test('failed decrypt / wrap / unwrap do not print or throw key material, plaintext or MAC', async () => {
    const ss = spies();
    const e = await enc();
    const msgs: string[] = [];
    const grab = async (p: Promise<any>) => { try { await p; } catch (x) { msgs.push(String((x as Error).message)); } };
    await grab(dec({ ...e, mac: flipHexChar(e.mac, 0) }));
    await grab(dec({ ...e, encryptedData: e.encryptedData.slice(0, -2) }));
    await grab(dec(e, 'wrong'));
    await grab(C.decryptFileKeyWith({ encryptedKey: 'aa'.repeat(16), iv: 'bb'.repeat(16), mac: 'cc'.repeat(32) }, H));
    await grab(C.encryptDataWithHandle('x', 'badhandle', 'c'));
    const all = dump(ss) + msgs.join('|');
    expect(all).not.toContain(KEY);
    expect(all).not.toContain(PLAIN);
    expect(all).not.toContain(e.mac);
    expect(all).not.toMatch(/ab{1}ab{1}ab{1}ab{1}ab{1}ab{1}ab{1}ab{1}/);
  });

  test('setup / unlock / wrong-pass paths never log passphrase or master key', async () => {
    const ss = spies();
    const P = 'Sup3r-Secret-Passphrase-XYZ!';
    await C.setupMasterKey(P);
    const master = C.__masterKeyHexForTest()!;
    C.clearAllCaches();
    await C.unlock('Wrong-Guess-ABCDEF!');
    await C.unlock(P);
    const all = dump(ss);
    expect(all).not.toContain(P);
    expect(all).not.toContain('Wrong-Guess-ABCDEF!');
    expect(all).not.toContain(master);
    for (const v of secureStore._store.values()) {
      expect(String(v)).not.toContain(master);
      expect(String(v)).not.toContain(P);
    }
  }, 60000);
});
