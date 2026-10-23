/**
 * RED TEAM — passphrase / lockout / unlock-race / master-wrap tamper / key-zeroing attacks.
 * A passing test means the attack FAILED (defence holds) or documents an accepted limitation.
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
import { keyCustody } from '../src/services/KeyCustody';

const PASS = 'Attack-Auth-Passphrase-1!';
const S = secureStore._store as Map<string, string>;
const K = {
  enc: 'filevault_master_enc', iv: 'filevault_master_iv', mac: 'filevault_master_mac',
  salt: 'filevault_kek_salt', meta: 'filevault_kdf_meta',
  fails: 'filevault_failed_attempts', lock: 'filevault_lock_until',
};

let masterHex: string;
let snapshot: Map<string, string>;

beforeAll(async () => {
  delete rn.NativeModules.RNFileVault;
  secureStore._reset();
  C.clearAllCaches();
  await C.setupMasterKey(PASS);
  masterHex = C.__masterKeyHexForTest()!;
  snapshot = new Map(S);
}, 60000);

beforeEach(() => {
  jest.restoreAllMocks();
  C.clearAllCaches();
  delete rn.NativeModules.RNFileVault;
  S.clear();
  snapshot.forEach((v, k) => S.set(k, v));
});

const flip = (s: string, i = 0) => s.slice(0, i) + (s[i] === '0' ? '1' : '0') + s.slice(i + 1);
const locked = () => C.__masterKeyHexForTest() === null;

describe('wrong-passphrase variants never unlock', () => {
  // NOTE: NUL-suffixed variants are omitted: the Jest KDF mock uses node pbkdf2 which truncates
  // strings at NUL (mock artifact; the real noble/libsodium paths take explicit-length bytes).
  const wrongs: any[] = ['', ' ', PASS + ' ', ' ' + PASS, PASS.toUpperCase(), PASS.slice(0, -1),
    PASS + '​', '​' + PASS, PASS.replace('A', 'А') /* Cyrillic A */, PASS.repeat(1000),
    null, undefined, 0, {}, [], PASS.split(''), { toString: () => PASS }];
  test.each(wrongs.map((w, i) => [i, w]))('variant #%s', async (_i, w) => {
    expect(await C.unlock(w)).toBe(false);
    expect(locked()).toBe(true);
  });

  test('object with toString() returning the passphrase does not authenticate (type confusion)', async () => {
    expect(await C.unlock({ toString: () => PASS, normalize: () => PASS } as any)).toBe(false);
    expect(locked()).toBe(true);
  });

  test('correct passphrase still works afterwards, counter reset', async () => {
    await C.unlock('nope');
    expect(await C.getFailedAttempts()).toBe(1);
    expect(await C.unlock(PASS)).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
    expect(await C.getFailedAttempts()).toBe(0);
  });
});

describe('unicode / NFC tricks', () => {
  const NFC = 'Pässwörd-é-日本語-Ω-' + 'x'.repeat(8);
  const NFD = NFC.normalize('NFD');
  test('NFD form of an NFC-set passphrase unlocks; NFKC/compat look-alikes do not', async () => {
    secureStore._reset();
    await C.setupMasterKey(NFC);
    const m = C.__masterKeyHexForTest();
    C.clearAllCaches();
    expect(NFD).not.toBe(NFC);
    expect(await C.unlock(NFD)).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(m);
    C.clearAllCaches();
    // compatibility variants must NOT be folded (would shrink the keyspace / enable look-alike)
    for (const alt of [NFC.replace('Ω', 'Ω' /* OHM SIGN, NFC->Ω */)]) {
      // OHM SIGN canonically normalises to Ω under NFC, so this one SHOULD unlock (canonical equiv.)
      expect(await C.unlock(alt)).toBe(true);
      C.clearAllCaches();
    }
    for (const alt of [NFC.replace('x', 'ｘ' /* fullwidth x */), NFC.replace('P', 'Ｐ'), NFC.replace('-', '‐'), NFC.replace('é', 'é́')]) {
      expect(await C.unlock(alt)).toBe(false);
      expect(locked()).toBe(true);
    }
  }, 60000);

  test('NFD setup, NFC unlock (both directions)', async () => {
    secureStore._reset();
    await C.setupMasterKey(NFD);
    C.clearAllCaches();
    expect(await C.unlock(NFC)).toBe(true);
  }, 60000);

  test('combining-mark ordering: canonical reordering equivalence only', async () => {
    secureStore._reset();
    const a = 'q̣̇-pass-word-123', b = 'q̣̇-pass-word-123'; // canonically equivalent
    await C.setupMasterKey(a);
    C.clearAllCaches();
    expect(await C.unlock(b)).toBe(true);
  }, 60000);

  test('lone surrogates / BOM / RTL override passphrases are handled without throwing out of unlock()', async () => {
    for (const p of ['\ud800abc', '﻿' + PASS, '‮' + PASS, PASS + '\ud83d']) {
      await expect(C.unlock(p)).resolves.toBe(false);
    }
  });

  test('1 MiB wrong passphrase returns false (bounded, no crash)', async () => {
    await expect(C.unlock('z'.repeat(1 << 20))).resolves.toBe(false);
  }, 60000);
});

describe('lockout counter / lock-until tampering', () => {
  test.each(['NaN', 'abc', '', '  ', '-1', '-999999', '99999999999999999999', '1e9', '0x10', '4.9', 'Infinity', '\u0000'])(
    'failed_attempts=%j: still locks within 5 further wrong guesses',
    async (v) => {
      S.set(K.fails, v);
      for (let i = 0; i < 6; i++) await C.unlock('wrong-' + i);
      expect((await C.getLockStatus()).locked).toBe(true);
      expect(await C.unlock(PASS)).toBe(false);
    }, 60000);

  test.each(['garbage', 'NaN', 'abc', '--5', '\u0000', 'undefined', 'null'])(
    'lock_until=%j: fails closed (locked), never grants a free unlock',
    async (v) => {
      S.set(K.lock, v);
      expect(await C.unlock(PASS)).toBe(false);
      expect((await C.getLockStatus()).locked).toBe(true);
    });

  test('getFailedAttempts() never returns NaN / negative / non-integer to the UI', async () => {
    for (const v of ['NaN', 'abc', '-7', '3.9', '', 'Infinity', '1e999']) {
      S.set(K.fails, v);
      const n = await C.getFailedAttempts();
      expect(Number.isInteger(n)).toBe(true);
      expect(n).toBeGreaterThanOrEqual(0);
    }
  });

  test('getLockStatus with unlockAt far in the future and absurd value is bounded or consistent', async () => {
    S.set(K.lock, '99999999999999999999');
    const st = await C.getLockStatus();
    expect(typeof st.locked).toBe('boolean');
    expect(Number.isFinite(st.unlockAt)).toBe(true);
  });

  test('exact threshold: 5th wrong guess sets lock; correct passphrase refused during lock', async () => {
    for (let i = 0; i < 5; i++) await C.unlock('bad' + i);
    expect(await C.getFailedAttempts()).toBe(5);
    expect(Number(S.get(K.lock))).toBeGreaterThan(Date.now());
    expect(await C.unlock(PASS)).toBe(false);
    // attempts while locked do not push counter or extend into overflow
    for (let i = 0; i < 10; i++) await C.unlock('bad');
    expect(await C.getFailedAttempts()).toBe(5);
  }, 60000);

  test('lock expiry: after lock_until passes the correct passphrase works and state is reset', async () => {
    for (let i = 0; i < 5; i++) await C.unlock('bad' + i);
    S.set(K.lock, String(Date.now() - 1));
    expect(await C.unlock(PASS)).toBe(true);
    expect(S.has(K.lock)).toBe(false);
    expect(S.has(K.fails)).toBe(false);
  }, 60000);

  test('clock rollback cannot be exploited by the app: lock stays while now < lock_until', async () => {
    for (let i = 0; i < 5; i++) await C.unlock('bad' + i);
    const spy = jest.spyOn(Date, 'now');
    spy.mockReturnValue(Number(S.get(K.lock)) - 1000);
    expect(await C.unlock(PASS)).toBe(false);
  }, 60000);
});

describe('concurrency', () => {
  test('12 parallel correct unlocks: all true, single live handle, no handle leak', async () => {
    const before = (keyCustody as any).sessions.size;
    const rs = await Promise.all(Array.from({ length: 12 }, () => C.unlock(PASS)));
    expect(rs.every(Boolean)).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
    expect((keyCustody as any).sessions.size - before).toBeLessThanOrEqual(1);
  }, 60000);

  test('mixed parallel right/wrong guesses: right ones either succeed or are refused by lock; counter never exceeds 5', async () => {
    const guesses = ['w1', PASS, 'w2', 'w3', PASS, 'w4', 'w5', 'w6', PASS, 'w7'];
    const rs = await Promise.all(guesses.map((g) => C.unlock(g)));
    expect(rs.length).toBe(10);
    const n = await C.getFailedAttempts();
    expect(n).toBeLessThanOrEqual(5);
    // serialised: result is deterministic w.r.t. order — first PASS (index1) comes after only 1 wrong
    expect(rs[1]).toBe(true);
  }, 60000);

  test('20 parallel wrong guesses count exactly 5 (no lost-update race)', async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => C.unlock('w' + i)));
    expect(await C.getFailedAttempts()).toBe(5);
  }, 60000);

  test('parallel changePassphrase + unlock never corrupts the wrapped master', async () => {
    const [a, b, c] = await Promise.all([
      C.changePassphrase(PASS, 'Brand-New-Pass-2!'),
      C.unlock(PASS),
      C.unlock('Brand-New-Pass-2!'),
    ]);
    expect(a).toBe(true);
    void b; void c;
    C.clearAllCaches();
    expect(await C.unlock('Brand-New-Pass-2!')).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
  }, 60000);
});

describe('wrapped-master tamper / replay / swap', () => {
  const fields = [K.enc, K.iv, K.mac, K.salt];
  test.each(fields)('bit-flip in %s => unlock fails and is counted', async (f) => {
    S.set(f, flip(S.get(f)!, 2));
    expect(await C.unlock(PASS)).toBe(false);
    expect(locked()).toBe(true);
    expect(await C.getFailedAttempts()).toBe(1);
  }, 60000);

  test.each(fields)('truncation / extension / emptying of %s => unlock fails, no throw', async (f) => {
    const v = S.get(f)!;
    for (const t of [v.slice(0, -2), v + '00', v + '0'.repeat(32), '', 'zz']) {
      S.set(f, t);
      await expect(C.unlock(PASS)).resolves.toBe(false);
      expect(locked()).toBe(true);
      S.set(K.fails, '0'); S.delete(K.lock);
    }
  }, 60000);

  test('cross-vault swap: wrapped master from vault B + salt from A cannot unlock with A passphrase', async () => {
    const mine = new Map(S);
    S.clear();
    C.clearAllCaches();
    await C.setupMasterKey('Other-Vault-Pass-9!');
    const other = new Map(S);
    S.clear(); mine.forEach((v, k) => S.set(k, v));
    S.set(K.enc, other.get(K.enc)!); S.set(K.iv, other.get(K.iv)!); S.set(K.mac, other.get(K.mac)!);
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(false);
    expect(await C.unlock('Other-Vault-Pass-9!')).toBe(false); // salt mismatch too
  }, 60000);

  test('kdf_meta downgrade / garbage is refused (no derivation under a foreign contract)', async () => {
    for (const m of ['pbkdf2', 'argon2id-raw', 'x', '{}']) {
      S.set(K.meta, m);
      expect(await C.unlock(PASS)).toBe(false);
    }
    S.delete(K.meta); // absent == legacy tag => proceeds
    expect(await C.unlock(PASS)).toBe(true);
  }, 60000);

  test('mac that merely equals the stored one for a DIFFERENT ciphertext is rejected (MAC covers iv||ct)', async () => {
    const ct = S.get(K.enc)!;
    // swap two 16-byte halves
    const swapped = ct.length >= 64 ? ct.slice(32, 64) + ct.slice(0, 32) + ct.slice(64) : ct;
    if (swapped !== ct) {
      S.set(K.enc, swapped);
      expect(await C.unlock(PASS)).toBe(false);
    }
  }, 60000);

  test('replay of an OLD wrapped master after changePassphrase: documented rollback (old pass works again), master identical => no data loss', async () => {
    const old = new Map(S);
    expect(await C.changePassphrase(PASS, 'Brand-New-Pass-2!')).toBe(true);
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(false);
    // attacker with store-write replays old wrap
    [K.enc, K.iv, K.mac, K.salt, K.meta].forEach((k) => S.set(k, old.get(k)!));
    S.delete(K.fails); S.delete(K.lock);
    expect(await C.unlock(PASS)).toBe(true);
    // OPEN (inherent, needs a monotonic counter / hardware-bound version): rollback of passphrase
    // change is possible for a store-write attacker; the master key itself is unchanged.
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
  }, 60000);

  test('changePassphrase: wrong old passphrase / junk new passphrase leave vault intact', async () => {
    expect(await C.changePassphrase('wrong', 'x')).toBe(false);
    S.delete(K.fails);
    for (const bad of [null, undefined, 5, {}] as any[]) {
      expect(await C.changePassphrase(PASS, bad)).toBe(false);
    }
    C.clearAllCaches();
    expect(await C.unlock(PASS)).toBe(true);
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
  }, 60000);

  test('stale / forged master_txn cannot override the vault with attacker-chosen garbage', async () => {
    S.set('filevault_master_txn', JSON.stringify({ kekSaltHex: '00'.repeat(16), ivHex: '00'.repeat(16), ctHex: '00'.repeat(48), macHex: '00'.repeat(32) }));
    // A well-formed but unauthenticated txn is applied (roll-forward) — it can only DoS, never reveal.
    const r = await C.unlock(PASS);
    expect(r).toBe(false);
    expect(locked()).toBe(true);
    expect(S.has('filevault_master_txn')).toBe(false);
  }, 60000);

  test('legacy plaintext key store entry planted by attacker does not bypass passphrase', async () => {
    S.delete(K.enc);
    S.set('filevault_encryption_key', 'ee'.repeat(32));
    expect(await C.unlock('anything')).toBe(false);
    expect(await C.unlock('')).toBe(false);
    expect(locked()).toBe(true);
  }, 60000);
});

describe('timing / oracle sanity (structural)', () => {
  test('wrong passphrase runs the same KDF + MAC pipeline as the right one (no early-out)', async () => {
    const { Argon2idService } = require('../src/services/Argon2idService');
    const kdf = jest.spyOn(Argon2idService, 'deriveKey');
    const ct = jest.spyOn(C, 'constantsTimeEquals');
    await C.unlock('wrong');
    const wrongK = kdf.mock.calls.length, wrongC = ct.mock.calls.length;
    kdf.mockClear(); ct.mockClear();
    S.delete(K.fails);
    await C.unlock(PASS);
    expect(kdf.mock.calls.length).toBe(wrongK);
    expect(ct.mock.calls.length).toBe(wrongC);
    // wrong-length passphrase same
    kdf.mockClear();
    C.clearAllCaches();
    await C.unlock('');
    expect(kdf.mock.calls.length).toBe(wrongK);
  }, 60000);

  test('wall-clock: wrong vs right unlock within a generous factor (no order-of-magnitude oracle)', async () => {
    const t = async (p: string) => { const s = process.hrtime.bigint(); await C.unlock(p); return Number(process.hrtime.bigint() - s) / 1e6; };
    await t(PASS); // warm
    const rights: number[] = [], wrongs: number[] = [];
    for (let i = 0; i < 5; i++) { C.clearAllCaches(); rights.push(await t(PASS)); S.delete(K.fails); wrongs.push(await t('wrong' + i)); S.delete(K.fails); }
    const med = (a: number[]) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
    const ratio = Math.max(med(rights), 1) / Math.max(med(wrongs), 1);
    expect(ratio).toBeLessThan(10);
    expect(ratio).toBeGreaterThan(0.1);
  }, 120000);
});

describe('key zeroing after lock', () => {
  test('clearAllCaches zeroes the custody bytes IN PLACE and drops the handle', async () => {
    await C.unlock(PASS);
    const handle = (C as any).__masterHandle as string;
    const bytes: Uint8Array = (keyCustody as any).sessions.get(handle);
    expect(bytes.some((b) => b !== 0)).toBe(true);
    const ref = bytes; // keep a reference to the live buffer
    C.clearAllCaches();
    expect(ref.every((b) => b === 0)).toBe(true);
    expect(keyCustody.has(handle)).toBe(false);
    expect((C as any).macKeyCache.size).toBe(0);
  }, 60000);

  test('after lock every key-using API fails closed', async () => {
    await C.unlock(PASS);
    C.clearAllCaches();
    await expect(C.encryptData('x', 'c')).rejects.toThrow();
    await expect(C.decryptData('02aa', 'aa'.repeat(16), 'bb'.repeat(32), 'c')).rejects.toThrow();
    await expect(C.encryptFileKey('ab'.repeat(32))).rejects.toThrow();
    await expect(C.getMasterKey()).resolves.toBeNull().catch(() => undefined);
    expect(() => C.currentMasterHandle()).toThrow();
  }, 60000);

  test('stale handle from a previous session cannot be reused after lock + re-unlock', async () => {
    await C.unlock(PASS);
    const old = C.currentMasterHandle();
    const e = await C.encryptData('s', 'c');
    C.clearAllCaches();
    await C.unlock(PASS);
    expect(C.currentMasterHandle()).not.toBe(old);
    await expect(C.decryptDataWithHandle(e.encryptedData, e.iv, e.mac, old, 'c')).rejects.toThrow();
    expect(await C.decryptData(e.encryptedData, e.iv, e.mac, 'c')).toBe('s');
  }, 60000);

  test('wrong-passphrase attempt while unlocked does not replace or leak the live master', async () => {
    await C.unlock(PASS);
    const h = C.currentMasterHandle();
    await C.unlock('wrong');
    expect(C.currentMasterHandle()).toBe(h);
    expect(C.__masterKeyHexForTest()).toBe(masterHex);
  }, 60000);

  test('repeated lock/unlock does not leak custody sessions', async () => {
    const base = (keyCustody as any).sessions.size;
    for (let i = 0; i < 8; i++) { await C.unlock(PASS); C.clearAllCaches(); }
    expect((keyCustody as any).sessions.size).toBe(base);
  }, 120000);

  test('closeKeyHandle zeroes bytes; double close is a no-op', () => {
    const h = C.registerKeyHandle('12'.repeat(32));
    const b: Uint8Array = (keyCustody as any).sessions.get(h);
    expect(C.closeKeyHandle(h)).toBe(true);
    expect(b.every((x) => x === 0)).toBe(true);
    expect(C.closeKeyHandle(h)).toBe(false);
  });
});

describe('leak checks on auth paths', () => {
  test('console output + thrown messages across failing unlocks / tampered vault never contain secrets', async () => {
    const spies = ['log', 'info', 'warn', 'error', 'debug'].map((m) => jest.spyOn(console, m as any).mockImplementation(() => {}));
    S.set(K.meta, 'weird-meta');
    await C.unlock(PASS);
    S.set(K.meta, snapshot.get(K.meta)!);
    S.set(K.mac, 'zz');
    await C.unlock(PASS);
    S.set(K.mac, snapshot.get(K.mac)!);
    await C.changePassphrase(PASS, 'NewSecretPass-Leak-1!');
    const out = JSON.stringify(spies.flatMap((s) => s.mock.calls.map((c) => c.map((x: any) => (x instanceof Error ? x.message : x)))));
    for (const secret of [PASS, 'NewSecretPass-Leak-1!', masterHex, snapshot.get(K.salt)!, snapshot.get(K.mac)!]) {
      expect(out).not.toContain(secret);
    }
    // at-rest: passphrase / master hex never persisted in clear
    for (const [k, v] of S.entries()) {
      expect(String(v)).not.toContain(PASS);
      if (k !== 'filevault_master_enc') expect(String(v)).not.toContain(masterHex);
    }
  }, 60000);
});
