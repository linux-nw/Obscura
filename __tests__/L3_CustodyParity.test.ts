/**
 * L3 Phase 1a — Parity reference vectors (JS side).
 *
 * This is the JS half of the de-risking harness. It runs the REAL production
 * primitives (the exact functions today's vaults are written with) and:
 *   1. asserts internal self-consistency (encrypt -> decrypt round-trips, MAC verifies);
 *   2. emits a vectors file the native/JCA harness (L3ParityHarness.java) re-derives
 *      and compares against, byte for byte.
 *
 * No production code is touched. If the native side diverges by a single byte, that is
 * a real finding: the file-key path cannot move to native custody without a wire-format
 * change (forbidden), so L3-file-key stays honestly Partial.
 *
 * Primitives exercised (all master-key consumers from the Phase 0 map):
 *   - AES-256-CBC/PKCS7  (aesCbcEncryptRaw/Raw)            -> JCA AES/CBC/PKCS5Padding
 *   - HMAC-SHA256        (SecureCryptoService.computeMac)  -> JCA HmacSHA256
 *   - HKDF-SHA256        (hkdfSha256, label filevault-mac-v1) -> RFC5869 over Mac
 *   - Encrypt-then-MAC file-key wrap + master-blob wrap    -> the real "pre-rebuild blob"
 */

const secureStore = require('../__mocks__/expo-secure-store');

import * as fs from 'fs';
import { SecureCryptoService } from '../src/services/CryptoService';
import { aesCbcEncryptRaw, aesCbcDecryptRaw } from '../src/services/AesCbcHmac';
import { hkdfSha256 } from '../src/services/FastPBKDF2';

const OUT =
  process.env.L3_VECTORS_OUT ||
  '/tmp/claude-1000/-mnt-c-Users-linux-Desktop-Coding-Projekte-Obscuraa-FileVault/53f1acbf-4355-4182-bf8d-536d14462dc5/scratchpad/l3_vectors.json';

// Fixed, deterministic test material so the vectors are reproducible and can also be
// hard-coded into the on-device androidTest later.
const KEY = '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f'; // 32 bytes
const IV  = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';                                 // 16 bytes
const utf8B64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

type AesVec = { name: string; keyHex: string; ivHex: string; plainB64: string; ctHex: string; macHex: string; macKeyHex: string };
type HkdfVec = { ikmHex: string; info: string; len: number; outHex: string };
type HmacVec = { name: string; keyHex: string; msgB64: string; outHex: string };
type BlobVec = { name: string; keyHex: string; ivHex: string; plainB64: string; ctHex: string; macHex: string };

const aes: AesVec[] = [];
const hkdf: HkdfVec[] = [];
const hmac: HmacVec[] = [];
const blobs: BlobVec[] = [];

describe('L3 Phase 1a: JS parity reference', () => {
  test('AES-256-CBC/PKCS7 + EtM-MAC at several lengths incl. exact block boundary', async () => {
    const macKeyHex = await SecureCryptoService.deriveMacKey(KEY);
    // 16 = exact block boundary: PKCS7 MUST add a full 16-byte padding block (-> 32 ct bytes).
    // 32, 64 = further exact multiples; 64 is the real file-key plaintext length.
    for (const len of [1, 15, 16, 17, 31, 32, 63, 64]) {
      const plain = Array.from({ length: len }, (_, i) => String.fromCharCode(33 + (i % 90))).join('');
      const ctHex = await aesCbcEncryptRaw(plain, KEY, IV);
      const macHex = await SecureCryptoService.computeMac(macKeyHex, IV + ctHex);
      // self-consistency: the production decrypt path must recover the same bytes
      expect(await aesCbcDecryptRaw(ctHex, KEY, IV)).toBe(plain);
      // block-boundary invariant: ct length (bytes) = ceil((len+1)/16)*16
      const expectedCtBytes = (Math.floor(len / 16) + 1) * 16;
      expect(ctHex.length).toBe(expectedCtBytes * 2);
      aes.push({ name: `len${len}`, keyHex: KEY, ivHex: IV, plainB64: utf8B64(plain), ctHex, macHex, macKeyHex });
    }
  }, 30000);

  test('HKDF-SHA256(filevault-mac-v1) + HMAC-SHA256 vectors', async () => {
    for (const ikm of [KEY, 'a'.repeat(64), 'ff'.repeat(32)]) {
      hkdf.push({ ikmHex: ikm, info: 'filevault-mac-v1', len: 32, outHex: hkdfSha256(ikm, 'filevault-mac-v1', 32) });
    }
    const mk = await SecureCryptoService.deriveMacKey(KEY);
    for (const msg of ['', 'abc', IV + 'deadbeef', 'x'.repeat(200)]) {
      hmac.push({ name: `msg${msg.length}`, keyHex: mk, msgB64: utf8B64(msg), outHex: await SecureCryptoService.computeMac(mk, msg) });
    }
    expect(hkdf[0].outHex).toHaveLength(64);
  });

  test('real pre-rebuild blobs: file-key wrap + master-blob (EtM)', async () => {
    // File-key wrap: exactly what FileManager stores per file (encryptFileKeyWith).
    const fileKey = 'deadbeefcafef00d' + '1122334455667788'.repeat(3); // 64 hex chars
    const wrap = await SecureCryptoService.encryptFileKeyWith(fileKey, KEY);
    expect(await SecureCryptoService.decryptFileKeyWith(wrap, KEY)).toBe(fileKey);
    blobs.push({ name: 'filekey-wrap', keyHex: KEY, ivHex: wrap.iv, plainB64: utf8B64(fileKey), ctHex: wrap.encryptedKey, macHex: wrap.mac });

    // Master-blob: same construction wrapAndStoreMasterKey uses (master wrapped under KEK).
    const kek = '9988776655443322110ffeeddccbbaa00112233445566778899aabbccddeeff0';
    const masterPlain = 'cafebabe00ff'.padEnd(64, '0');
    const mwrap = await SecureCryptoService.encryptFileKeyWith(masterPlain, kek);
    expect(await SecureCryptoService.decryptFileKeyWith(mwrap, kek)).toBe(masterPlain);
    blobs.push({ name: 'master-blob', keyHex: kek, ivHex: mwrap.iv, plainB64: utf8B64(masterPlain), ctHex: mwrap.encryptedKey, macHex: mwrap.mac });
  }, 30000);

  afterAll(() => {
    fs.writeFileSync(OUT, JSON.stringify({ aes, hkdf, hmac, blobs }, null, 2));
    // Flat, pipe-delimited mirror so the plain-JDK harness needs no JSON lib.
    // All fields are hex/base64/label -> no '|' collisions.
    const lines: string[] = [];
    for (const a of aes) lines.push(`AES|${a.name}|${a.keyHex}|${a.ivHex}|${a.plainB64}|${a.ctHex}|${a.macHex}|${a.macKeyHex}`);
    for (const h of hkdf) lines.push(`HKDF|${h.ikmHex}|${h.info}|${h.len}|${h.outHex}`);
    for (const m of hmac) lines.push(`HMAC|${m.name}|${m.keyHex}|${m.msgB64}|${m.outHex}`);
    for (const b of blobs) lines.push(`BLOB|${b.name}|${b.keyHex}|${b.ivHex}|${b.plainB64}|${b.ctHex}|${b.macHex}`);
    fs.writeFileSync(OUT.replace(/\.json$/, '.txt'), lines.join('\n') + '\n');
    // eslint-disable-next-line no-console
    console.log(`[L3-parity] wrote ${aes.length + hkdf.length + hmac.length + blobs.length} vectors -> ${OUT}`);
  });
});
