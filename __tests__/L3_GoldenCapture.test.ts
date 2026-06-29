/**
 * L3 Phase 2 — golden capture (BEFORE the rewire).
 *
 * Freezes real vault blobs produced by the CURRENT (unchanged) production crypto, so the
 * post-rewire custody path can be proven to decrypt them byte-identically. src/ is untouched
 * at capture time, so these are the genuine "main-stand" blobs.
 *
 * What is frozen (committed to __tests__/fixtures/l3_golden_prerewire.json):
 *   - fileKeyWrap: a per-file key wrapped under the master key (AES-256-CBC + HMAC EtM),
 *     exactly what FileManager stores.
 *   - masterBlob:  a master key wrapped under a passphrase-KEK (same construction as
 *     wrapAndStoreMasterKey), exactly what unlockKEK consumes.
 *   - content (xchacha): the published draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD KAT, which is
 *     the SAME vector the on-device XChaCha20BridgeTest pins. The content custody path
 *     (decryptWithHandle) must reproduce it on device in the Phase 4 ceremony.
 *
 * This test is also a GUARD: it recomputes the AES-CBC+HMAC blobs from fixed inputs and
 * asserts they still equal the committed fixture. If a later change perturbs the wrapping
 * crypto by a single byte, this fails — the invariant tripwire.
 */

const secureStore = require('../__mocks__/expo-secure-store');

import * as fs from 'fs';
import * as path from 'path';
import { SecureCryptoService } from '../src/services/CryptoService';
import { aesCbcEncryptRaw } from '../src/services/AesCbcHmac';

const FIXTURE = path.join(__dirname, 'fixtures', 'l3_golden_prerewire.json');

// Fixed vault material (a synthetic but realistic vault).
const MASTER = 'a3f1c0de11223344556677889900aabbccddeeff00112233445566778899abcd'; // 32-byte master
const KEK    = 'ffeeddccbbaa99887766554433221100112233445566778899aabbccddeeff00'; // 32-byte KEK
const FILEKEY = '0f1e2d3c4b5a69788796a5b4c3d2e1f0aabbccddeeff00112233445566778899'; // 64-hex file key
const IV_FK  = '11223344556677889900aabbccddeeff'; // 16-byte iv (file-key wrap)
const IV_MB  = '00ffeeddccbbaa998877665544332211'; // 16-byte iv (master blob)

async function wrapEtm(plaintextHex: string, keyHex: string, ivHex: string) {
  const ct = await aesCbcEncryptRaw(plaintextHex, keyHex, ivHex);
  const macKey = await SecureCryptoService.deriveMacKey(keyHex);
  const mac = await SecureCryptoService.computeMac(macKey, ivHex + ct);
  return { iv: ivHex, encryptedKey: ct, mac };
}

describe('L3 Phase 2: golden capture (pre-rewire)', () => {
  test('capture + self-validate file-key wrap and master blob', async () => {
    const fileKeyWrap = await wrapEtm(FILEKEY, MASTER, IV_FK);
    const masterBlob = await wrapEtm(MASTER, KEK, IV_MB);

    // Self-validate: the production unwrap recovers the originals byte-identically.
    // L3 Phase 2: decryptFileKeyWith takes a custody handle, not a raw hex key.
    expect(await SecureCryptoService.decryptFileKeyWith(fileKeyWrap, SecureCryptoService.registerKeyHandle(MASTER))).toBe(FILEKEY);
    expect(await SecureCryptoService.decryptFileKeyWith(masterBlob, SecureCryptoService.registerKeyHandle(KEK))).toBe(MASTER);

    const golden = {
      note: 'L3 pre-rewire golden — DO NOT regenerate after Phase 2. Frozen main-stand blobs.',
      masterKeyHex: MASTER,
      kekHex: KEK,
      fileKeyWrap: { ...fileKeyWrap, plaintextHex: FILEKEY },
      masterBlob: { ...masterBlob, plaintextHex: MASTER },
      contentXchachaKat: {
        source: 'draft-irtf-cfrg-xchacha-03 §A.3.1 (== XChaCha20BridgeTest)',
        keyHex: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        nonceHex: '404142434445464748494a4b4c4d4e4f5051525354555657',
        aadHex: '50515253c0c1c2c3c4c5c6c7',
        plaintextUtf8: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        ctHex:
          'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
          '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
          '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
          '21f9664c97637da9768812f615c68b13b52e',
        tagHex: 'c0875924c1c7987947deafd8780acf49',
      },
    };

    if (fs.existsSync(FIXTURE)) {
      // GUARD: wrapping crypto must not have shifted by a byte.
      const onDisk = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
      expect(onDisk.fileKeyWrap).toEqual(golden.fileKeyWrap);
      expect(onDisk.masterBlob).toEqual(golden.masterBlob);
    } else {
      fs.mkdirSync(path.dirname(FIXTURE), { recursive: true });
      fs.writeFileSync(FIXTURE, JSON.stringify(golden, null, 2) + '\n');
      // eslint-disable-next-line no-console
      console.log(`[L3-golden] captured pre-rewire fixture -> ${FIXTURE}`);
    }
  }, 30000);
});
