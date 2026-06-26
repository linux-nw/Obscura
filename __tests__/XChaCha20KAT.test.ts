/**
 * S4: XChaCha20-Poly1305-IETF Known-Answer Test (JS reference).
 *
 * Pins the official draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD test vector using the
 * independent @noble/ciphers implementation. This is the CI-checkable reference that the
 * on-device native test (androidTest/XChaCha20BridgeTest.kt) mirrors byte-for-byte:
 *   - JS  (@noble/ciphers)            → asserted here
 *   - Native (libsodium crypto_aead_xchacha20poly1305_ietf) → asserted on device
 * Both pinned to the SAME published vector ⇒ the two implementations are byte-identical
 * for this input (cross-impl equality, S4 acceptance #2), and both match the IETF KAT
 * (S4 acceptance #1).
 *
 * @noble/ciphers returns the COMBINED form (ciphertext || 16-byte Poly1305 tag). The
 * native module uses the DETACHED form; detached ct == combined[:-16], mac == combined[-16:].
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

// draft-irtf-cfrg-xchacha-03 §A.3.1 inputs
const KEY   = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
const NONCE = fromHex('404142434445464748494a4b4c4d4e4f5051525354555657'); // 24 bytes
const AAD   = fromHex('50515253c0c1c2c3c4c5c6c7');
const PLAINTEXT = Buffer.from(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  'utf8'
);

// Published known answer (detached form).
const EXPECTED_CT  =
  'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
  '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
  '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
  '21f9664c97637da9768812f615c68b13b52e';
const EXPECTED_TAG = 'c0875924c1c7987947deafd8780acf49';

describe('S4: XChaCha20-Poly1305-IETF KAT (draft-irtf-cfrg-xchacha-03 §A.3.1)', () => {
  test('encrypt produces the published ciphertext and tag', () => {
    const combined = xchacha20poly1305(KEY, NONCE, AAD).encrypt(new Uint8Array(PLAINTEXT));
    const ct  = combined.slice(0, combined.length - 16);
    const tag = combined.slice(combined.length - 16);
    expect(hex(ct)).toBe(EXPECTED_CT);
    expect(hex(tag)).toBe(EXPECTED_TAG);
  });

  test('decrypt of the published vector returns the plaintext', () => {
    const combined = Uint8Array.from([...fromHex(EXPECTED_CT), ...fromHex(EXPECTED_TAG)]);
    const pt = xchacha20poly1305(KEY, NONCE, AAD).decrypt(combined);
    expect(Buffer.from(pt).toString('utf8')).toBe(PLAINTEXT.toString('utf8'));
  });

  test('AEAD tamper detection: flipping a ciphertext byte fails the tag check', () => {
    const tampered = Uint8Array.from([...fromHex(EXPECTED_CT), ...fromHex(EXPECTED_TAG)]);
    tampered[0] ^= 0x01;
    expect(() => xchacha20poly1305(KEY, NONCE, AAD).decrypt(tampered)).toThrow();
  });

  test('AAD binding: wrong AAD fails the tag check', () => {
    const combined = Uint8Array.from([...fromHex(EXPECTED_CT), ...fromHex(EXPECTED_TAG)]);
    const wrongAad = Uint8Array.from([...AAD]); wrongAad[0] ^= 0x01;
    expect(() => xchacha20poly1305(KEY, NONCE, wrongAad).decrypt(combined)).toThrow();
  });
});
