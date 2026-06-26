/**
 * AesCbcHmac — raw AES-256-CBC encrypt/decrypt helpers (pure-JS fallback backend).
 *
 * Formerly named "FastAES". The old name was misleading: it is neither faster than
 * the native path nor AES-GCM — it is CryptoJS AES-256-CBC with PKCS7 padding and
 * NO authentication tag. The caller (CryptoService) is responsible for computing and
 * verifying an Encrypt-then-MAC HMAC-SHA256 tag over the ciphertext.
 *
 * Wire format note: this module produces raw CBC ciphertext only. The 0x02 backend
 * prefix byte and HMAC tag are added by CryptoService — unchanged by this rename.
 */

import CryptoJS from 'crypto-js';

/**
 * AES-256-CBC encryption (raw, unauthenticated).
 * @param data   Plaintext string
 * @param keyHex Hex-encoded 32-byte key
 * @param ivHex  Hex-encoded 16-byte IV
 * @returns Hex-encoded ciphertext (PKCS7 padded, no authentication tag)
 */
export async function aesCbcEncryptRaw(
  data: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
  const ivBytes  = CryptoJS.enc.Hex.parse(ivHex);
  const cipher = CryptoJS.AES.encrypt(data, keyBytes, {
    iv: ivBytes,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return cipher.ciphertext.toString(CryptoJS.enc.Hex);
}

/**
 * AES-256-CBC decryption (raw, unauthenticated — verify the HMAC tag first).
 * @param encryptedHex Hex-encoded ciphertext (no prefix, no auth tag)
 * @param keyHex       Hex-encoded 32-byte key
 * @param ivHex        Hex-encoded 16-byte IV
 * @returns Decrypted plaintext string
 */
export async function aesCbcDecryptRaw(
  encryptedHex: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const keyBytes = CryptoJS.enc.Hex.parse(keyHex);
  const ivBytes  = CryptoJS.enc.Hex.parse(ivHex);
  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Hex.parse(encryptedHex),
  });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, keyBytes, {
    iv: ivBytes,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
}
