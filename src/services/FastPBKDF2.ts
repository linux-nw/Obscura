/**
 * FastPBKDF2 — PBKDF2-SHA256 wrapper + HKDF-SHA256 subkey derivation.
 *
 * Uses CryptoJS (already in package.json).
 */

import CryptoJS from 'crypto-js';

/** Returns true iff @noble/hashes is available at runtime. */
export function isNobleAvailable(): boolean {
  try {
    require('@noble/hashes/pbkdf2.js');
    return true;
  } catch {
    return false;
  }
}

/**
 * PBKDF2-SHA256 key derivation.
 * @param password  UTF-8 passphrase (should already be NFC-normalised)
 * @param saltHex   Hex-encoded salt
 * @param iterations Iteration count (e.g. 600 000 for KEK, 10 000 for MAC key)
 * @param keyLen    Desired output length in bytes
 * @returns Hex-encoded derived key
 */
export async function fastPbkdf2(
  password: string,
  saltHex: string,
  iterations: number,
  keyLen: number
): Promise<string> {
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100_000_000) {
    throw new Error('fastPbkdf2: invalid iteration count');
  }
  if (!Number.isInteger(keyLen) || keyLen < 4 || keyLen > 64 || keyLen % 4 !== 0) {
    throw new Error('fastPbkdf2: invalid key length');
  }
  if (saltHex.length < 32 || saltHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(saltHex)) {
    throw new Error('fastPbkdf2: salt must be hex, at least 16 bytes');
  }
  // CryptoJS keySize is in 32-bit words: keyLen bytes / 4 bytes per word
  const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(saltHex), {
    keySize: keyLen / 4,
    iterations,
    hasher: CryptoJS.algo.SHA256,
  });
  return key.toString(CryptoJS.enc.Hex);
}

/**
 * HKDF-SHA256 subkey derivation (RFC 5869).
 *
 * Correct primitive for deriving a subkey from an already-strong key.
 * PBKDF2 is designed for password stretching, not subkey derivation.
 *
 * @param ikmHex   Hex-encoded input keying material (must be a strong key)
 * @param infoStr  Domain-separation label (ASCII, e.g. 'filevault-mac-v1')
 * @param length   Output length in bytes (max 32 for one-round Expand)
 * @returns Hex-encoded derived key (length*2 hex chars)
 */
export function hkdfSha256(ikmHex: string, infoStr: string, length: number = 32): string {
  if (!Number.isInteger(length) || length < 1 || length > 32) {
    throw new Error('hkdfSha256: length must be 1..32');
  }
  if (ikmHex.length < 32 || ikmHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(ikmHex)) {
    throw new Error('hkdfSha256: ikm must be hex, at least 16 bytes');
  }
  // Extract: PRK = HMAC-SHA256(salt=0x00*32, IKM)
  // Per RFC 5869 §2.2: when IKM is already uniform, use HashLen zero bytes as salt.
  const salt = CryptoJS.enc.Hex.parse('00'.repeat(32)); // 32 zero bytes
  const ikm  = CryptoJS.enc.Hex.parse(ikmHex);
  const prk  = CryptoJS.HmacSHA256(ikm, salt);

  // Expand (one round sufficient for length ≤ 32):
  // T(1) = HMAC-SHA256(PRK, info || 0x01)
  const infoWords    = CryptoJS.enc.Utf8.parse(infoStr);
  const counterByte  = CryptoJS.enc.Hex.parse('01');
  const t1Input      = infoWords.clone().concat(counterByte);
  const t1           = CryptoJS.HmacSHA256(t1Input, prk);

  // Trim to requested byte length
  return t1.toString(CryptoJS.enc.Hex).substring(0, length * 2);
}
