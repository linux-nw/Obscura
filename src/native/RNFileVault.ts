/**
 * RNFileVault — TypeScript bridge for the native Android module.
 *
 * The Kotlin side (RNFileVaultModule.kt) accepts ReadableMaps via the React
 * Native bridge. These wrappers convert the positional-argument calling style
 * used in the TS services to the map-based bridge API.
 *
 * All functions are async because the native side resolves Promises.
 */

import { NativeModules } from 'react-native';

type RNFileVaultNative = {
  encrypt(params: { data: string; key: string; nonce: string; aad?: string }): Promise<{ encrypted: string; tag: string }>;
  decrypt(params: { encrypted: string; nonce: string; tag: string; key: string; aad?: string }): Promise<string>;
  argon2id(params: { password: string; salt: string; iterations: number; memory: number; keyLen: number }): Promise<string>;
  verifyConstantTime(params: { a: string; b: string }): Promise<{ result: boolean }>;
  generateRandomBytes(params: { length: number }): Promise<string>;
};

function native(): RNFileVaultNative {
  const m = NativeModules.RNFileVault as RNFileVaultNative | undefined;
  if (!m) throw new Error('RNFileVault native module not available');
  return m;
}

const isHex = (v: unknown, chars: number): boolean =>
  typeof v === 'string' && v.length === chars && /^[0-9a-fA-F]+$/.test(v);

const isEvenHex = (v: unknown): boolean =>
  typeof v === 'string' && v.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(v);

function assertAead(key: string, nonce: string, aad?: string): void {
  if (!isHex(key, 64)) throw new Error('RNFileVault: key must be 32 bytes (hex)');
  if (!isHex(nonce, 48)) throw new Error('RNFileVault: nonce must be 24 bytes (hex)');
  if (aad !== undefined && !isEvenHex(aad)) throw new Error('RNFileVault: aad must be even-length hex');
}

/** XChaCha20-Poly1305 IETF encryption (detached MAC).
 *  @param data    Base64-encoded plaintext
 *  @param key     Hex-encoded 32-byte key
 *  @param nonce   Hex-encoded 24-byte nonce
 *  @param aad     Optional hex-encoded additional authenticated data (e.g. the
 *                 backend-prefix byte). Bound into the Poly1305 tag but not encrypted.
 *  @returns { encrypted: hex ciphertext, tag: hex Poly1305 tag }
 */
export async function encrypt(
  data: string,
  key: string,
  nonce: string,
  aad?: string
): Promise<{ encrypted: string; tag: string }> {
  assertAead(key, nonce, aad);
  if (typeof data !== 'string') throw new Error('RNFileVault: data must be a Base64 string');
  return native().encrypt({ data, key, nonce, aad });
}

/** XChaCha20-Poly1305 IETF decryption (detached MAC verification).
 *  @param encrypted Hex-encoded ciphertext
 *  @param nonce     Hex-encoded 24-byte nonce
 *  @param tag       Hex-encoded 16-byte Poly1305 tag
 *  @param key       Hex-encoded 32-byte key
 *  @param aad       Optional hex-encoded AAD — MUST match the value used at encrypt
 *                   time or the tag check fails.
 *  @returns Base64-encoded plaintext (throws on auth failure)
 */
export async function decrypt(
  encrypted: string,
  nonce: string,
  tag: string,
  key: string,
  aad?: string
): Promise<string> {
  assertAead(key, nonce, aad);
  if (!isEvenHex(encrypted)) throw new Error('RNFileVault: ciphertext must be even-length hex');
  if (!isHex(tag, 32)) throw new Error('RNFileVault: tag must be 16 bytes (hex)');
  return native().decrypt({ encrypted, nonce, tag, key, aad });
}

/** Argon2id key derivation via libsodium crypto_pwhash.
 *  @param password   UTF-8 passphrase
 *  @param salt       Base64-encoded 16-byte salt
 *  @param iterations Time cost (ops limit)
 *  @param memory     Memory cost in KB
 *  @param keyLen     Output length in bytes
 *  @returns Base64-encoded derived key
 */
export async function argon2id(
  password: string,
  salt: string,
  iterations: number,
  memory: number,
  keyLen: number
): Promise<string> {
  if (typeof password !== 'string' || typeof salt !== 'string') throw new Error('RNFileVault: invalid argon2id input');
  if (![iterations, memory, keyLen].every(Number.isInteger) || iterations < 1 || memory < 8 || keyLen < 16 || keyLen > 64) {
    throw new Error('RNFileVault: invalid argon2id parameters');
  }
  return native().argon2id({ password, salt, iterations, memory, keyLen });
}

/** sodium_memcmp constant-time comparison.
 *  @param a UTF-8 string A
 *  @param b UTF-8 string B
 *  @returns true iff a === b in constant time
 */
export async function verifyConstantTime(a: string, b: string): Promise<boolean> {
  const result = await native().verifyConstantTime({ a, b });
  return result.result === true;
}

/** libsodium randombytes_buf.
 *  @param length Number of random bytes
 *  @returns Base64-encoded random bytes
 */
export async function generateRandomBytes(length: number): Promise<string> {
  if (!Number.isInteger(length) || length < 1 || length > 1024) {
    throw new Error('RNFileVault: random length must be 1..1024');
  }
  const out = await native().generateRandomBytes({ length });
  const padding = out.endsWith('==') ? 2 : out.endsWith('=') ? 1 : 0;
  if (typeof out !== 'string' || (out.length / 4) * 3 - padding !== length) {
    throw new Error('RNFileVault: native RNG returned unexpected length');
  }
  return out;
}
