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

const Native = NativeModules.RNFileVault as {
  encrypt(params: { data: string; key: string; nonce: string; aad?: string }): Promise<{ encrypted: string; tag: string }>;
  decrypt(params: { encrypted: string; nonce: string; tag: string; key: string; aad?: string }): Promise<string>;
  argon2id(params: { password: string; salt: string; iterations: number; memory: number; keyLen: number }): Promise<string>;
  verifyConstantTime(params: { a: string; b: string }): Promise<{ result: boolean }>;
  generateRandomBytes(params: { length: number }): Promise<string>;
};

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
  return Native.encrypt({ data, key, nonce, aad });
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
  return Native.decrypt({ encrypted, nonce, tag, key, aad });
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
  return Native.argon2id({ password, salt, iterations, memory, keyLen });
}

/** sodium_memcmp constant-time comparison.
 *  @param a UTF-8 string A
 *  @param b UTF-8 string B
 *  @returns true iff a === b in constant time
 */
export async function verifyConstantTime(a: string, b: string): Promise<boolean> {
  const result = await Native.verifyConstantTime({ a, b });
  return result.result;
}

/** libsodium randombytes_buf.
 *  @param length Number of random bytes
 *  @returns Base64-encoded random bytes
 */
export async function generateRandomBytes(length: number): Promise<string> {
  return Native.generateRandomBytes({ length });
}
