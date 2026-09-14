import * as Crypto from 'expo-crypto';

/**
 * Generates an unpredictable, prefix-free ID: a base36 timestamp plus 8 random bytes as hex.
 * The caller is responsible for any prefix in the resulting file/note/record name.
 * Shared implementation, factored out of FileManager's original generateSecureFileId().
 */
export async function generateSecureId(): Promise<string> {
  const timestamp = Date.now().toString(36);
  const randomBytes = await Crypto.getRandomBytesAsync(8);
  const randomHex = Array.from(new Uint8Array(randomBytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `${timestamp}_${randomHex}`;
}
