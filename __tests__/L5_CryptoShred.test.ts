/**
 * Layer 5 — crypto-shredding at the vault level.
 *
 * The vault's content is encrypted with the master key (no per-file keys exist — see §15
 * Layer 5). Therefore the reliable "delete" is destroying the master key: once the wrapped
 * master key is gone from SecureStore AND from memory, every ciphertext blob is permanently
 * undecryptable, regardless of whether the ciphertext bytes still linger on flash (where
 * overwrite is unreliable due to wear-leveling).
 *
 * This proves: after deleteEncryptionKey() + clearAllCaches(), a blob that decrypted fine a
 * moment ago can no longer be decrypted.
 */

const secureStore = require('../__mocks__/expo-secure-store');

import { SecureCryptoService } from '../src/services/CryptoService';

const PASSPHRASE = 'CryptoShredPass_123!';

beforeEach(() => {
  secureStore._reset();
  SecureCryptoService.clearAllCaches();
});

describe('Layer 5: vault-level crypto-shredding', () => {
  test('destroying the master key makes existing ciphertext permanently undecryptable', async () => {
    await SecureCryptoService.setupMasterKey(PASSPHRASE);

    const { encryptedData, iv, mac } = await SecureCryptoService.encryptData('top secret payload', 'f1:content');

    // Sanity: with the key present, the blob decrypts.
    expect(await SecureCryptoService.decryptData(encryptedData, iv, mac, 'f1:content')).toBe('top secret payload');

    // Crypto-shred: wipe the in-memory key AND the stored wrapped master key.
    SecureCryptoService.clearAllCaches();
    await SecureCryptoService.deleteEncryptionKey();

    // No key anywhere → the blob is dead, regardless of any flash residue.
    // L3 Phase 2: getMasterKey() is gone (throws); the locked state is "no master handle".
    expect(SecureCryptoService.__masterKeyHexForTest()).toBeNull();
    await expect(
      SecureCryptoService.decryptData(encryptedData, iv, mac, 'f1:content'),
    ).rejects.toThrow();

    // And the passphrase can no longer unlock anything (wrapped master key is gone).
    const unlocked = await SecureCryptoService.unlock(PASSPHRASE).catch(() => false);
    expect(unlocked).toBe(false);
  }, 60000);
});
