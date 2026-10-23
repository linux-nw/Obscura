import * as fs from 'fs';
import * as path from 'path';

const dir = path.join(__dirname, '..', 'android', 'app', 'src', 'main', 'java', 'com', 'filevault', 'app', 'modules');
const read = (f: string) => fs.readFileSync(path.join(dir, f), 'utf8');

describe('Kotlin native modules: static security invariants', () => {
  test('no lenient hex parsing via toInt(16) anywhere in the bridge modules', () => {
    for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.kt'))) {
      expect(read(f)).not.toMatch(/toInt\(16\)/);
    }
  });

  test('RNFileVaultModule delegates to the strict hex decoder and bounds KDF/RNG inputs', () => {
    const s = read('RNFileVaultModule.kt');
    expect(s).toMatch(/NativeKeyCustodyCrypto\.fromHex\(hex\)/);
    expect(s).toMatch(/MIN_ARGON2_MEMORY_KB/);
    expect(s).toMatch(/length < 1 \|\| length > 1024/);
    expect(s).toMatch(/sodium_init\(\)/);
    expect(s).not.toMatch(/promise\.reject\("DECRYPT_ERROR", e\.message/);
  });

  test('custody core validates handle format, key and nonce sizes, and serialises close vs use', () => {
    const s = read('NativeKeyCustody.kt');
    expect(s).toMatch(/\^\[0-9a-f\]\{32\}\$/);
    expect(s).toMatch(/nonce must be 24 bytes/);
    expect(s).toMatch(/tag must be 16 bytes/);
    expect(s).toMatch(/ReentrantReadWriteLock/);
    expect(s).toMatch(/sodium_memzero\(kek, kek\.size\)\s*\n\s*\}\s*\n\s*\}/);
  });

  test('custody crypto enforces AES key/IV/MAC shapes and zeroes derived MAC keys', () => {
    const s = read('NativeKeyCustodyCrypto.kt');
    expect(s).toMatch(/AES key must be 32 bytes/);
    expect(s).toMatch(/MAC must be 32 bytes/);
    expect(s).toMatch(/macKey\.fill\(0\)/);
    expect(s).toMatch(/invalid hex character/);
  });

  test('HardwareKeystoreModule validates key ids and reserves the attestation probe alias', () => {
    const s = read('HardwareKeystoreModule.kt');
    expect(s).toMatch(/KEY_ID_RE/);
    expect(s).toMatch(/attest_probe/);
    expect(s.match(/"filevault_\$keyId"/g)?.length).toBe(1);
  });
});
