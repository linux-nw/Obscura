// Mock for expo-crypto: uses Node.js crypto for deterministic tests.
const nodeCrypto = require('crypto');

module.exports = {
  getRandomBytesAsync: jest.fn(async (length) => {
    // Mirror the REAL expo-crypto hard cap so an over-cap request fails in tests too
    // (caught a device-only L6 bug where 65536 was requested in one call).
    if (typeof length !== 'number' || length < 0 || length > 1024) {
      throw new TypeError(`expo-crypto: getRandomBytesAsync(${length}) expected a valid number from range 0...1024`);
    }
    const buf = nodeCrypto.randomBytes(length);
    // Return a Uint8Array with the same buffer/byteOffset/byteLength shape.
    const arr = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    return arr;
  }),
  CryptoDigestAlgorithm: { SHA256: 'SHA-256', SHA512: 'SHA-512' },
  digestStringAsync: jest.fn(async (alg, str) => {
    const hash = nodeCrypto.createHash('sha256').update(str).digest('hex');
    return hash;
  }),
};
