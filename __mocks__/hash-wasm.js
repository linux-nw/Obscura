// Mock for hash-wasm: uses Node.js crypto PBKDF2 as a deterministic
// in-process substitute. Tests care about consistency, not Argon2id semantics.
const nodeCrypto = require('crypto');

module.exports = {
  argon2id: jest.fn(async (options) => {
    const { password, salt, hashLength = 32 } = options;
    const saltBuf = Buffer.from(typeof salt === 'string' ? salt : String(salt));
    const key = nodeCrypto.pbkdf2Sync(
      typeof password === 'string' ? password : Buffer.from(password),
      saltBuf,
      1,
      hashLength,
      'sha256'
    );
    return key.toString('hex');
  }),
};
