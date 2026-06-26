// Mock for @noble/hashes/argon2.js: uses Node.js crypto PBKDF2 as a deterministic,
// fast in-process substitute. Real Argon2id at 64 MB / t=3 in pure JS is far too slow
// for the test suite. Tests care about consistency, not Argon2id semantics.
//
// Byte-for-byte identical behaviour to __mocks__/hash-wasm.js (the path this replaced)
// so any value pinned against the old mock stays stable.
//
// Argon2idReal.test.ts overrides this with the REAL module to pin the KAT.
const nodeCrypto = require('crypto');

function deriveStub(password, salt, opts = {}) {
  const dkLen = opts.dkLen ?? 32;
  const saltBuf = Buffer.from(typeof salt === 'string' ? salt : String(salt));
  const key = nodeCrypto.pbkdf2Sync(
    typeof password === 'string' ? password : Buffer.from(password),
    saltBuf,
    1,
    dkLen,
    'sha256'
  );
  return new Uint8Array(key);
}

const argon2id = jest.fn((password, salt, opts) => deriveStub(password, salt, opts));
const argon2idAsync = jest.fn(async (password, salt, opts) => deriveStub(password, salt, opts));

module.exports = { argon2id, argon2idAsync, argon2d: argon2id, argon2i: argon2id };
