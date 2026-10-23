# L3 Native Key Custody — Phase 0 Audit

Branch: `feat/l3-native-key-custody`. Read-only map of every point where the raw
master key materialises in the JS heap, and every primitive that consumes it.
This is the landmark the end-state is proven against: after the rebuild, the raw
master key must appear at **none** of the JS rows below.

Invariant reminder: not one ciphertext byte may change. Same key, same AEAD, same
AAD, same wire format, same prefixes `0x01`/`0x02`/`0x03`. Only *where the key lives*
changes.

## 1. Where the raw master key is first born in JS

| # | Site | file:line | What happens | Key form |
|---|------|-----------|--------------|----------|
| B1 | `setupMasterKey` | CryptoService.ts:749-752 | vault creation: `generateSecureBytes(32)` → hex → cache | raw hex string |
| B2 | `unlockKEK` | CryptoService.ts:808-822 | **login: `CryptoJS.AES.decrypt` of the wrapped master blob** → `masterKeyHex` → cache | raw hex string (decrypted **in JS**) |
| B3 | `loadMasterKeyForBiometric` | CryptoService.ts:711-728 | biometric: `CryptoJS.AES.decrypt` of hardware-stored blob → cache | raw hex string (in JS) |
| B4 | `migrateLegacy` | CryptoService.ts:831-846 | legacy plaintext key → cache | raw hex string |
| B5 | `installMasterKey` | CryptoService.ts:1869-1871 | post-rotation: caller hex → cache | raw hex string |

**B2/B3 are decisive:** the KEK-unwrap of the master key is done by `CryptoJS.AES.decrypt`
**inside JS**, not natively. Moving "unwrap to native" (Phase 1 req. 3) means a native
AES-256-CBC decrypt of the master blob byte-identical to CryptoJS.

## 2. Storage / lifetime of the cached key

| Site | file:line | Lifetime |
|------|-----------|----------|
| `__mkBytes: Uint8Array` | :1251 | long-lived zeroable copy (M2 mitigation already in place) |
| `_masterKeyCache` getter | :1253-1254 | **mints a fresh immutable hex string on every read** (`bytesToHex_fast`) → non-wipeable Hermes string, GC-lifetime. This is the documented §15.5 residual. |
| `_masterKeyCache` setter | :1256-1258 | zeroes prior bytes, stores new `Uint8Array` |
| `macKeyCache` | :1262 | `Map<masterKeyHex → macKeyHex>` — **keyed by the raw master hex**, so the raw key sits in a Map key too |

## 3. Every reader of the raw key

| Caller | file:line | Purpose | Path |
|--------|-----------|---------|------|
| `encryptData` | :960 | content encrypt | → `encryptDataWith(keyHex)` |
| `decryptData` | :1050 | content decrypt | → `decryptDataWith(keyHex)` |
| `encryptFileKey` | :1891 | wrap a per-file key | → `aesCBCEncrypt(fileKey, masterKeyHex)` |
| `decryptFileKey` | :1927 | unwrap a per-file key | → `aesCBCDecrypt(..., masterKeyHex)` |
| `changePassphrase` | :858 | re-wrap under new pass | reads `_masterKeyCache` |
| KeyRotationService | :94, :102, :110, :127, :141, :151 | WAL rotation | `getMasterKey`, `encryptFileKeyWith`/`decryptFileKeyWith` (explicit hex), `installMasterKey` |
| BackupService | createBackup BackupService.ts:85 | decrypt content for export | via `decryptData`/`decryptFileKey` → master key |

## 4. Native methods that exist today (signatures)

`RNFileVaultModule.kt` (`RNFileVault.ts` bridge):

| Method | Signature | Key handling |
|--------|-----------|--------------|
| `encrypt` | `{data,key,nonce,aad}` → `{encrypted,tag}` | **raw key crosses bridge as hex**, `hexToBytes`, `key.fill(0)` after op |
| `decrypt` | `{encrypted,nonce,tag,key,aad}` → plaintext | same — raw key crosses bridge every op |
| `argon2id` | `{password,salt,iterations,memory,keyLen}` → b64 key | KDF only |
| `verifyConstantTime` | `{a,b}` → bool | sodium_memcmp |
| `generateRandomBytes` | `{length}` → b64 | randombytes_buf |

No `sodium_malloc` / `sodium_mlock` / handle map exists yet. Native zeroing is
`ByteArray.fill(0)`, not `sodium_memzero`/`sodium_mlock`.

## 5. Which primitives consume the raw master key, and where they run

| Primitive | Used for | Runs today |
|-----------|----------|------------|
| XChaCha20-Poly1305 (`xchacha20Encrypt/Decrypt` → `RNFileVault.encrypt/decrypt`) | content (encryptData, 0x01) | **NATIVE** (key passed as hex) |
| AES-256-CBC raw (`aesCbcEncryptRaw/Raw`, AesCbcHmac.ts → **CryptoJS**) | file-key wrapping body; 0x02 content fallback | **JS (CryptoJS)** |
| HMAC-SHA256 (`computeMac` :1203 → @noble/hashes, CryptoJS fallback) | Encrypt-then-MAC tag over CBC ct; master-MAC at unlock | **JS** |
| HKDF-SHA256 (`deriveMacKey` :1273 → `hkdfSha256`) | derive MAC subkey from the master key | **JS** |
| AES-256-CBC decrypt (`CryptoJS.AES.decrypt`) | KEK-unwrap of the master blob (B2/B3) | **JS (CryptoJS)** |

## 6. Scope finding (the reason this is not a one-round prefix change)

"Raw master key never in JS" requires re-homing **four** primitive families to native,
each **byte-identical** to today or the invariant breaks (a pre-rebuild blob must
decrypt identically; every KAT must stay green):

1. **XChaCha20 content** — already native; switch the key argument from hex to a handle. (small)
2. **AES-256-CBC encrypt/decrypt for file-key wrapping** — today CryptoJS in JS.
   libsodium has **no AES-CBC**. Needs JCA `Cipher("AES/CBC/PKCS5Padding")` proven
   byte-identical to CryptoJS PKCS7. (medium, high parity risk)
3. **HMAC-SHA256 + HKDF-SHA256 subkey-from-master** — today JS. Needs native, byte-identical
   (HMAC input is the ASCII string `ivHex + ciphertextHex`; HKDF label `filevault-mac-v1`). (medium)
4. **AES-256-CBC decrypt of the master blob (KEK-unwrap, B2/B3)** — today CryptoJS in JS.
   Same JCA requirement as #2. (medium)

If only #1 ships, the raw master key **still** materialises in JS for every file-key
wrap/unwrap and at every unlock (B2/B3) — L3 would not be honestly Done. There is no
shortcut: re-wrapping file keys with XChaCha instead of AES-CBC would change the
file-key wire format, which the invariant forbids.

**Hardest risk:** byte-identical JCA-vs-CryptoJS parity (PKCS7 padding, key/IV hex
decoding, the `ivHex+ctHex` ASCII HMAC framing). This is the classic footgun and must
be proven by a parity harness against existing KATs/blobs *before* any custody wiring.

**Out of scope here / separate:** decoy/guest content key (own Argon2id key — DecoyVaultService);
the decoy lock-counter-A bug (§15.6 follow-up).
