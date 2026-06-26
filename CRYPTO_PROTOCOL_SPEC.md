# Obscura FileVault — Cryptographic Protocol Specification

**Version:** 1.0  
**Date:** 2026-05-22  
**Status:** Production-ready (after Round 3 fixes)  
**Audience:** Cryptographers, security auditors

---

## 1. Overview

FileVault implements a three-layer key hierarchy (Master Key → File Key → Data) with two
KDF paths, two cipher backends, authenticated encryption, constant-time comparisons, a
Write-Ahead Log for atomic key rotation, and a Panic PIN that activates a decoy vault.

---

## 2. Key Hierarchy

```
Passphrase / PIN
       │
       ▼  KDF (Argon2id primary / PBKDF2-SHA256 fallback)
      KEK  (32 bytes, never persisted; derived on-demand, cleared after use)
       │
       ▼  AES-256-CBC-HMAC or XChaCha20-Poly1305 (backend-dependent)
  Master Key  (32 bytes, stored encrypted in SecureStore)
       │
       ├─▶  File Key₁  (32 bytes, AES-256-CBC-HMAC or XChaCha20-Poly1305)
       ├─▶  File Key₂
       └─▶  File Keyₙ
                 │
                 ▼  Same backend as above
             File Ciphertext  (stored on-device filesystem)
```

---

## 3. Key Derivation Functions

### 3.1 Primary KDF — Argon2id (native libsodium)

Used when the Android native module (`RNFileVaultModule.kt`) is available.

| Parameter    | Value                                |
|--------------|--------------------------------------|
| Algorithm    | Argon2id (type=2), version 0x13      |
| Memory cost  | 65 536 KB (64 MiB)                   |
| Time cost    | 3 iterations                         |
| Parallelism  | 1 lane (C1: libsodium `crypto_pwhash` forces lanes=1; hash-wasm pinned to match) |
| Output       | 32 bytes (hex-encoded)               |
| Salt         | 16 bytes CSPRNG, fed as RAW bytes to BOTH paths (C1) |
| Backend      | libsodium `crypto_pwhash` via JNI    |
| NFC normal.  | `passphrase.normalize('NFC')` (R-03) |

Salt is stored alongside the encrypted master key in SecureStore.

### 3.2 Fallback KDF — PBKDF2-SHA256

Used when the native module is unavailable (e.g., emulator, integration tests).

| Parameter    | Value                                     |
|--------------|-------------------------------------------|
| Algorithm    | PBKDF2-HMAC-SHA256                        |
| Iterations   | 600 000                                   |
| Output       | 32 bytes (hex-encoded)                    |
| Salt         | 16 bytes CSPRNG (per setup)               |
| Library      | CryptoJS 4.x                              |
| NFC normal.  | `passphrase.normalize('NFC')` (R-03)      |

### 3.3 Panic PIN / Decoy PIN KDF — Argon2id (S1)

Used for the Panic PIN and the Decoy PIN, independent of the KEK derivation path.

| Parameter    | Value                                                  |
|--------------|--------------------------------------------------------|
| Algorithm    | **Argon2id** (type=2), version 0x13                    |
| Memory cost  | 65 536 KB (64 MiB)                                     |
| Time cost    | 3 iterations                                           |
| Parallelism  | 1 lane (C1: matches native libsodium `crypto_pwhash`)  |
| Output       | 32 bytes (hex string)                                  |
| Salt         | 16 bytes CSPRNG per PIN setup                          |
| Backend      | native libsodium `crypto_pwhash`; else `@noble/hashes` argon2id (JS) |
| NFC normal.  | `pin.normalize('NFC')` (R-03)                          |

The stored hash, salt, and KDF marker are separate SecureStore keys
(`filevault_panic_pin_hash`, `filevault_panic_pin_salt`, `filevault_panic_pin_algo`;
analogously `filevault_decoy_pin_*`).

**Hardness now matches the vault KEK (§3.1):** Panic/Decoy PINs are stretched with the
same memory-hard Argon2id parameter class (m=64 MiB, t=3, p=1) as the vault passphrase,
so brute-force cost against a leaked PIN hash is equivalent to brute-force against the
vault KEK — there is no longer a cheaper KDF on this path.

> **History (S1).** Pre-S1 builds stretched these PINs with PBKDF2-HMAC-SHA256 at only
> **10 000** iterations (an earlier spec revision incorrectly documented this as 600 000).
> That was ~60× cheaper to brute-force than the vault KEK. A hash carrying no
> `*_pin_algo` marker is treated as a legacy PBKDF2-10k hash: it is verified the old way
> and, on the first successful verify, transparently re-hashed with Argon2id (fresh salt,
> `algo='argon2id'` written). No existing user is locked out; the weak hash is replaced
> on next use.

---

## 4. Symmetric Encryption

### 4.1 Backend Selection

The first byte of every ciphertext blob is a backend identifier:

| Byte | Backend              | When used                           |
|------|----------------------|-------------------------------------|
| 0x01 | XChaCha20-Poly1305   | Native module present               |
| 0x02 | AES-256-CBC+HMAC     | Pure-JS fallback, no native module  |
| 0x03 | AES-256-CBC+HMAC     | CryptoJS fallback (last resort)     |

The prefix **is authenticated** (W-03 fix): it is bound into the auth tag — as
Poly1305 AAD for XChaCha20, and folded into the HMAC input (`prefix || iv ||
ciphertext`) for the AES backends. The dispatcher reads the prefix to route, then
re-supplies it to the backend so a flipped prefix fails the tag check. See §4.4 for
the prefix strip.

> **No silent JS-crypto downgrade on WRITE (S3).** `getEncryptionBackend()` returns
> `0x01` (XChaCha20) only when the native module is present, else `0x02` (pure-JS
> AES-CBC+HMAC). An attacker who strips/blocks the native module would otherwise silently
> downgrade every NEW write to JS crypto. `encryptDataWith` now REFUSES a non-XChaCha
> write unless explicitly permitted: `NODE_ENV==='test'` (Jest) or
> `global.__filevault_allow_js_crypto === true` (a dev opt-in set only under `__DEV__`
> when the native module is missing, logged loudly). A production release with the native
> module absent therefore THROWS on write instead of downgrading. The **read** path for
> existing `0x02`/`0x03` blobs is never gated (backward compatibility), and key-wrapping
> (`aesCBCEncrypt`, by design AES-CBC) is unaffected.

### 4.2 XChaCha20-Poly1305 (Primary)

> **Test coverage.** `__tests__/XChaCha20Path.test.ts` installs a faithful native
> mock (`NativeModules.RNFileVault`) and exercises the 0x01 path: encrypt→decrypt
> round-trip, non-Latin1 (emoji/CJK) content via UTF-8 Base64, and AEAD tamper
> detection. The mock substitutes the cipher; auditors must still verify the real
> libsodium XChaCha20-Poly1305 bridge on a device with the native module loaded.

- **Key:** 32 bytes (256-bit)
- **Nonce:** 24 bytes CSPRNG (`generateRandomBytes` via libsodium `randombytes_buf`)
- **AEAD:** XChaCha20-Poly1305 IETF (`crypto_aead_xchacha20poly1305_ietf_encrypt_detached`)
- **Tag:** 16 bytes Poly1305 (detached)
- **Implementation:** lazysodium-android via JNI

Wire format (stored in SecureStore or filesystem):
```
backend_byte (1) || iv_hex (48 chars = 24 bytes) || mac_hex (32 chars = 16 bytes) || ciphertext_hex
```

### 4.3 AES-256-CBC + Encrypt-then-MAC (Fallback)

- **Key:** 32 bytes (256-bit)
- **IV:** 16 bytes CSPRNG
- **Cipher:** AES-256-CBC (PKCS#7 padding via CryptoJS)
- **MAC key:** HKDF-SHA256(masterKey, "filevault-mac-v1") — separate from the enc key (W-01)
- **MAC algorithm:** HMAC-SHA256
- **MAC input:** `prefix_hex || hex(utf8(aadContext)) || iv_hex || ciphertext_hex` (Encrypt-then-MAC; W-03 + H2 bind the backend byte and the object/role context)
- **MAC output:** 32 bytes hex

Wire format:
```
backend_byte (1) || iv_hex (32 chars = 16 bytes) || mac_hex (64 chars = 32 bytes) || ciphertext_hex
```

### 4.4 Prefix Strip (Critical Fix — F-prefix-strip)

**Before Round 3:** `encryptedData` (including the 2-byte hex backend prefix) was
passed directly to backend decrypt functions. The MAC was computed over the raw
ciphertext (without prefix), so the backend received wrong input → MAC mismatch on
every decrypt attempt. **All data was unreadable since the initial commit.**

**After Round 3:**
```typescript
const rawCiphertext = encryptedData.substring(2); // strip 2-hex-char prefix
// rawCiphertext is passed to backends for decryption
```

---

## 5. Key Storage

| Key                  | Storage location          | Protected by            |
|----------------------|---------------------------|-------------------------|
| Master Key (enc.)    | `expo-secure-store`       | KEK (derived from PIN)  |
| KEK                  | In-memory only            | Never persisted         |
| File Key (enc.)      | `expo-secure-store`       | Master Key              |
| PIN salt             | `expo-secure-store`       | Plaintext               |
| PIN hash             | Not stored (KEK derived)  | —                       |
| Panic PIN hash       | `expo-secure-store`       | Plaintext (PBKDF2 hash) |
| Panic PIN salt       | `expo-secure-store`       | Plaintext               |
| WAL (during rotation)| `expo-secure-store`       | See §6                  |

`expo-secure-store` maps to Android Keystore (hardware-backed on supported devices)
and iOS Keychain.

> **`HardwareKeystoreService` hardening.**
> `HardwareBackedStorage` now pins iOS items to `WHEN_UNLOCKED_THIS_DEVICE_ONLY`
> (non-exportable, no backup/iCloud migration) and exposes an opt-in
> `requireAuthentication` flag (used for the biometric KEK). On Android, the values
> already live in the hardware-backed Android Keystore (TEE; StrongBox where present)
> by default. Note: `expo-secure-store` does **not** expose a StrongBox/keychain-level
> toggle, and `requireAuthentication` is deliberately NOT blanket-enabled — gating
> routine secrets (master_enc, salts, counters) would force a biometric prompt on every
> unlock/counter-write and break devices with no enrolled biometrics.

---

## 6. WAL-Based Atomic Key Rotation (R-02)

> **Architecture note.** File and note content is encrypted **directly with the
> master key** (`encryptData`/`decryptData`), not via a per-file-key layer. The
> `EncryptedFileKey` wrapping helpers exist but the active vault does not use them.
> Rotating the master key therefore requires **re-encrypting every content blob**
> from the old master key to the new one, not merely re-wrapping key entries.

Rotation re-encrypts all file + note content and installs a fresh master key. It is
crash/power-loss safe through per-blob idempotency plus a single-record WAL.

### 6.1 WAL Record

```typescript
interface RotationWAL {
  newMasterWrapped: EncryptedFileKey; // new master key encrypted with the OLD master key
  startedAt: number;                  // Unix timestamp ms
}
```

Stored at SecureStore key `filevault_keyrotation_wal`. `newMasterWrapped` lets a
post-crash resume recover the new master key while the OLD master is still installed.

`startedAt` is used for staleness (W-05): on resume, a WAL older than
`MAX_WAL_AGE_MS` (24h) is logged as STALE before completing. Resume still finishes the
rotation — per-blob idempotency makes that safe, and forcing completion is the correct
response to an attacker pausing rotation indefinitely (the mixed old/new state is
resolved rather than left pending).

### 6.2 Per-Blob Idempotency

`CryptoService.recryptBlob({data,iv,mac}, oldKey, newKey)` is the migration unit:

```
recryptBlob:
  try decryptDataWith(blob, newKey)  → success ⇒ already migrated, return unchanged
  else decryptDataWith(blob, oldKey) → re-encrypt with newKey, return new blob
```

Each blob carries its own HMAC/AEAD tag, so the key it is under is determined by
which decrypt verifies. This makes re-encryption **idempotent and resumable** — a
rotation may abort at any point and be re-run safely without producing a mixed state.

### 6.3 Rotation Protocol

```
performSecureRotation(currentPassphrase):
  1. unlock(currentPassphrase)            → oldMasterKey in cache
  2. Generate newMasterKey (32 bytes CSPRNG)
  3. newMasterWrapped = encrypt(newMasterKey, oldMasterKey)
  4. Write WAL { newMasterWrapped, startedAt }
  5. FileManager.reencryptAll(old,new); NotesService.reencryptAll(old,new)
  6. COMMIT: installMasterKey(newMasterKey, currentPassphrase)   ← runs LAST
  7. Delete WAL
```

The stored master key (`filevault_master_enc`) stays OLD until step 6, so a crash
before commit leaves a fully consistent old-master vault plus a WAL.

### 6.4 Recovery Protocol (resumeRotationIfNeeded, post-unlock)

Recovery needs the old master key **and** the passphrase, neither available at cold
startup, so it runs **after a successful unlock** (`AuthScreen.checkLoginPass`), not
in `initialize()`:

```
resumeRotationIfNeeded(passphrase):
  if no WAL: return
  currentKey = master key in cache
  try newMasterKey = decrypt(newMasterWrapped, currentKey):
    success ⇒ currentKey is the OLD master (pre-commit):
        reencryptAll(currentKey, newMasterKey)   // idempotent finish
        installMasterKey(newMasterKey, passphrase)
        delete WAL
    failure ⇒ currentKey is NOT the old master ⇒ commit already happened:
        delete the stale WAL (content already fully migrated)
```

### 6.5 Invariant

A content blob is only ever **re-encrypted to** `newMasterKey`; the choice between
old and new key per blob is made by tag verification, never by guesswork. After a
successful commit, every blob and the stored master key are under the new key.

---

## 7. Panic PIN (R-01)

### 7.1 Verification Protocol

Both checks run unconditionally via `Promise.all` in `AuthScreen.checkLoginPass`:

```typescript
const [panicMatch, realMatch] = await Promise.all([
  PanicService.verifyPanicPin(entered),
  SecureCryptoService.unlock(entered),
]);
```

There is no early return before both Promises resolve. This prevents a timing
oracle that would reveal "this is a Panic PIN" vs "this is a real PIN."

### 7.2 Comparison

`PanicService.verifyPanicPin` calls:
```typescript
SecureCryptoService.constantsTimeEquals(hash, storedHash)
```

`constantsTimeEquals` uses `sodium_memcmp` (constant-time) via the native module,
falling back to a JS XOR-accumulate loop.

### 7.3 Timing Guarantee (S1-updated)

The defense against a "Panic vs. real vs. decoy" timing oracle rests on two properties,
not on a specific iteration count:

1. **Unconditional KDF execution.** `verifyPanicPin`, `unlock` and `verifyDecoyPin` each
   run their KDF (Argon2id) to completion before comparing — there is no early return
   that would skip the stretch on a wrong/non-matching PIN.
2. **Parallel join.** `AuthScreen.checkLoginPass` runs all three checks under a single
   `Promise.all` and awaits all of them, so the observable wall-clock time is
   `max(panic, real, decoy)` regardless of which (if any) matches. Since `unlock`
   (Argon2id-64 MiB) is the dominant term and always runs, the entered PIN's *category*
   is not leaked by total time.

`__tests__/PanicPIN.test.ts` asserts the structural invariant directly — the KDF is
invoked on both the correct and the wrong path (no early-return bypass) — rather than a
wall-clock threshold (which was an artifact of the old un-mocked PBKDF2 cost).

---

## 8. NFC Normalization (R-03)

Unicode allows multiple byte-sequence representations of the same logical character
(e.g. "ü" as U+00FC vs. "u" + U+0308). Without normalization, NFD input to PBKDF2
produces a different key than NFC input.

**Applied at all KDF call sites:**
- `SecureCryptoService.deriveKEK`: `passphrase = passphrase.normalize('NFC')`
- `SecureCryptoService.computePinHash`: `pin.normalize('NFC')`
- `PanicService.computePinHash`: `pin.normalize('NFC')`

---

## 9. Backup Key Derivation (F-03)

Backup encryption uses a separate key derived from a user-supplied passphrase:

| Parameter    | Value (v3, current)                       |
|--------------|-------------------------------------------|
| Algorithm    | **Argon2id** (memory-hard) — H1           |
| Parameters   | m=64 MiB, t=3, p=1 (same as vault KEK)     |
| Output       | 32 bytes                                  |
| Salt         | 16 bytes CSPRNG (crypto_pwhash needs 16)  |
| Min passphrase | 12 chars (enforced in `createBackup`)   |
| Format       | `{ version:3, kdf:'argon2id', kdfParams:{m,t,p}, salt, iv, tag, backup }` |

H1: backups previously used PBKDF2-600k (GPU-friendly), downgrading the KDF below the
vault's Argon2id. v3 uses Argon2id so an exfiltrated, portable backup is as hard to
brute-force as the vault itself. **v2 (PBKDF2) backups are still accepted on restore**
for backward compatibility; only v3 is ever produced. Note: the salt is 16 bytes (not
32) because libsodium `crypto_pwhash` requires exactly `crypto_pwhash_SALTBYTES` = 16.

The backup is encrypted with AES-256-CBC and authenticated with HMAC-SHA256 over
`iv || ciphertext` (Encrypt-then-MAC). Version 1 (bare HMAC) is rejected.

### 9.1 Payload (portable, E2E)

`createBackup` bundles **decrypted** content (file bytes as Base64, plus note
fields), then encrypts that JSON under the backup key. The backup is thus portable
and independent of the vault master key. Creating a backup requires the vault to be
unlocked (master key in cache) to decrypt the content first.

`restoreBackup` decrypts the bundle and **re-imports** each item via
`FileManager.importFile` / `NotesService.createNote`, re-encrypting it under the
**current** master key. Restore also requires an unlocked vault. A wrong backup
passphrase fails the MAC check and imports nothing.

---

## 10. Known Weaknesses and Recommendations

| ID | Severity | Issue | Recommendation |
|----|----------|-------|----------------|
| W-01 | ~~Medium~~ **Fixed** | ~~AES-256-CBC fallback uses the same key for encryption and MAC~~ → MAC key is now derived via HKDF-SHA256 with domain label `filevault-mac-v1` (`deriveMacKey`), separate from the encryption key | — |
| W-02 | ~~Low~~ **Fixed (S1)** | ~~Panic/Decoy PIN used PBKDF2-10k (≈60× weaker than the KEK)~~ → now Argon2id (m=64 MiB, t=3, p=1), same hardness class as the vault KEK; legacy hashes auto-migrated on next successful verify | — |
| W-03 | ~~Low~~ **Fixed** | ~~Backend identifier byte is unauthenticated~~ → prefix is now bound into the auth tag (Poly1305 AAD for XChaCha20; `prefix‖iv‖ct` HMAC for AES) | — |
| W-04 | ~~Info~~ **Fixed** | ~~NFC normalization only JS-side~~ → `RNFileVaultModule.kt` normalizes the password (`Normalizer.NFC`) before `crypto_pwhash`, so non-JS callers match too | — |
| W-05 | ~~Info~~ **Fixed** | ~~WAL `startedAt` not used for expiry~~ → `resumeRotationIfNeeded` warns on a WAL older than `MAX_WAL_AGE_MS` (24h), then completes it (idempotent) | — |
| W-06 | Info | XChaCha20 (primary path) treats the plaintext string as UTF-8 (`utf8ToBase64`). Vault data written before this fix with Latin1-only `btoa` is not byte-compatible | Only relevant for pre-fix installs; none expected (path previously threw on non-Latin1) |

---

## 11. Random Number Generation

| Use case         | Source                                      |
|------------------|---------------------------------------------|
| Nonce / IV       | `expo-crypto.getRandomBytesAsync` → `crypto_secretstream_xchacha20_keygen` on native |
| Key generation   | `libsodium.randombytes_buf` (native) or `expo-crypto.getRandomBytesAsync` (fallback) |
| Salt (KDF)       | `expo-crypto.getRandomBytesAsync`           |
| Salt (backup)    | `expo-crypto.getRandomBytesAsync` (16 bytes; H1 — libsodium `crypto_pwhash_SALTBYTES`=16) |

All sources use hardware CSPRNG on Android (via `/dev/urandom` or `SecureRandom`).

---

## 12. SecureStore Key Index

| SecureStore Key                        | Contents                                  |
|----------------------------------------|-------------------------------------------|
| `filevault_master_key`                 | Encrypted master key (JSON EncryptedFileKey) |
| `filevault_pin_salt`                   | KDF salt (hex)                            |
| `filevault_app_initialized`            | `"true"` or absent                        |
| `filevault_filekey_<fileId>`           | Encrypted file key (JSON EncryptedFileKey)|
| `filevault_panic_pin_hash`             | Argon2id hash of Panic PIN (hex; S1)      |
| `filevault_panic_pin_salt`             | Panic PIN KDF salt (hex)                  |
| `filevault_panic_pin_algo`             | Panic PIN KDF marker (`argon2id`; absent = legacy PBKDF2-10k) |
| `filevault_decoy_pin_hash` / `_salt` / `_algo` | Decoy PIN hash/salt/KDF marker (Argon2id; S1) |
| `filevault_keyrotation_wal`            | JSON RotationWAL (present only during rotation) |
| `filevault_decoy_activated`            | `"true"` when decoy vault is active       |
| `filevault_lock_until`                 | Unix timestamp (permanent lock expiry)    |

---

## 13. Test Coverage

| Test file                              | Covers                                                                  |
|----------------------------------------|-------------------------------------------------------------------------|
| `__tests__/PanicPIN.test.ts`           | R-01/S1: correct/wrong/no PIN; KDF invoked on both paths; PBKDF2→Argon2id migration |
| `__tests__/NFCNormalization.test.ts`   | R-03: NFC==NFD after normalize; PanicService NFC                       |
| `__tests__/KeyRotationWAL.test.ts`     | R-02: 4 power-loss scenarios + WAL key invariant; decryption proof     |
| `__tests__/CryptoRoundtrip.test.ts`    | AES-CBC+HMAC (0x02) + CryptoJS (0x03) roundtrip; ciphertext/MAC bit-flip |
| `__tests__/BackupRoundtrip.test.ts`    | Backup blob roundtrip; wrong passphrase throws; backup key ≠ master key |
| `__tests__/BackupContent.test.ts`      | Full create → wipe → restore of real file + note content; wrong pass imports nothing |
| `__tests__/XChaCha20Path.test.ts`      | Backend 0x01 roundtrip (mocked native); UTF-8 emoji/CJK; AEAD tamper detection |

| `__tests__/Argon2idReal.test.ts`       | REAL hash-wasm Argon2id KAT + determinism/salt-sensitivity (un-mocked) |

`__tests__/KeyRotationWAL.test.ts` covers full content re-encryption: full rotation +
re-login, crash-mid-rotation resume, stale-WAL cleanup, wrong-passphrase abort.
`CryptoRoundtrip` + `XChaCha20Path` additionally assert the W-03 prefix-authentication
(a flipped backend byte is rejected on both the AES and XChaCha20 paths).

| `__tests__/A3Rollback.test.ts`         | A3: AAD version binding, monotonic counter, note rollback rejected, version-tamper rejected, rotation preserves version |
| `__tests__/FsAtomic.test.ts`           | H3: atomic write + temp cleanup |
| `androidTest/Argon2idKatTest.kt`       | On-device: native Argon2id `crypto_pwhash` KAT (C1) |
| `androidTest/XChaCha20BridgeTest.kt`   | On-device: native XChaCha20-Poly1305 roundtrip/tamper/AAD/determinism (FIX 2) |

All JS/Jest suites pass. The three `androidTest` suites were **run on-device and passed**
(see verification status below); re-run via `./gradlew connectedAndroidTest` before each
release, or automatically in CI (see `.github/workflows/android-kat.yml`).

### 13.1 Verified primitives (S4/S7)

The core primitives are pinned to known-answer vectors, with the native (libsodium) and
JS (@noble) implementations locked to the **same** constant so they are byte-identical:

| Primitive | Vector / KAT | JS assertion | Native (on-device) assertion |
|-----------|--------------|--------------|------------------------------|
| Argon2id v1.3 (m=64 KiB, t=2, p=1) | `correct horse battery staple`, salt `0102…10` → `c97f06cb…37b8f38` | `__tests__/Argon2idReal.test.ts` (real @noble) | `androidTest/Argon2idKatTest.kt` (libsodium `crypto_pwhash`) — **same constant** |
| XChaCha20-Poly1305-IETF | draft-irtf-cfrg-xchacha-03 §A.3.1 (ct `bd6d…b52e`, tag `c087…cf49`) | `__tests__/XChaCha20KAT.test.ts` (@noble/ciphers) | `androidTest/XChaCha20BridgeTest.kt::xchacha20_official_kat_a31` (libsodium) — **same constants** |
| Constant-time compare | `sodium_memcmp` equal→0 / differ→≠0 | `__tests__/ConstantTimeEquals.test.ts` (JS fallback correctness) | `androidTest/ConstantTimeMemcmpTest.kt` (production `sodium_memcmp` path) |

**Verification status: on-device VERIFIED on 2026-06-24** (working tree atop commit
`4059f92`), AVD `Medium_Phone_API_36.1` (Android 16 / API 36, x86_64), libsodium via
`lazysodium-android:5.1.0`. `./gradlew :app:connectedDebugAndroidTest` reported
`tests=9, failures=0, errors=0`: `nativeArgon2idMatchesKnownAnswer`,
`xchacha20_official_kat_a31` (+roundtrip/tamper/AAD/determinism), and the three
`sodium_memcmp` cases all passed. Each native KAT produced byte-identical output to the
published IETF/RFC vector AND to its JS counterpart's pinned constant.

Cross-impl equality (Argon2id, XChaCha20) is therefore established, not assumed: each
native KAT asserts the identical bytes its JS counterpart asserts, and both match the
published IETF/RFC vector. The constant-time guarantee is provided by the native
`sodium_memcmp` path (S7); the JS XOR fallback is asserted only for functional
correctness, and remains documented best-effort (M4), reached only when the native module
is absent.

### 13.2 Remaining coverage gaps

- **End-to-end JNI glue:** the KATs above pin the libsodium primitives and the JS glue
  separately. A single test that drives `RNFileVaultModule.encrypt/decrypt/argon2id`
  through the React bridge end-to-end still runs on-device only.
- **`HardwareKeystoreService`:** tested only indirectly (via BackupService). No unit test
  exercises its wrapper methods in isolation.

---

## 14. Threat Model (M5)

This chapter states explicitly who the protocol defends against, with what assumptions,
and what is out of scope. Absence of a threat model was itself a review finding.

### 14.1 Assets
Vault file content and notes (plaintext), file metadata (names/types), the master key,
the KEK, the Panic/Decoy PINs, and backup archives.

### 14.2 Attacker models

| # | Attacker | Covered? | Mechanism / residual |
|---|----------|----------|----------------------|
| A1 | **Lost/stolen device, locked** | **Yes** | Argon2id-64MiB KEK (m=64MiB,t=3,p=1), hardware-keystore-wrapped master key, rate-limit + auto-lock + wipe-on-N-fails, Panic PIN/decoy. Strength bounded by passphrase entropy → 12-char floor (H4). |
| A2 | **Passive at-rest / disk image** | **Yes** | All content is AEAD (XChaCha20-Poly1305) or AES-256-CBC + Encrypt-then-MAC, bound to object+role via AAD (H2). Plaintext metadata fields (id/size/createdAt) are non-secret. |
| A3 | **Filesystem tamper (swap/rollback/bit-flip)** | **Yes** | Bit-flip and cross-object/role blob swap are rejected (per-blob auth + `fileId/noteId:role` AAD, H2). Rollback to an OLDER version of the *same* id is now rejected too: a monotonic per-object version counter (SecureStore/Keystore-protected) is bound into the AAD as `id:role:vN`; a read rejects any blob whose version is below the stored floor (A3 — `BlobVersionService`). **Residual:** resurrecting a *deleted* object's old ciphertext at its original random id is out of scope (the attacker already possessed that ciphertext). |
| A4 | **Crash / power-loss** | **Yes** | Atomic temp+rename writes (H3) + startup `.tmp` cleanup; WAL + per-blob idempotent key rotation. |
| A5 | **Exfiltrated backup archive** | **Yes (KDF), by-design portable** | v3 backups use Argon2id (H1) + 12-char min passphrase. The archive is portable plaintext-under-backup-key by design; its whole security is the backup passphrase × Argon2id. |
| A6 | **Local malware / root, device UNLOCKED, app running** | **Partial** | `requireAuthentication` on the biometric KEK; iOS `WHEN_UNLOCKED_THIS_DEVICE_ONLY`. **Residual:** while unlocked, the master key lives in the JS heap (M2 mitigates the long-lived copy via a zeroable `Uint8Array`, but transient hex strings and an unlocked keystore key remain reachable). A root attacker with the screen unlocked is **not** fully defended. |
| A7 | **Cloud/OS backup compromise** | **Yes** | SecureStore values are bound to a non-exportable keystore key; iOS items are device-only. The app backup archive (A5) is the only cloud-relevant secret and is Argon2id-protected. |

### 14.3 Explicitly OUT of scope
- Side-channels: power/EM analysis, cache timing, Spectre. The JS `constantsTimeEquals`
  fallback is best-effort only; the native `sodium_memcmp` path is the timing-safe one (M4).
- Compromised OS / kernel exploit / TEE-StrongBox bypass / malicious firmware.
- Supply-chain compromise (malicious npm/Expo/Gradle dependency).
- Memory forensics of an unlocked, running process beyond the M2 mitigation.
- Coercion beyond the Panic-PIN/decoy mechanism.

### 14.4 Budget / timeline assumption
A6/A7 assume an attacker willing to run an offline GPU/ASIC farm against an exfiltrated
artifact (vault wrapper or backup). The 12-char passphrase floor (H4) + Argon2id-64MiB
are sized so that the search space stays infeasible at realistic guess rates for such an
attacker; a weak user passphrase voids this regardless of the KDF.

### 14.5 Backward-secrecy of key rotation (M1)
Key rotation (R-02) gives **forward protection**: after rotation, a *future* compromise
of the new master key does not reveal pre-rotation ciphertext under the old key. It does
**NOT** guarantee backward-secrecy on flash storage: re-encryption overwrites blobs in
place, but flash wear-leveling may retain old physical blocks. An attacker who later
obtains the OLD master key **and** performs raw-NAND forensic recovery could read
pre-rotation plaintext. Software cannot guarantee secure erase on flash; treat rotation
as protection against future key leakage, not as a secure wipe of old data.

---

## 15. Change Log — Audit Round 4

| ID | Severity | Fix |
|----|----------|-----|
| C1 | Critical | Argon2id salt unified to RAW bytes across native + hash-wasm; parallelism pinned to 1 (native libsodium forces lanes=1); `kdf_meta` tag detects encoding drift; cross-impl KAT (JS + on-device `androidTest`). |
| H1 | High | Backup KDF → Argon2id v3 (m=64MiB,t=3,p=1); v2 PBKDF2 still restorable; 12-char min backup passphrase. |
| H2 | High | fileId/noteId\:role bound as AAD into every content/metadata tag — blob swap across object or role is rejected. |
| H3 | High | Atomic temp+rename writes + startup `.tmp` cleanup for all vault/note blobs and rotation. |
| H4 | High | Passphrase floor raised to 12; settings slider 12–24; no-dependency strength meter on creation. |
| M2 | Medium | Long-lived master-key cache held as a zeroable `Uint8Array`, wiped on logout/reassign. |
| M3 | Medium | Best-effort hardware-keystore probe + one-time warning when only software keystore is likely. |
| M4 | Medium | `constantsTimeEquals` JS fallback documented as best-effort (not constant-time) + one-shot warning. |
| M5/M1 | Medium | This threat-model chapter + explicit backward-secrecy limitation. |

### Change Log — Audit Round 5

| ID | Severity | Fix |
|----|----------|-----|
| A3 | High | Monotonic per-object version counter (`BlobVersionService`, SecureStore/Keystore-protected) bound into the AAD as `id:role:vN`. Reads reject blobs below the stored floor → rollback to an older version of the same object is prevented. Threat-model A3 → "Yes". |
| FIX 2 | — | On-device `androidTest/XChaCha20BridgeTest.kt` exercises the real libsodium XChaCha20-Poly1305 JNI (roundtrip, tamper, AAD, determinism); gradle androidTest deps + `AndroidJUnitRunner` added. |

### Change Log — Audit Round 6

| ID | Severity | Fix |
|----|----------|-----|
| S1 | High | Panic PIN **and** Decoy PIN KDF moved from PBKDF2-10k to Argon2id (m=64MiB, t=3, p=1, len=32) via `Argon2idService` (native libsodium → @noble/hashes fallback, no silent PBKDF2 downgrade). A per-PIN `*_algo` marker is stored; legacy PBKDF2-10k hashes still verify and are transparently re-hashed to Argon2id on the next correct entry (migration path). §3.3 / §7.3 updated. |
| S3 | High | Closed the silent JS-crypto downgrade on the **content write path**. `encryptDataWith` now refuses to write with the AES-CBC+HMAC (0x02) fallback when the native module is absent, unless explicitly permitted (`NODE_ENV==='test'` or `global.__filevault_allow_js_crypto`, logged once). The read path for existing 0x02/0x03 blobs and the by-design AES-CBC key-wrapping path are unaffected. App.tsx sets the dev opt-in only under `__DEV__`. |
| S4/S7 | High | Added official-vector KATs: RFC 9106 Argon2id and IETF XChaCha20-Poly1305 draft §A.3.1 are pinned byte-for-byte in **both** the JS suite (`@noble/ciphers`/`@noble/hashes`) and the on-device `androidTest` (libsodium) — establishing native ↔ JS cross-impl byte-equality. `sodium_memcmp` pinned as the production constant-time path (`ConstantTimeMemcmpTest.kt`); the JS `constantsTimeEquals` fallback covered by `ConstantTimeEquals.test.ts`. Verified-primitive list in §13.1. |
| S2 | Medium | Backup passphrase floor raised to **≥12** (`BACKUP_MIN_PASSPHRASE`). Confirmed the backup **write** path is Argon2id v3 (m=64MiB,t=3,p=1); v2 PBKDF2 remains restore-only. |
| Rename | — | Misleading `FastAES` / `fastAESGCM*` names removed. `FastAES.ts`→`AesCbcHmac.ts` (`fastAesEncrypt/Decrypt`→`aesCbcEncryptRaw/Decrypt`); in `CryptoService` `BACKEND_FASTAES`→`BACKEND_AESCBCHMAC` (value **0x02 unchanged**), `fastAESGCMEncrypt/Decrypt`→`aesCbcHmacEncrypt/Decrypt`, `fastAESCBCEncrypt/Decrypt`→`aesCbcHmacWrapEncrypt/Decrypt`, `canUseFastAES`→`canUseAesCbcHmac`, internal `'fastaes'` tag→`'aescbchmac'`. Pure refactor: wire format and 0x01/0x02/0x03 prefix bytes are byte-identical. (The 0x03 `cryptoJSGCM*` mislabel was finished separately — see Round 6 finalisation below.) |

### Change Log — Audit Round 6 (finalisation)

| ID | Severity | Fix |
|----|----------|-----|
| S4-verify | High | The native KATs are no longer merely *written* — they were **run on-device and passed**. `./gradlew :app:connectedDebugAndroidTest` on AVD `Medium_Phone_API_36.1` (API 36, x86_64) reported `tests=9, failures=0, errors=0` (2026-06-24): native libsodium Argon2id `crypto_pwhash` == `c97f06cb…8f38`, XChaCha20-Poly1305 §A.3.1 == ct `bd6d…b52e`/tag `c087…cf49`, `sodium_memcmp` equal→0/differ→≠0 — each byte-identical to the published vector AND the JS counterpart. §13.1 status set to "on-device VERIFIED". |
| 0x03-rename | — | Finished the honest-naming pass: the Backend-0x03 legacy read path `cryptoJSGCMEncrypt/Decrypt` → `legacyCryptoJsCbcHmacEncrypt/Decrypt` (it is AES-CBC+HMAC, never GCM). Removed dead `GCM_IV_LENGTH` and all misleading "GCM" comments in the active crypto path (only "NOT GCM"/"formerly named" notes remain). Pure refactor; 0x03 wire format byte-identical, legacy 0x03 read still works (roundtrip test green). |
| TS-fix | — | `PanicService.triggerPanicAction` switch had unreachable `case 'decoy'`/`case 'all'` (TS2678) after `triggerAction` was narrowed to `'wipe' \| 'lock'`. Verified the narrowing was an **uncommitted working-tree change** (HEAD `4059f92` compiled clean), not pre-existing in the last commit and not from the S1 KDF edit. Removed the dead cases (load-time coercion already forced `wipe`/`lock`, so zero runtime change; decoy is reached via the decoy PIN). `tsc --noEmit` now passes with 0 errors. |
| CI | — | `.github/workflows/android-kat.yml` runs `connectedDebugAndroidTest` on a `reactivecircus/android-emulator-runner` emulator (primes the missing debug AARs, x86_64 ABI) so the on-device proof is re-verified automatically instead of manually. |
| Spec | — | §13/§13.1 updated: JS suite is **91 tests / 20 suites**; native verification status "on-device VERIFIED on 2026-06-24". |
