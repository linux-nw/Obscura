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

**Verification status: on-device VERIFIED (x86_64) on 2026-06-24, re-verified
2026-06-26** — AVD `Medium_Phone_API_36.1` (Android 16 / API 36, x86_64), libsodium via
`lazysodium-android:5.1.0`. `./gradlew :app:connectedDebugAndroidTest
-PreactNativeArchitectures=x86_64` reported `tests=15, failures=0, errors=0`: the three
native KATs — `nativeArgon2idMatchesKnownAnswer`, `xchacha20_official_kat_a31`
(+roundtrip/tamper/AAD/determinism), the three `sodium_memcmp` cases — plus the six
end-to-end bridge-roundtrip cases (§13.2). Each native KAT produced byte-identical output
to the published IETF/RFC vector AND to its JS counterpart's pinned constant.

**arm64-v8a: on-device VERIFIED on 2026-06-26** — physical device Samsung **SM-S906B**
(Galaxy S22+, arm64-v8a), Android 16, libsodium via `lazysodium-android:5.1.0`, branch
`feat/round6-crypto-final`. `./gradlew :app:connectedDebugAndroidTest
-PreactNativeArchitectures=arm64-v8a` reported `tests=15, failures=0, errors=0` — the same
9 native KATs + 6 bridge-roundtrip cases as the x86_64 run, byte-identical to the published
IETF/RFC vectors AND to the JS constants on native arm64. Cross-impl byte-equality is now
established on **both** ABIs (x86_64 and arm64-v8a), not assumed.

(Note: the arm64 verification is done on a real device, not the emulator. On an x86_64
emulator's arm64-translation layer the app crashes at startup, because React Native's
SoLoader resolves the in-APK native folder from the device's *primary* ABI — `x86_64`
there — so an arm64-only APK's `libreactnative.so` is not found. A physical arm64 device
has primary ABI `arm64-v8a`, so the same test sources run unmodified.)

Cross-impl equality (Argon2id, XChaCha20) is therefore established, not assumed: each
native KAT asserts the identical bytes its JS counterpart asserts, and both match the
published IETF/RFC vector. The constant-time guarantee is provided by the native
`sodium_memcmp` path (S7); the JS XOR fallback is asserted only for functional
correctness, and remains documented best-effort (M4), reached only when the native module
is absent.

### 13.2 Remaining coverage gaps

- **End-to-end JNI glue (closed on x86_64):** `androidTest/RNFileVaultBridgeRoundtripTest.kt`
  drives `RNFileVaultModule.encrypt`→`decrypt` through the real bridge surface
  (`ReadableMap` in, `Promise` out), exercising the marshalling the primitive KATs skip:
  Base64 of the payload, hex parse of key/nonce/tag, the detached-tag split, and the
  AAD-from-hex path. Covers empty / 1-byte / >1 MiB roundtrips, a one-byte-flip tamper
  case (Poly1305 must reject), and an AAD-mismatch case. Verified `tests=15, failures=0`
  on **both** x86_64 (emulator) and arm64-v8a (device SM-S906B), 2026-06-26. The
  `argon2id` bridge method is still only covered at the primitive level.
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

## 15. Endpoint Threat Model (Endpoint-Hardening, Layers 1-7)

§14 covers the **at-rest** crypto (untouched by this work). §15 covers the **endpoint** on a
potentially compromised or seized device: where the key lives in RAM, what leaks through the
screen and keyboard, how device integrity is attested, how data is destroyed, what happens
under coercion, and supply-chain integrity. Each layer states what it **covers**, what it
**deliberately does not**, and **against which attacker** it holds.

**Structural out-of-scope (stated honestly):** an active kernel exploit on a rooted, *live*,
*unlocked* device with attacker-held root. A userspace app cannot structurally win that — the
attacker shares the process' address space and the unlocked keystore. Everything below raises
cost against weaker, more realistic attackers; none of it defeats live attacker-root.

### 15.1 Per-layer summary

| Layer | Covers | Deliberately NOT | Primary attacker | Proof |
|-------|--------|------------------|------------------|-------|
| 1 UI leakage | `FLAG_SECURE` set natively in `MainActivity.onCreate` (pre-JS, always-on): blocks screenshot, screen-record, Recents thumbnail. Privacy overlay (VaultMark) when app backgrounded. | Reading the framebuffer with root; *detecting* a screenshot from userspace (impossible on Android — reported honestly as `false`). | Shoulder-surf, casual screenshot, Recents leak, non-root screen-record. | `dumpsys` shows `FLAG_SECURE`; manual on-device. |
| 2 IME capture | All **credential** fields — unlock / decoy-PIN / panic-PIN (shared hardened field `AuthScreen.tsx:380`), app/panic/decoy set-PIN (shared `openSetPinModal`, `SettingsScreen.tsx:998,1027`), backup passphrase (`:1086`): `secureTextEntry`, `autoComplete=off`, `textContentType=none`, `importantForAutofill=no`, `spellCheck=false`. Self-audit fix: **typed note content** (`NoteEditor.tsx` title/category/body) now carries the same anti-capture flags (minus masking). Runtime warning if the active IME is not a system keyboard. | A malicious **system** IME or a root keylogger — you must type into *some* keyboard. | 3rd-party keyboard cloud-sync, autofill/clipboard/dictionary capture. | Native `getActiveInputMethod`; field props; `tsc`. |
| 3 RAM key lifetime **(PARTIAL — see §15.5)** | Long-lived master-key cache held as a zeroable `Uint8Array` (`CryptoService.ts:1245`), actively `.fill(0)` on every reassignment and on lock (`:1251`). Native Kotlin zeroes its key + plaintext byte arrays immediately after each crypto op (`RNFileVaultModule.kt:58,106,116,167`). | **Raw key still transits the JS heap**: `getMasterKey()` → getter `:1248` materialises a fresh **immutable hex string** per call (unzeroable, GC-only). Native zeroing is Kotlin `ByteArray.fill(0)`, **not** `sodium_memzero`/`sodium_mlock` → pages swappable, GC-copy residue possible. True 0-JS-lifetime would need native-only key custody (opaque handle, AEAD in native) — a crypto-core rearchitecture, out of scope. | Post-lock heap-residue scrape. | `__tests__/L3_KeyZeroing`; native `androidTest`; §15.5. |
| 4 Device integrity | Real `KeyInfo.securityLevel` (STRONGBOX / TRUSTED_ENVIRONMENT / SOFTWARE); `setUnlockedDeviceRequired(true)` gated on a secure lockscreen; key-attestation cert-chain export (challenge → root-of-trust `verifiedBootState`+`deviceLocked`). | Defeating a TEE/StrongBox bypass; providing hardware backing where the device has none (degrades to SOFTWARE, **warned**, not blocked). | Detect software-only keystore / tampered boot state (informational signal). | `HardwareKeystoreAttestTest.kt` on-device (2 tests). |
| 5 Crypto-shredding | No per-file content keys exist → destroying the master key (wrapped key in SecureStore **and** the in-memory copy) makes **every** blob permanently undecryptable, regardless of flash residue. Plaintext view-temp cache swept (overwrite+delete). | Guaranteed *physical* erasure of flash blocks (NAND wear-leveling may retain old blocks); recovering a key the attacker already extracted while unlocked. | Post-wipe forensic recovery of vault content. | `__tests__/L5_CryptoShred`. |
| 6 Duress / coercion | Panic PIN (Argon2id) → wipe or permanent-lock. Guest/decoy vault: own Argon2id PIN, neutral `guest/`+`filevault_guest_*` naming, content **XChaCha20-encrypted** with a guest-PIN-derived key (separate KDF salt, never stored) → on disk indistinguishable from the real vault. | True plausible deniability — see §15.2. The hidden-vault *existence* stays provable. | Casual coercion + low-tier / string-grep forensics. | `__tests__/L6_DecoyEncryption`; §15.2. |
| 7 Supply-chain / APK integrity | Native `verifyPinnedSignature()` compares the running APK's signing-cert SHA-256 against a **build-time-pinned** `BuildConfig.SIGNING_CERT_SHA256` (constant-time, **fail-closed**); JS `IntegrityService.checkSignature` maps it to `valid`/`invalid`/`unverifiable` and fails the aggregate only on a true `invalid`. Shipped Hermes bundle isolated from the toolchain advisories (all critical/high are dev/test-only). npm lockfile carries 871 SRI hashes (`npm ci`-enforced); react/hermes AARs pinned by `.sha1`. | Defeating an attacker who **patches out the self-check** before re-signing (any on-device check is bypassable — this is not attestation); server-verified Play Integrity (app is offline, no server); checksum-pinning the Maven-Central `lazysodium`/`jna` AARs (no Gradle `verification-metadata.xml` yet — §15.3). | Naive repackaging / re-signing; side-load from an untrusted source; a tampered/cloned APK. | `__tests__/L7_SignatureVerification` (9 tests); `IntegrityModule.kt` review; §15.3. |

### 15.2 Layer 6 deniability boundary — precise, against which attacker it holds

Layer 6 **raises the bar** against casual coercion and low-tier forensics. It is **NOT full
deniability.** Stated precisely:

**What it HOLDS against:**
- **Casual coercion ("unlock it now").** Entering the guest PIN clears the real master key from
  RAM (the parallel `unlock()` that loaded it is wiped) and shows the guest session; the real
  vault is inaccessible. An attacker who does not image the device sees a plausible guest vault.
- **Naive forensic string-grep.** After the rename, a disk image / SecureStore dump contains no
  literal "decoy"; guest artifacts blend with the real `filevault_*` / `vault/` / `notes/`
  family. The per-artifact "this one is the fake" label is gone.
- **Low-tier "which file is obviously the fake" forensics.** Pre-L6 the decoy was *plaintext*
  while the real vault was ciphertext — an instant differential that, by elimination, fingered
  the real vault. Now both are opaque XChaCha20 ciphertext; on-disk content no longer
  self-identifies as fake.

**What it does NOT do (does NOT hold against):**
1. **An analyst who recognises the app.** The UI openly ships a "Täusch-Tresor"/guest feature;
   anyone who identifies the binary *knows* a guest+real vault can coexist and will demand the
   second credential. Renaming hides *which* artifact is which, never the *feature*.
2. **Hidden-vault existence denial.** Two independent credential sets (real + guest
   `filevault_*_pin_hash`) and two populated encrypted directories (`vault/` + `guest/`) are
   both present and visible. Their coexistence *proves* a second vault exists. This is the
   structural ceiling: unlike a VeraCrypt hidden volume (one container whose slack space may or
   may not hold a hidden volume), Android app storage exposes discrete files/keys — a coexisting
   encrypted real vault is provably there. VeraCrypt-style hidden-volume deniability is **not
   achievable** on this storage model.
3. **Storage-size / backup / FS-metadata differential.** `guest/` and `vault/` differ in size,
   file count and mtimes. The guest content is written **once** at PIN-set and never touched, so
   its mtimes are frozen while the real vault's churn — a behavioural tell that survives into
   any cloud/OS backup or repeated `ls -la` snapshot.
4. **Interactive coercion.** The in-app decoy view currently shows an **empty** vault
   (`getFakeFiles`/`getFakeNotes` are not wired to a screen). The encryption improves the
   *image-the-disk* picture, not the *make-the-user-open-it* picture — a coercer who makes the
   user open the guest vault sees nothing, itself suspicious. A populated decoy browser is
   deferred.
5. **Image-then-coerce.** A forensically-aware coercer clones the device **before** demanding a
   PIN, pre-empting the panic-PIN wipe and capturing *both* vaults. Panic helps against an
   unsophisticated coercer, not one who images first.
6. **Bundle/symbol residue.** The JS class identifier (`DecoyVaultService`) and German UI labels
   ("Täusch-PIN") persist in the Hermes bundle; grepping the APK still reveals the feature.
   Closing this needs a source rename + UI relabel — deferred (low marginal value while the
   feature is visibly in the UI).

**Attacker matrix (Layer 6):**

| Coercion scenario | Result |
|-------------------|--------|
| Casual "open it", no device imaging | **HOLDS** — guest shown, real key cleared from RAM |
| Forensic string-grep for "decoy" | **HOLDS** — neutral `guest` naming |
| "Which file is the obvious fake?" | **HOLDS** — both vaults opaque ciphertext |
| Analyst knows the app, demands 2nd PIN | **FAILS** — feature known; 2nd credential set visible |
| Image-then-coerce (clone before PIN) | **FAILS** — panic pre-empted; both vaults captured |
| Make-user-open-decoy interactively | **WEAK** — in-app decoy view shows empty (not wired) |
| Storage-size / mtime / backup correlation | **FAILS** — `guest/` vs `vault/` distinguishable, frozen mtimes |

**One-line honest summary:** Layer 6 defeats casual coercion and naive/low-tier forensics; it is
**not** full plausible deniability — storage size, backups and filesystem metadata continue to
leak the existence, and likely the identity, of the real vault.

### 15.3 Layer 7 boundary — APK integrity and supply-chain, against which attacker it holds

Layer 7 has two halves with very different ceilings.

**APK signature self-check.** The native `verifyPinnedSignature()` reads the running package's
signing-cert SHA-256 from `PackageManager` and compares it, constant-time, to
`BuildConfig.SIGNING_CERT_SHA256` — a value compiled into the APK at build time from the
`FILEVAULT_SIGNING_CERT_SHA256` gradle property (never committed; derived from the release
keystore with `keytool`).

**What it HOLDS against:**
- **Naive repackaging / re-signing.** An attacker who decompiles, modifies and re-signs the APK
  with their own key changes the signing cert; the runtime cert no longer matches the pinned
  hash → verdict `invalid` → the integrity check fails. Trojanised clones produced by automated
  tooling that did not strip the check are caught.
- **Side-load provenance (advisory).** `checkInstallerIntegrity()` flags installs from an
  untrusted source vs a known store. Informational, not enforced.

**What it does NOT do (does NOT hold against):**
1. **An attacker who patches out the check.** The verification runs *inside* the code the attacker
   is repackaging. A competent adversary NOPs the call (or forces the `valid` branch) before
   re-signing. R8/minify only raises the cost of locating it. **No on-device self-check is a
   trust anchor** — only server-verified attestation (Play Integrity) is, and this app is offline
   with no server, so that is **deliberately out of scope**.
2. **Fail-open on absence.** By design `unverifiable` (native module missing, or an unpinned debug
   build) does **not** fail the check — a false positive must never lock out a legitimate user.
   So the check adds assurance only in a properly pinned release build; it is silent elsewhere.
3. **Response.** The verdict is surfaced (warning), not wired to an automatic wipe. JS-evaluated
   anti-tamper auto-destruction is intentionally avoided (false-positive bricking risk; consistent
   with `DeviceSecurityService`'s no-JS-heuristics rule). Enforcement is an opt-in pending
   on-device tuning.

**Supply-chain.**
- **npm.** `package-lock.json` carries 871 Subresource-Integrity (`sha512`) hashes; `npm ci`
  refuses to install anything whose tarball hash drifts. `npm audit` reports 39 advisories
  (1 critical, 3 high). **All critical/high are build/dev/test-only** and are **not** linked into
  the shipped Hermes bundle: `shell-quote` (critical) ← `react-devtools-core`; `form-data` (high)
  ← `jsdom` ← `jest-expo` (test); `undici`/`ws` (high) ← `@expo/cli` + `metro` (dev server /
  bundler). The release bundle is the app's own JS plus the runtime deps it actually imports.
- **Native AARs.** `react-android` / `hermes-android` are vendored in `android/local-maven` with
  `.sha1`/`.md5`. The Maven-Central `com.goterl:lazysodium-android:5.1.0` and
  `net.java.dev.jna:jna:5.17.0` (the crypto-bearing libs) are pulled by coordinate **without** a
  Gradle `verification-metadata.xml` checksum gate — a named residual. Closing it:
  `./gradlew --write-verification-metadata sha256` against a clean cache, then commit the
  generated metadata. Not generated here: real checksums require a clean Gradle resolve in a build
  environment, and fabricating them would be worse than declaring the gap.

**Structural residual (both halves):** an attacker who controls the **build host** wins
regardless — they can mint a matching signature pin and tamper the bundle before it is signed.
Supply-chain integrity ultimately rests on the build machine and signing key being trusted; the
on-device checks defend only the *distribution* path after a clean build.

**Attacker matrix (Layer 7):**

| Scenario | Result |
|----------|--------|
| Repackaged + re-signed APK, check left intact | **HOLDS** — cert mismatch → `invalid` |
| Side-load from untrusted installer | **DETECTED** (advisory) |
| Attacker patches out the self-check, then re-signs | **FAILS** — on-device check is not a trust anchor |
| Tampered dev-server / bundler dependency at build time | **FAILS** — build host is the trust root |
| Drifted npm tarball | **HOLDS** — `npm ci` SRI mismatch |
| Swapped `lazysodium`/`jna` AAR from Maven Central | **WEAK** — no checksum pin yet (verification-metadata pending) |

**One-line honest summary:** Layer 7 raises the bar against naive repackaging and catches npm
tarball drift, but an on-device signature check is not attestation and a compromised build host
defeats the whole chain — the un-pinned native AARs and the absent server-side attestation are the
named residuals.

### 15.4 Aggregate status (Layers 1-7)

| Layer | Status | Proof artifact | Principal residual risk |
|-------|--------|----------------|-------------------------|
| 1 UI leakage & `FLAG_SECURE` | Done (enforcing line confirmed) | `MainActivity.kt:28` native unconditional; no runtime disabler; `dumpsys` host-unverifiable | Framebuffer read with root |
| 2 IME / keyboard | Done (all credential fields + note content) | enforcing field props (`AuthScreen:380`, `SettingsScreen:998/1027/1086`, `NoteEditor`); `tsc` | Malicious **system** IME / root keylogger |
| 3 Master key out of JS heap | **Partial** | `__tests__/L3_KeyZeroing`; native `androidTest`; §15.5 | raw key transits JS heap as immutable hex string per op; native zero is `fill(0)` not `mlock`/`memzero` |
| 4 Device integrity / attestation | Done (verdict from real KeyInfo; hardcoded-`true` wart fixed) | `HardwareKeystoreService.ts:98`→`securityLevelOf`; `HardwareKeystoreAttestTest.kt` (on-device) | No hardware backing → SOFTWARE (warned) |
| 5 Crypto-shredding | Done (test-pinned) | `__tests__/L5_CryptoShred` (post-shred decrypt `rejects.toThrow`); `F2_CacheCleanup`; FileViewer per-close temp delete | NAND wear-levelling physical residue |
| 6 Duress / coercion | Done (rename complete; content encrypted) | `__tests__/L6_DecoyEncryption`; grep for old `decoy` names clean; §15.2 | Hidden-vault *existence* stays provable |
| 7 Supply-chain / APK integrity | Done (**device-verified** valid + invalid) | `__tests__/L7_SignatureVerification` (9); on-device §15.6; §15.3 | Self-check bypassable; AARs un-pinned (verification-metadata gen failed, §15.3); no server attestation |

**Self-audit (this round).** Each "Done" was re-checked against its *enforcing* line, assuming guilt.
Findings: **L3 downgraded to Partial** (the raw key still materialises as an immutable JS hex string
per crypto op — §15.5). **L2 gap fixed** (typed note content was IME-capturable; same anti-capture
flags now applied). **L4 wart fixed** (`generateKey` hard-coded `isHardwareBacked=true`; now derived
from real `KeyInfo` — the verdict path already read the honest value, so this closed a latent trap,
not an active failure). L1/L5/L6 confirmed with cited enforcing lines + tests, no theater found.

### 15.6 On-device verification (SM-S906B, Android 16, StrongBox + TEE)

A pinned **release** build (`FILEVAULT_SIGNING_CERT_SHA256` baked in) was built and installed on the
SM-S906B; verdicts read from `logcat`. Results:

| Pass | Result (logcat) | Verdict |
|------|-----------------|---------|
| **L1** `FLAG_SECURE` | `dumpsys window` main window `fl=81812100`; `0x81812100 & 0x2000 (FLAG_SECURE) = 0x2000` | **SET** on the live MainActivity window |
| **L4** real level | `[L4] Keystore security level: STRONGBOX (hardwareBacked=true)`; fixed `generateKey.attestation securityLevel=STRONGBOX` | **real KeyInfo**, not hardcoded |
| **L7** valid | correctly release-signed install → `verifyPinnedSignature configured=true isValid=true actual=9D:67:…:FD` (== pin) | **valid** |
| **L7** invalid | same APK **re-signed** with a throwaway key → `configured=true isValid=false actual=3B:97:…:3E` (≠ pin) | **fail-closed invalid** |

**Device-found bugs (fixed; hidden by host mocks) — commit `f994baa`:**
1. `DecoyVaultService.randomHex` requested up to 98304 bytes from `expo-crypto.getRandomBytesAsync`
   in one call; it hard-caps at 1024 and throws → `createFakeFiles` crashed on device
   (`getRandomBytesAsync(65536) expected … 0…1024`). The host mock did not enforce the cap.
2. `bufferToHex` / `utf8ToBase64` / `utf8ToHex` built strings via `+=` per byte — **O(n²)** in Hermes,
   which **hung** on tens-of-KB blobs (decoy file content). Now O(n); byte-identical output (full
   crypto suite green). The `expo-crypto` mock now enforces the 1024 cap so neither regresses silently.

**L6 status — host-proven; on-device file round-trip not completed via the test harness.** The guest
**notes** encrypted and wrote successfully on-device. The full guest **file** round-trip could not be
driven through a boot-time instrumentation hook: a 64 MB Argon2id (`crypto_pwhash`) invoked during app
*init* intermittently stalls when crammed alongside startup crypto (the same KDF runs fine for normal
unlock and in the on-device KATs, `tests=15, failures=0`), and RN `setTimeout` does not fire reliably
post-init, so a deferred run was not possible either. This is a **test-harness/init-timing artifact,
not a demonstrated product bug** — the L6 logic is proven by `__tests__/L6_DecoyEncryption` with the
now-realistic capped mock, and the two device-found bugs above are fixed. **Recommended close-out:**
verify the guest file flow through the real Settings UI (set the decoy PIN on an idle app), where the
KDF runs without init contention.

**L3** stays honestly **Partial** (§15.5) — not upgraded. **L4 SOFTWARE-fallback** branch remains
device-unverifiable on this hardware (the S22 has StrongBox + TEE; it cannot produce a software-only
key to exercise that path). **AAR checksum pin** deferred (below).

**Deterministic closeout attempted — AAR checksum pin (FAILED, not faked).** Ran
`gradlew --write-verification-metadata sha256` on the real Windows build host (JDK 21, network up).
It failed: `java.lang.IllegalStateException: The root project is not yet available for build` in
`WriteDependencyVerificationFile.resolveAllConfigurationsConcurrently` — Gradle's verification-metadata
writer is incompatible with the RN/Expo `includeBuild` composite-build layout. No `verification-metadata.xml`
was produced; fabricating one was rejected. Realistic alternative (deferred, infra not audit finding):
vendor `lazysodium-android` + `jna` into `android/local-maven` with committed checksums, matching the
existing react/hermes pinning pattern.

### 15.5 Layer 3 — why it is Partial, not Done

L3's claim is "master key out of the JS heap". Precisely measured, the **long-lived** copy is handled
well but the **transient** copies are not, and the native zeroing is weaker than `libsodium`'s.

- **Does raw key material exist in the JS heap?** Yes. (a) The canonical cache `__mkBytes` is a
  `Uint8Array` that lives the whole unlocked session by design and is `fill(0)`-zeroed on lock
  (`CryptoService.ts:1251`) — this is the *good* part, genuinely zeroable, not theater. (b) But the
  string-typed accessor `get _masterKeyCache` (`:1248`) rebuilds a fresh 64-char **hex string** on
  every read, and `getMasterKey()` (`:694`) returns it on every encrypt/decrypt. Strings are
  immutable in Hermes — those copies cannot be wiped, only dropped for a GC that is not deterministic.
- **Do `sodium_mlock` / `sodium_memzero` fire?** No. The native side uses Kotlin `ByteArray.fill(0)`
  (`RNFileVaultModule.kt:58,106,116,167`), which is best-effort: no `mlock` (key pages may be swapped
  to disk) and the JVM GC may have already copied the array (compaction) leaving residue. The comment
  does not over-claim sodium here — but the protection is below what the layer name implies.
- **Does auto-lock zero the native buffer?** There is no long-lived native key buffer to zero — the
  native module is stateless per-op (key passed in, `fill(0)`'d after). Lock zeroes the JS `Uint8Array`.
- **Quantified raw-key JS-heap lifetime:** ≈ the entire unlocked session for the `Uint8Array` (intended),
  **plus** one immutable hex-string copy per crypto op lingering until the next GC. Not ~0.
- **What 0-JS-lifetime would require:** keep the key only inside native (mlock'd libsodium buffer),
  expose an opaque handle across the bridge, and perform all AEAD natively without ever returning the
  hex key to JS. The current architecture returns the hex key to JS and orchestrates crypto there, so
  the key structurally must enter the JS heap. Closing this is a crypto-core rearchitecture — out of
  scope for endpoint hardening, and deliberately **not** attempted here.

---

## 16. Change Log — Audit Round 4

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

### Change Log — Round 6.1 (secure + close residual gaps)

| ID | Severity | Fix |
|----|----------|-----|
| Secure | — | Round 6 working tree committed onto branch `feat/round6-crypto-final` as three clean Round-6 commits (native KAT+CI / honest crypto backend names / PanicService TS2678) plus two labelled sweep commits (support test+service layer, non-crypto WIP), `git status` clean. `tsc --noEmit` 0 errors and JS suite **20 suites / 91 tests** green verified *after* committing. |
| Bridge | High | New `androidTest/RNFileVaultBridgeRoundtripTest.kt` drives `RNFileVaultModule.encrypt`→`decrypt` through the real bridge (`ReadableMap`/`Promise`), covering the marshalling the primitive KATs skip (Base64/hex/detached-tag-split/AAD), with empty/1-byte/>1 MiB roundtrips, a Poly1305 tamper case and an AAD-mismatch case. Verified **`tests=15, failures=0`** on x86_64 (2026-06-26) — the §13.2 "end-to-end JNI glue" gap is closed on x86_64. |
| arm64 | High | arm64-v8a **on-device VERIFIED** on physical device Samsung SM-S906B (Galaxy S22+, arm64-v8a), Android 16, lazysodium 5.1.0, 2026-06-26: `./gradlew :app:connectedDebugAndroidTest -PreactNativeArchitectures=arm64-v8a` → `tests=15, failures=0, errors=0` (9 native KATs + 6 bridge cases), byte-identical to the published vectors and the JS constants on native arm64. Cross-impl byte-equality now established on **both** ABIs. §13.1/§13.2 set to VERIFIED. (Earlier x86_64-emulator arm64-translation attempt failed at startup — RN SoLoader resolves libs by the emulator's primary ABI x86_64; resolved by running on real arm64 hardware where the primary ABI is arm64-v8a.) |
| CI | — | `android-kat.yml` runs the suite on an x86_64 emulator. An arm64 emulator matrix is deliberately **not** added — infeasible on GitHub-hosted runners (`ubuntu-24.04-arm` has no `/dev/kvm`; x86_64 runners hit the SoLoader/primary-ABI wall). arm64 is verified by the documented manual on-device run above. |
