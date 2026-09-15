# Obscura FileVault

**A privacy-first, cryptographically secured file and note vault for Android.**

Obscura is an Android mobile application (built with React Native/Expo) that encrypts files and notes on-device using military-grade cryptography. It implements a sophisticated three-layer key hierarchy, Argon2id key derivation, XChaCha20-Poly1305 authenticated encryption, and multiple anti-forensic and anti-tampering features including a panic PIN for emergency data denial, decoy vault functionality, secure auto-lock, and atomic key rotation with crash recovery.

---

## What is Obscura?

Obscura FileVault is a **zero-knowledge encrypted storage** application designed for users who need to protect sensitive files and notes on their mobile devices. Unlike cloud-based vaults, all encryption and decryption happens on-device—the server never sees plaintext content or keys. The application is hardened against physical attacks (rooted devices, forensic tools), timing side-channels, and brute-force attacks through:

- **Multi-layered encryption** with hardware-backed key storage (where available)
- **Panic PIN**: a secret unlock code that triggers a convincing decoy vault, enabling you to hand over the device under duress without revealing the real vault
- **Anti-screen capture**: automatically obscures sensitive content when the app is backgrounded
- **Atomic key rotation**: safely re-encrypts all content under a new key with crash/power-loss recovery
- **Argon2id KDF**: memory-hard key derivation resistant to GPU-accelerated brute-force
- **Constant-time cryptography**: prevents timing leaks that could reveal whether a PIN is correct

### Stack

- **Languages:** TypeScript (66%), JavaScript (15%), Kotlin (15%), CSS, HTML, Java
- **Framework / Runtime:** Expo 54 + React Native 0.81.5 + React 19
- **Notable Libraries:**
  - `expo-secure-store`: hardware-backed key storage (Android Keystore)
  - `@noble/hashes`: pure-JS Argon2id fallback and HKDF-SHA256
  - `crypto-js`: AES-256-CBC and PBKDF2 encryption backends
  - `hash-wasm`: WebAssembly Argon2id (optimized JS fallback)
  - `expo-crypto`: CSPRNG and platform crypto primitives
  - `lazysodium-android`: native libsodium via JNI for production XChaCha20-Poly1305 and Argon2id

---

## How it's organized

```
Obscura/
├── src/
│   ├── components/       UI components (VaultMark, icons, FileViewer)
│   ├── screens/          AuthScreen (login), MainScreen (vault), FilesView, NotesScreen,
│   │                       NoteEditor, SettingsScreen
│   ├── services/         20+ service modules implementing crypto, file ops, security
│   ├── native/           TypeScript bridges to the Kotlin native modules — file crypto
│   │                       (RNFileVault), key custody (NativeKeyCustody), integrity (IntegrityNative)
│   └── fonts.ts + theme.ts   Custom Obscura fonts and dark-mode theme
├── android/              Android native bridge — Kotlin modules for file crypto
│                           (RNFileVaultModule.kt), native key custody (NativeKeyCustodyModule.kt,
│                           libsodium secure-memory backing), hardware keystore, integrity,
│                           device security
├── __tests__/            Jest unit tests covering crypto, KDF, WAL, backup, key custody,
│                           decoy vault, auto-lock, and more
├── __mocks__/            Mock implementations for secure-store, crypto, file-system (for testing)
├── App.tsx               Root component + app initialization
├── index.ts              Expo entry point + performance polyfill
├── app.json              Expo config (Android permissions, metadata)
├── package.json          Dependencies + test/build scripts
├── CRYPTO_PROTOCOL_SPEC.md   70 KB detailed cryptographic protocol specification
├── FINAL_REPORT_ROUND3.md    Production-readiness audit (2026-05-22); lists 8 new files, 12 fixes, 0 TS errors
├── L3_CUSTODY_AUDIT.md       Map of raw key locations in memory; phase 0 for hardware backing
├── SECURITY.md               Vulnerability reporting process + audit scope
├── RECOVERY_REPORT.md        Accounting of the 2026-09-14 branch-loss recovery + newly found gaps
└── .github/workflows/    CI for Android KAT verification + the host Jest/type-check suite
```

### How it fits together

**Startup flow:**
1. `App.tsx` initializes 10+ services (crypto, file manager, notes, auto-lock, panic service, backup, key rotation, etc.)
2. `AuthScreen` prompts for PIN/passphrase
3. If correct, `AuthScreen` runs **three parallel KDF checks** (real PIN + panic PIN + decoy PIN) via `Promise.all` to prevent timing leaks
4. On success, `MainScreen` is mounted with a locked master key in memory
5. User can import files/create notes—all encrypted with the master key before storage
6. On background, app clears caches and starts a 5-minute auto-lock timer

**Encryption flow (file content):**
```
User's passphrase
    ↓ [Argon2id KDF: 64 MiB, 3 iterations]
    ↓ (or PBKDF2-600k fallback if native unavailable)
KEK (Key Encryption Key) — 32 bytes, never persisted
    ↓ [AES-256-CBC-HMAC or native unwrap]
    ↓ (from SecureStore; wrapped master key)
Master Key — 32 bytes, in-memory only
    ↓ [XChaCha20-Poly1305 (native) or AES-256-CBC-HMAC (JS fallback)]
    ↓ (for each file/note)
Ciphertext → filesystem
```

**Key features:**
- **Three backend ciphers** (via 1-byte prefix): XChaCha20-Poly1305 (native, preferred), AES-256-CBC-HMAC (pure-JS), CryptoJS fallback
- **Panic PIN**: separate Argon2id KDF, same hardness as vault; when entered, decoy vault is shown instead
- **Atomic key rotation**: WAL (Write-Ahead Log) makes rotation crash-safe; resume after power loss or app crash
- **Memory safety**: `Uint8Array` zeroing on cache clear; in-memory keys never stringified to console logs
- **Secure delete**: files are cryptographically shredded (key destruction, not file overwriting)
- **Backup/restore**: portable encrypted backup bundles (Base64 JSON) with separate Argon2id key

---

## How to run it

### Prerequisites

- **Node.js 18+** and npm
- **Expo CLI**: `npm install -g expo-cli`
- **Android Studio** (for the Android emulator)
- **Kotlin/Android SDK** (if building the native Kotlin module; APK builds via EAS or local Gradle)

### Quick Start

```bash
# Install dependencies
npm install

# Run on Android emulator
npm run android

# Run on web (development preview, no native crypto)
npm run web

# Start Expo dev server (pick platform manually)
npm start
```

### Development Build (with native module)

```bash
# Requires EAS CLI (https://docs.expo.dev/eas-cli/)
eas build --platform android --profile preview

# Then install the APK on a device/emulator
```

### Run Tests

```bash
# Jest unit tests (crypto, KDF, WAL, backup, key custody, decoy vault, auto-lock, ...)
npm test

# Type-check TypeScript
npm run type-check

# Both of the above together
npm run verify

# Jest with a coverage report over src/services/
npm run test:coverage
```

### Key Build Scripts (in package.json)

| Script | Purpose |
|--------|---------|
| `npm start` | Start Expo dev server |
| `npm run android` | Run on Android emulator |
| `npm run web` | Run on web (no native crypto, pure-JS fallback) |
| `npm run type-check` | TypeScript check (should report 0 errors) |
| `npm test` | Jest host test suite |
| `npm run test:coverage` | Jest with coverage over `src/services/` |
| `npm run verify` | `type-check` + `test` |
| `postinstall` | Patches Expo FormData + performance logger for React Native compatibility |

Note: `npm run test:device` (on-device native `androidTest` suite) is referenced in this
project's audit history but is not currently defined as an npm script — running it means
invoking Gradle's `connectedDebugAndroidTest` task directly against a connected device or
emulator.

### Environment & Security Notes

- **No secrets required** — the app uses only on-device key storage (Android Keystore, Expo SecureStore)
- **DEV vs. PROD mode:**
  - `__DEV__` (Expo dev build): allows pure-JS crypto fallback for testing without native module
  - Production APK/IPA: requires native crypto module; writes fail if the module is missing (anti-downgrade protection)
- **Hardware-backed storage:** Keys are protected in the TEE (Trustzone Execution Environment) or StrongBox if available

---

## Architecture highlights

### Security Layers

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **L1: Screen Protection** | `FLAG_SECURE` (Android) + privacy overlay | Prevents screenshot/recents capture of vault content |
| **L2: IME Warning** | Device security check on launch | Warns if a third-party keyboard is active (can log keystrokes) |
| **L3: Hardware Keystore** | `expo-secure-store` → Android Keystore | Hardware-backed key storage (TEE/StrongBox when available) |
| **L4: In-Memory Zeroing** | `Uint8Array.fill(0)` + cache clear on lock/background | Prevents plaintext key residue in heap |
| **L5: Crypto-Shred on Wipe** | Master key destruction renders all ciphertexts unreadable | Permanent deletion even if bytes linger on flash |
| **L6: Decoy Vault Cache** | Separate cache key for decoy content | Prevents mixing real and decoy plaintext in memory |

### Cryptographic Primitives

- **KDF (Primary):** Argon2id (libsodium `crypto_pwhash`, m=64 MiB, t=3, p=1)
- **KDF (Fallback):** PBKDF2-SHA256 (CryptoJS, 600k iterations)
- **Symmetric (Primary):** XChaCha20-Poly1305 (libsodium, native)
- **Symmetric (Fallback):** AES-256-CBC + Encrypt-then-MAC (HMAC-SHA256)
- **Key Derivation:** HKDF-SHA256 (MAC key from master key)
- **Random:** CSPRNG via `expo-crypto` → `/dev/urandom` or `SecureRandom`

### Key Services

| Service | Responsibility |
|---------|-----------------|
| `SecureCryptoService` | Master key unwrap, content encrypt/decrypt, constant-time comparison |
| `KeyCustody` | Custody seam: every master/content key is addressed by an opaque handle, never passed around as a raw value. Backed by `NativeKeyCustody` (libsodium secure memory, on-device — the raw key crosses the JS/native bridge only once, at registration) or a JS-backed fallback used in tests/dev without the native module |
| `FileManager` | File import/export, storage layout, atomic writes |
| `NotesService` | Encrypted note CRUD, re-encryption on key rotation |
| `AutoLockService` | Configurable inactivity timeout, lock on background, operation-lock suppression during multi-step crypto ops (key rotation) |
| `PanicService` | Panic PIN verification, decoy vault activation |
| `DecoyVaultService` | Separate encrypted vault (activated by panic PIN) |
| `BackupService` | Create/restore portable encrypted backups |
| `KeyRotationService` | Atomic key rotation with WAL crash recovery |
| `ScreenProtectionService` | `FLAG_SECURE`, privacy overlay |
| `DeviceSecurityService` | IME check, hardware keystore assessment |
| `HardwareKeystoreService` | SecureStore wrapper, key storage hardening |

`XChaCha20CryptoService` still exists in `src/services/` but is a deprecated compatibility
shim (every method logs a warning and forwards to `SecureCryptoService`) — the services
above are where the real logic lives. On the native side, `NativeKeyCustodyModule.kt` /
`NativeKeyCustody.kt` (Kotlin) are the counterpart to `KeyCustody`/`NativeKeyCustody.ts`
above; see `L3_CUSTODY_AUDIT.md` for the full custody design.

---

## Notable features & guarantees

### Panic PIN & Decoy Vault

The **panic PIN** is a separate unlock code that, when entered, loads a **decoy vault** instead of the real one. This is useful under duress—you can hand over your device with the decoy vault active and deny knowledge of the real one.

- Panic PIN uses the same Argon2id hardness as the vault PIN (brute-force cost equivalent)
- Verification is constant-time (prevents "is this a panic or real PIN?" timing leak)
- Decoy content is stored and encrypted separately from real content

### Atomic Key Rotation

Rotating the master key is crash-safe via a WAL (Write-Ahead Log):

1. New master key is generated and wrapped with the old key
2. WAL is written to SecureStore
3. All file + note content is re-encrypted in-place (idempotent per-blob)
4. WAL is deleted after success
5. If interrupted, resumption after unlock completes the re-encryption

### NFC Normalization

Unicode characters can have multiple byte representations (e.g., "ü" as U+00FC or "u" + U+0308 combining diaeresis). Without normalization, users entering the same passphrase differently would derive different keys. The app normalizes all passphrases to NFC form before KDF.

### Backend Prefix Authentication

The first byte of every ciphertext identifies the backend (0x01 = XChaCha20, 0x02/0x03 = AES-CBC). This byte is **authenticated** as AEAD AAD (bound into the Poly1305 tag or folded into the HMAC) to prevent downgrade attacks.

### Secure Delete

On vault wipe, the app:
1. Clears all file data from disk
2. Deletes all notes
3. **Destroys the master key** (crypto-shred)
4. Any remaining ciphertext bytes become permanently undecryptable

---

## Quality & Testing

### Test Coverage

| Test Suite | Coverage |
|------------|----------|
| `PanicPIN.test.ts` | Panic/decoy PIN verification, timing resistance, KDF migration |
| `NFCNormalization.test.ts` | Unicode normalization equivalence |
| `KeyRotationWAL.test.ts` | Atomic rotation, crash recovery, WAL invariants |
| `CryptoRoundtrip.test.ts` | AES-CBC-HMAC round-trip, tamper detection |
| `BackupRoundtrip.test.ts` | Backup creation/restore, wrong passphrase rejection |
| `BackupContent.test.ts` | Full content backup/restore workflow |
| `XChaCha20Path.test.ts` | XChaCha20-Poly1305 (mocked native), emoji/CJK UTF-8 |
| `Argon2idReal.test.ts` | @noble/hashes Argon2id KAT verification |
| `A3Rollback.test.ts` | WAL version binding, note rollback rejection |
| `FsAtomic.test.ts` | Atomic file writes, temp cleanup |
| Plus Android on-device instrumented tests (crypto KATs, key-custody handle/parity, hardware keystore, bridge roundtrips — verified manually on-device on x86_64 + arm64) |

This table lists representative suites, not the full set — see `__tests__/` for the complete host test suite.

### Production Readiness

- ✅ **0 TypeScript errors** (strict mode enabled)
- ✅ **Full host test suite green**
- ✅ **Critical bug fixed:** Prefix-strip bug (all data was unreadable until Round 3 fix)
- ✅ **5 security bugs fixed:** Panic PIN timing, backup KDF, WAL handling, NFC normalization, unauthenticated prefix
- ⚠️ **5 known weaknesses** (all Medium/Low/Info severity, documented in `CRYPTO_PROTOCOL_SPEC.md` §10):
  - W-01: AES fallback MAC key derivation (fixed; separate key via HKDF)
  - W-02: Panic PIN PBKDF2 rounds (fixed; now Argon2id)
  - W-03: Backend byte unauthenticated (fixed; now AEAD AAD)
  - W-04: NFC normalization not enforced on native (documented; native callers handle it)
  - W-05: WAL staleness not enforced (logged; rotation completes regardless)

### Audit & Verification

- **FINAL_REPORT_ROUND3.md:** Complete accountability report (Phase 1 reality audit, Phase 2 fixes applied, Phase 3 quality gates) — dated 2026-05-22, predates the L3 native-custody work below
- **L3_CUSTODY_AUDIT.md:** Map of every point where the raw master key materialises in the JS heap; roadmap for Phase 1 hardware key custody
- **CRYPTO_PROTOCOL_SPEC.md:** 70 KB detailed cryptographic specification (threat model, primitives, wire formats, test coverage, known weaknesses)
- **SECURITY.md:** Vulnerability reporting process and audit scope
- **RECOVERY_REPORT.md:** Accounting of the 2026-09-14 branch-loss recovery — what was reconstructed, what's a documented gap, and standalone findings (N-series) turned up along the way

---

## Try asking

- **"How do I create a decoy vault?"**  
  Set a panic PIN in Settings. If you enter that PIN at login, the decoy vault opens instead. Create a decoy vault with dummy files so it looks convincing.

- **"What happens if I rotate the master key and the app crashes halfway?"**  
  The WAL (stored in SecureStore) captures the new key and the set of re-encrypted files. On next login, the app detects the incomplete rotation and resumes, finishing the re-encryption idempotently.

- **"How is the backup encrypted differently from vault content?"**  
  Backup uses a separate Argon2id-derived key from a user-supplied backup passphrase. This makes backups portable (independent of the vault master key) and useful for offline archival.

- **"Can I restore a backup on a different device?"**  
  Yes—the backup format is device-agnostic JSON. Restore is just a decryption + re-import step, so the content is re-encrypted under the current vault's master key on the target device.

- **"What if someone roots my device?"**  
  Hardware-backed key storage (Android Keystore) makes it harder, but not impossible, for an attacker to extract keys from a rooted device. The 64 MiB Argon2id KDF also makes brute-force expensive. See `L3_CUSTODY_AUDIT.md` for the roadmap to move the raw master key out of the JS heap entirely.

---

## License & Citation

This project implements cryptographic protocols. For academic/commercial use, please refer to `CRYPTO_PROTOCOL_SPEC.md` for the formal specification and verify the implementation against the documented invariants.

**Status:** Production-ready after Round 3 security fixes. Ready for independent cryptographic audit before wide release.
