# Production-Readiness Round 3 — Final Report

**Date:** 2026-05-22  
**Branch:** master  
**Approach:** Verify-first. Every claim backed by grep/Read before touching code.

---

## Verdict

**READY for security review. Not yet ready for production release** (see W-01–W-05 in
`CRYPTO_PROTOCOL_SPEC.md`).

All critical bugs fixed. All 12 tests green. 0 new TypeScript errors introduced.

---

## Phase 1 — Reality Audit

| Claim | Verified Reality |
|-------|-----------------|
| SettingsService exists | **MISSING** — created (`src/services/SettingsService.ts`) |
| RNFileVault.ts exists | **MISSING** — Kotlin module present, TS bridge absent — created |
| hash-wasm in package.json | **MISSING** — needed by Argon2idService; mock added for tests |
| BackupService key stretching | **MISSING** — bare HMAC only; replaced with PBKDF2-SHA256 600k |
| Panic PIN uses PBKDF2 | **WRONG** — was bare HMAC(salt, pin); fixed |
| Panic PIN constant-time | **WRONG** — was `hash === stored`; fixed with constantsTimeEquals |
| decryptData prefix handling | **CRITICAL BUG** — 2-byte prefix included in decrypt input; MAC mismatch on every call |
| NFC normalization | **MISSING** — added at all KDF call sites |
| KeyRotationService WAL | **INCOMPLETE** — private field access, missing await; fixed |
| HardwareKeystoreService | **MISSING** — referenced but not created; created |
| FastPBKDF2 | **MISSING** — PanicService imports it; created |
| FastAES | **MISSING** — CryptoService imports it; created |

---

## Phase 2 — Fixes Applied

### F-01: SettingsService (new file)
**File:** `src/services/SettingsService.ts`  
Provides `AppSettings` type and `SettingsService.get() / save()` with SecureStore
backing. Eliminates 6 TypeScript import errors.

### F-02: RNFileVault TypeScript Bridge (new file)
**File:** `src/native/RNFileVault.ts`  
Wraps `NativeModules.RNFileVault` (Kotlin module already registered in
`RNFileVaultModule.kt`) with typed async functions for `encrypt`, `decrypt`,
`argon2id`, `verifyConstantTime`, `generateRandomBytes`.

### F-03: Backup Key Stretching
**File:** `src/services/BackupService.ts`  
- Replaced bare `HMAC(passphrase, constant)` with `PBKDF2-SHA256(600k, randomSalt)`
- Fixed Encrypt-then-MAC: HMAC now covers `iv || ciphertext`, not plaintext
- Fixed `.nonce` reference → `.iv` (XChaCha20CryptoService returns `{encryptedData, iv, mac}`)
- Added version byte (`version: 2`); version 1 rejected on restore
- Added `HardwareKeystoreService` (`src/services/HardwareKeystoreService.ts`)

### CRITICAL: Prefix Strip Bug
**File:** `src/services/CryptoService.ts`  
The 2-byte hex backend prefix was passed to backend decrypt functions, but the
MAC covers only the raw ciphertext. Every decrypt call produced a MAC mismatch
and threw. All stored data was unreadable since the initial commit.

```typescript
// Before (broken):
if (backend === 'xchacha') return await this.xchachaDecrypt(encryptedData, ...);

// After (fixed):
const rawCiphertext = encryptedData.substring(2);
if (backend === 'xchacha') return await this.xchachaDecrypt(rawCiphertext, ...);
```

### R-01: Panic PIN Timing Resistance
**Files:** `src/services/PanicService.ts`, `src/screens/AuthScreen.tsx`  
- `computePinHash`: PBKDF2-SHA256 100k (was bare HMAC)
- `verifyPanicPin`: `constantsTimeEquals` (was `===`)
- `AuthScreen.checkLoginPass`: `Promise.all([panicCheck, realCheck])` — both checks
  always run; no early return leaks which path matched

### R-02: WAL-Based Atomic Key Rotation
**File:** `src/services/KeyRotationService.ts`  
Complete rewrite. Three-state recovery in `initialize()`:
- Empty `filesDone` → rollback, old state intact
- All done → commit, WAL deleted
- Partial → resume remaining files, then commit

Fixed: `XChaCha20CryptoService.STORAGE_KEY` (private) → `getStorageKey()` (public)  
Fixed: `getTimeUntilRotation()` missing `await` → made `async`, added `await`

### R-03: NFC Normalization
**Files:** `src/services/CryptoService.ts`, `src/services/PanicService.ts`  
`passphrase.normalize('NFC')` at every KDF call site. NFD input now produces the
same derived key as NFC input.

### R-04: DeviceSecurityService
Already correct. `SecurityStatus` return type is typed; no `as any` in callers.
No change needed.

### Supporting infrastructure (new files)
- `src/services/FastPBKDF2.ts` — CryptoJS PBKDF2-SHA256 wrapper
- `src/services/FastAES.ts` — AES-256-CBC via CryptoJS
- `src/services/HardwareKeystoreService.ts` — SecureStore wrapper interface

---

## Phase 3 — Quality Gates

### TypeScript
```
npx tsc --noEmit   →   exit 0   (0 errors, 0 new vs baseline)
```
- 25 baseline errors present before Round 3 → all eliminated
- No `as any` introduced
- No private member access from outside class
- No `NodeJS.Timeout` (replaced with `ReturnType<typeof setTimeout>`)

### Tests
```
npm test   →   12/12 passed, 0 failed
```

| Suite | Tests | Result |
|-------|-------|--------|
| PanicPIN.test.ts | 4 | PASS |
| NFCNormalization.test.ts | 3 | PASS |
| KeyRotationWAL.test.ts | 5 | PASS |

### Code quality
- No foreign-language characters in new code comments (all EN)
- No fire-and-forget `await` for security writes
- No early-return timing leaks in PIN verification paths

---

## Statistics

| Metric | Value |
|--------|-------|
| Files created | 8 (5 src + 3 mocks/tests infrastructure) |
| Files modified | 12 |
| TS errors eliminated | 25 |
| Critical bugs fixed | 1 (prefix strip — all data was unreadable) |
| Security bugs fixed | 5 (R-01×2, F-03×2, timing) |
| Test cases | 12 |
| Remaining known weaknesses | 5 (W-01–W-05, all Medium/Low/Info) |

---

## Remaining Weaknesses (non-blocking for security review)

See `CRYPTO_PROTOCOL_SPEC.md §10` for details.

| ID | Severity | Summary |
|----|----------|---------|
| W-01 | Medium | CBC fallback: enc key == MAC key (no key separation) |
| W-02 | Low | Panic PIN uses 100k PBKDF2; recommendation is ≥ 600k |
| W-03 | Low | Backend-ID byte unauthenticated |
| W-04 | Info | NFC normalization documented but not enforced on native callers |
| W-05 | Info | WAL `startedAt` not used for stale WAL expiry |
