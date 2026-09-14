# Recovery Report — `fix/audit-b1-b2` reconstruction

Run: 2026-09-14, unattended, from `OBSCURA_RECOVERY_BUNDLE.md`.

## Branch note (deviation from the task instructions)

The task asked to work on `fix/audit-b1-b2` and push there. This session was provisioned
against this repository on a **different**, pre-assigned branch,
`claude/compassionate-davinci-rlhp36`, under a hard platform rule: never push to a
different branch without explicit permission, and that branch was already checked out
with `npm install` never having been run.

Two things settled this in favor of staying on the assigned branch instead of creating
`fix/audit-b1-b2`:
- `fix/audit-b1-b2` does not exist on `origin` (confirmed via `git ls-remote`) — there was
  nothing to resume there.
- `claude/compassionate-davinci-rlhp36` turned out to already **be** `main` (identical HEAD)
  and already carried two of the bundle's items (H2 LICENSE, H4 README — see below), i.e.
  it already **is** the continuation state the bundle describes, just under a different name.

All work below is committed and pushed to `claude/compassionate-davinci-rlhp36`. If you
specifically need the branch named `fix/audit-b1-b2`, say so and I'll create it from here.

## What actually needed doing

Before starting, `node_modules/` did not exist. `npm install` was run first (clean, no
errors — 862 packages, only the usual audit warnings, no blocking failures).

Checked the actual repo state against the bundle's assumptions before touching anything:

| Item | Bundle assumed | Actually found |
|---|---|---|
| H2 LICENSE | to be added | **already present, byte-identical to the bundle's text** (commit `b3168c8`) |
| H4 README | to be added | **a file already exists** (commit `0478c90`, "Add comprehensive README.md"), but its content is a long, different, cross-platform-marketing-style README — not the short Android-only text the bundle shows for H4. See "README divergence" below. Left as-is. |
| H3 SECURITY.md | to be added | missing — added |
| C1 / M2 / H1 / F1 / L8 | to be added | missing — added |
| H5 test mock | to be added | missing — added (mock only, see gap below) |

## Commits made (chronological, oldest first)

All pushed to `origin/claude/compassionate-davinci-rlhp36`.

1. `fbd5e70` — `test(H5): add native-backed KeyCustody mock infrastructure`
   `__mocks__/react-native.js` (AppState + createNativeKeyCustodyMock + globalThis-anchored
   NativeModules) + package-lock.json sync from `npm install`.
2. `7bf69ac` — `fix(C1): atomic WAL for the wrapped master key`
   `src/services/CryptoService.ts`, `src/services/XChaCha20CryptoService.ts` (dead-wrapper
   removal, see gap below), `__tests__/MasterKeyWAL.test.ts` (new).
3. `c8ded7d` — `fix(M2): operation-lock between auto-lock and multi-step crypto ops`
   `src/services/AutoLockService.ts`, `src/services/KeyRotationService.ts`,
   `src/services/FileManager.ts`, `src/services/ids.ts` (new).
4. `867798a` — `fix(H1): extend boot cache-sweep to cache/ImagePicker/`
   `src/services/FileManager.ts`.
5. `d98d783` — `chore(H2): declare license in package.json`
6. `8596b44` — `docs(H3): add SECURITY.md`
7. `046bcbc` — `build(F1): narrow .gitignore, regenerate Android scaffold`
   `.gitignore`, `package.json` (script updates from prebuild), regenerated
   `android/` scaffold (AndroidManifest.xml, gradle files, gradlew, res/, proguard-rules.pro),
   `MainApplication.kt` (new, with `FileVaultPackage()` registered manually).
8. `d57c03b` — `ci(L8): pin workflow permissions, wire up the host test suite`
   `.github/workflows/android-kat.yml`, `.github/workflows/verify.yml` (new), `package.json`
   (`test:coverage` / `verify` scripts).

Every commit above was gated on `npx tsc --noEmit` (clean throughout) and `npx jest`
(28/28 suites, 117/117 tests green throughout — count rose to that after the H5/C1 test
additions and held). Each commit was `git add`-ed with explicit file paths, never `-A`/`.`,
and pushed immediately with `git push -u origin claude/compassionate-davinci-rlhp36`.

## Skipped / left uncommitted (per your rule 4 — no device)

`adb` is not installed in this environment and no device/emulator is attached
(`adb devices` — command not found). Per your instruction, **M1 and L3 were applied to the
working tree but deliberately NOT committed**:

- `android/app/src/main/java/com/filevault/app/modules/NativeKeyCustody.kt` (modified,
  uncommitted) — `unwrapVaultWithKek` now takes a `ByteArray` KEK directly instead of a hex
  string, so the caller controls zeroing.
- `android/app/src/main/java/com/filevault/app/modules/NativeKeyCustodyModule.kt` (modified,
  uncommitted) — decodes the KEK once at the bridge boundary and zeroes it in a `finally`.
- `android/app/src/androidTest/java/com/filevault/app/L3Phase4CeremonyTest.kt` (modified,
  uncommitted) — updated to the new `unwrapVaultWithKek(ByteArray, ...)` signature.
- `android/app/src/main/java/com/filevault/app/modules/Argon2Module.kt` (**new file**,
  untracked) — Argon2id-via-libsodium bridge module.

**These four files currently sit uncommitted in the working tree of this session's
container.** If this container is discarded before you pull them out, they are lost again.
Recommended: before doing anything else, run `git diff` / copy these four files out, or ask
me to open a PR from the current working tree so they're preserved even without a device
test having run.

To finish M1/L3 properly: connect a device, run `npm run test:device`
(specifically `L3Phase4CeremonyTest.test4e_biometricUnwrapVaultWithKek`), confirm 15/15
(or whatever the current on-device suite size is) green via Logcat, then commit.

## New gaps discovered during this run (not flagged by the bundle)

The bundle was honest about what it couldn't reconstruct, but a few more gaps surfaced
only by actually running the build/tests. None of these are things I invented content for —
each is called out below with what's missing and why I didn't fabricate a replacement:

1. **`__tests__/SecurityServices.test.ts` doesn't exist at all** (H5). The bundle's own
   wording assumed a pre-existing `describe('KeyCustody (JS-backed fallback)', ...)` block
   already lived on `main` and only the new native-backed block needed reconstruction. There
   is no such file anywhere in this repo. I applied the `__mocks__/react-native.js` diff
   (fully given, verified non-breaking against the whole existing suite) but did **not**
   write the test file itself — I have only the ten bare test names for the new block and
   nothing for the assumed-existing base block.

2. **`test-utils/memfs.ts` doesn't exist** (M2). `__tests__/AutoLockOperationSuppression.test.ts`
   was marked "vollständig" in the bundle but its first line does
   `jest.mock('expo-file-system/legacy', () => require('../test-utils/memfs').createFileSystemMock())`.
   That module isn't in this repo. Building a real in-memory filesystem mock (needs correct
   read-after-write semantics so `recryptBlob`'s real crypto round-trips) is a genuine
   implementation task, not a mechanical extraction — I didn't write one. The **code** fix
   (`beginOperation`/`endOperation` in AutoLockService, wired into
   `FileManager.reencryptAll` and `KeyRotationService`) is committed and is exercised
   indirectly by the full existing suite staying green; the specific new regression test for
   it is not.

3. **`__tests__/ImportCacheCleanupOnFailure.test.ts` doesn't exist** (H1) — this one the
   bundle *did* flag correctly as not reconstructable. Left as documented.

4. **`src/services/XChaCha20CryptoService.ts` had a live caller of the function C1 deletes.**
   `SecureCryptoService.deriveKeyFromPassphrase()` was removed by the C1 diff as dead code,
   but `XChaCha20CryptoService.deriveKeyFromPassphrase()` (a deprecated compatibility
   wrapper) called it — this would have broken `tsc --noEmit`. Confirmed nothing calls
   *that* wrapper either, so I removed it too, for the same reason C1's own comment gives
   for the original: dead code, and no longer even compiles.

5. **`src/services/ids.ts` didn't exist.** The M2/FileManager diff imports
   `generateSecureId` from `./ids` with a comment saying it's shared with
   NotesService/DecoyVaultService. Those services still have their own separate,
   un-refactored ID generators — the shared-file refactor implied by that comment was never
   itself captured in the bundle. I created `ids.ts` with exactly FileManager's own
   previous algorithm (visible in the diff's own removed lines — nothing invented), used only
   by FileManager. I did **not** touch NotesService/DecoyVaultService — that broader
   dedup refactor is out of scope and unverified.

6. **`npm run test:coverage` and `npm run verify` were documented in the README but never
   defined in package.json.** L8's new `verify.yml` needed the former to actually run.
   Added both, matching exactly what the README already promised.

7. **The regenerated `android/app/build.gradle` and `MainActivity.kt` are not pure
   scaffold**, contrary to the bundle's F1 note ("keine bespoke Krypto-Logik"). `npx expo
   prebuild --platform android --clean` overwrote both with generic templates, wiping:
   L7 release signing-cert-pin `buildConfigField`, the release `signingConfig` block, the
   `lazysodium-android`/`jna` dependencies, the `androidTest` runner config, and a Windows
   packageRelease-cleanup workaround (build.gradle); and the always-on `FLAG_SECURE`
   screen-protection flag (MainActivity.kt). Both were restored via `git checkout --
   <path>` from HEAD before continuing — verified `git diff` is empty for both. **If you
   ever re-run `expo prebuild --clean` yourself, do the same restoration**, or better,
   stop tracking `build.gradle`/`MainActivity.kt` as prebuild-regeneratable at all.

8. **`FileVaultPackage.kt` (already on `main`, untouched by any of the bundle's diffs)
   references two native modules that don't build right now:**
   - `Argon2Module` — this is exactly section 11/L3 above. Until a device test lands it,
     `FileVaultPackage.kt`'s existing, already-committed `createNativeModules()` list won't
     compile at all. This makes L3 more than an audit nice-to-have — the native app is
     currently non-buildable on `main` without it.
   - `ScreenSecurityModule` — does **not exist anywhere**, not in this repo, not in the
     recovery notes, not on any branch I can see. `src/services/ScreenProtectionService.ts`
     already treats `NativeModules.ScreenSecurity` as optionally `undefined`, so the JS side
     degrades gracefully, but the Kotlin side will not compile until this class exists or
     the reference is removed from `FileVaultPackage.kt`.

     **Tracked as N2 — a new, standalone finding, explicitly NOT part of this recovery.**
     Per instruction: the code (`FileVaultPackage.kt` and everything downstream of it) has
     **not been touched** for this. No stub, no removal of the reference, nothing — it's
     left exactly as it already was on `main`, broken exactly as found. This is here purely
     as a documented finding for you to look at and decide on (write the module, or remove
     the reference) before anyone acts on it.

9. **`assets/logo-vector.svg` — nothing to insert, not just "unconfirmed."** The task said
   to "insert the last version shown in the bundle," but the bundle itself contains no SVG
   source anywhere — only a paragraph in its own "not reconstructable" list, describing a
   version ("hub + circle + triangle via fill-rule=evenodd") that was shown earlier in the
   original chat, not in this document. There is currently no `logo-vector.svg` in
   `assets/` at all (only `logo.png`, `logo-mark.png`). I left this untouched rather than
   drawing a new SVG from a text description. **This needs Noah to redo it visually in the
   browser from scratch** — there's no draft to confirm, unconfirmed or otherwise.

## README divergence (informational, not fixed)

`README.md` (already on `main`) describes Obscura as cross-platform ("Android and iOS")
and lists an `ios` folder-adjacent stack. There is no `ios/` directory in this repo, `app.json`
has never had it built, and `SECURITY.md` (this run) plus `.github/workflows/android-kat.yml`
both describe the project as Android-only. I did not change the README — the H4 audit item
was about README existing/being comprehensive, not about auditing its accuracy, and I didn't
want to silently rewrite an already-committed, already-reviewed document on my own judgment.
Worth a human decision on whether the iOS framing is aspirational or simply wrong.

## N3 — `android-kat.yml` has never passed a single CI run (pre-existing, unrelated to this audit)

Found while verifying the F1 (`046bcbc`) and L8 (`d57c03b`) commits on GitHub: both show a
failed check. Investigated via the actual GitHub Actions logs (not guessed) before writing
anything below.

**Not N2.** The failure has nothing to do with `ScreenSecurityModule`/`FileVaultPackage.kt`.
It happens before any Kotlin compile step even starts.

**The actual failure**, identical on both runs:

```
.github/workflows/android-kat.yml, job "androidTest", step "Prime missing debug AARs into local-maven"
##[error]An error occurred trying to start process '/usr/bin/bash' with working directory
'/home/runner/work/Obscura/Obscura/android/local-maven'. No such file or directory
```

That's `.github/workflows/android-kat.yml:67-68`:
```yaml
      - name: Prime missing debug AARs into local-maven
        working-directory: android/local-maven
```

`android/local-maven` is a machine-local, `.gitignore`d offline Gradle Maven cache (per the
step's own comment: "This is exactly the manual fix used to get the first on-device run
green"). It has never been committed to this repo. On a fresh GitHub-hosted runner checkout
that directory does not exist, so the step fails trying to `cd` into it, before it can even
run the `find`/`curl` logic that would populate it.

**Confirmed pre-existing, not caused by F1/L8, via `list_workflow_runs` on this workflow:**
21 total runs since 2026-06-26, across `main`, `feat/round6-crypto-final`,
`feat/endpoint-hardening`, `feat/l3-native-key-custody`, and `claude/vibrant-dijkstra-y9hwyf`
— **21/21 failed**. Pulled the actual job log for run #13 (2026-09-11, branch
`claude/vibrant-dijkstra-y9hwyf`, three days before this session started): byte-identical
`android/local-maven` error. Also confirmed via `git show b3168c8:.github/workflows/android-kat.yml`
that the "Prime missing debug AARs" step with this exact `working-directory` already existed
before this session touched the file at all — my L8 commit only added a `permissions:` block
above it, nothing in this step. (Earlier runs, e.g. #4 from June, failed for a different
reason — an `npm ci` lockfile error — so the specific symptom has shifted over time, but the
workflow has never once gone green.)

Why F1 and L8 are the ones showing red on GitHub for *this* branch: neither commit caused
anything — they're simply the first two commits on `claude/compassionate-davinci-rlhp36`
that match the workflow's own trigger paths (F1 touches `android/**`; L8 edits
`.github/workflows/android-kat.yml` itself, which is also a listed trigger path). Every
earlier commit in this session (H5, C1, M2, H1, H2, H3) touched none of those paths, so the
workflow simply never ran on this branch until F1.

**Not fixed. Not proposed as a patch. `android-kat.yml` was not touched for this.** Per
instruction this is tracked as a standalone finding (N3), explicitly out of scope for
today's audit — a candidate direction (the step may need a prior job that actually populates
`android/local-maven` from Gradle's own resolution, or the whole on-device-KAT workflow may
never have been intended to run unattended in CI at all — the file's own header comment
documents a *manual* on-device run: "Done: device SM-S906B, 2026-06-26, tests=15
failures=0") is noted here for context only, not as a decision. `verify.yml` (the other L8
addition) is unaffected and green on every run so far.

## Current `git log --oneline` (top of branch down to before this session)

```
d57c03b ci(L8): pin workflow permissions, wire up the host test suite
046bcbc build(F1): narrow .gitignore, regenerate Android scaffold
8596b44 docs(H3): add SECURITY.md
d98d783 chore(H2): declare license in package.json
867798a fix(H1): extend boot cache-sweep to cache/ImagePicker/
c8ded7d fix(M2): operation-lock between auto-lock and multi-step crypto ops
7bf69ac fix(C1): atomic WAL for the wrapped master key
fbd5e70 test(H5): add native-backed KeyCustody mock infrastructure
b3168c8 Add MIT License
0478c90 Add comprehensive README.md for Obscura FileVault
8254c5f Merge pull request #5 from linux-nw/feat/l3-native-key-custody
... (older L3/endpoint-hardening history unchanged)
```

## What I need from you

1. **Confirm the branch.** Everything is on `claude/compassionate-davinci-rlhp36`, not
   `fix/audit-b1-b2` (which never existed on GitHub). Say if you want it moved/renamed.
2. **A device or emulator with `adb`** to finish M1/L3: pull the four uncommitted files
   out of this container's working tree first if you're not continuing in this exact
   session, then run `npm run test:device` and commit once green.
3. **A decision on `ScreenSecurityModule` (N2)** — item 8 above. Referenced by
   already-committed code, blocks the native Android build entirely, independent of
   anything in this recovery. Deliberately untouched pending your review — either write
   the module or remove the reference from `FileVaultPackage.kt`, but that's your call to
   make, not something I did on my own initiative.
4. **The logo.** No SVG source exists to insert (item 9) — needs to be redrawn from
   scratch in the browser, not just re-confirmed.
5. **A call on the README** (informational section above) — cross-platform framing vs.
   the Android-only reality documented everywhere else.
6. Two test files are gaps I couldn't responsibly fill (items 1–2 above):
   `__tests__/SecurityServices.test.ts` and `__tests__/AutoLockOperationSuppression.test.ts`.
   The underlying code fixes (H5 mock infra, M2 operation lock) are committed and covered
   indirectly by the existing suite; if you have the original chat history these tests came
   from, that's the only path to recovering them verbatim rather than me writing new tests
   that "look like" the originals.
7. **N3 — `android-kat.yml` (the on-device KAT workflow) has never passed, ever, on any
   branch.** Pre-existing, unrelated to this audit, not touched. You said you'll look at it
   yourself in a separate session (likely conclusion: it was never wired for real headless
   CI, only documents a manual on-device run). `verify.yml` is unaffected.
