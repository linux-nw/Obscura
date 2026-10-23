# Obscura security status

Status after Hardening Round 7 (audit + red-team simulation). All verification is code-level: `tsc --noEmit` clean, Jest 45 suites / 680 tests green. Nothing here has been built or run on a device; Kotlin changes are covered only by source-assert tests.

## What was done

| Phase | Result |
|-------|--------|
| Audit: crypto core | AES-CBC+HMAC boundary malleability, native bounds/hex parsing, rotation WAL data loss, plaintext master key at rest, non-atomic master write, lockout bypasses, Argon2 bounds |
| Audit: data services | Path traversal via unauthenticated meta, backup id/KDF-param bombs, incomplete wipe, temp-file residue, decoy distinguishability, panic counter |
| Audit: app/device | Wipe-on-max-attempts, wipe ordering, FLAG_SECURE gap in RN Modals, integrity check never run, cosmetic 2FA, manifest/build hardening |
| Red team: crypto | 198 attacks (blobs, auth, rotation crash injection at all 20 I/O steps, backups); 6 flaws fixed incl. critical rotation data loss |
| Red team: data | 150 attacks (backup/file/notes/decoy/panic/wipe); 11 flaws fixed |
| Red team: app | 118 attacks (native fail-closed, lockout/settings tamper, static hygiene); 9 flaws fixed |

Attack suites: `__tests__/Attack_*`, hardening suites: `__tests__/Sec_*`. Change log: `CRYPTO_PROTOCOL_SPEC.md` §17.

## Open items

Format changes (need a versioned migration):
- No AAD/context binding on wrapped file keys and wrapped master (file-key swap between ids undetected at key layer; content AAD limits damage).
- Unauthenticated meta `createdAt`/`size`.
- Wrap MAC input lacks domain separation from content MAC input (theoretical).

Needs a trusted clock / platform support:
- Temporary lockout can be bypassed by moving the system clock forward.
- Counters live in SecureStore; an attacker with store-write access can reset them or replay an old wrapped master (no data loss, passphrase change rolled back).
- A bit-flipped rotation WAL can be read as "already committed" and deleted (requires store-write access).
- Deleting a blob drops its version floor, so a retained copy can be resurrected by a file-write attacker.

Inherent limits:
- Passphrases, hex keys and decrypted note text live in JS/JVM strings that cannot be zeroed.
- Overwrite passes are unreliable on flash; crypto-shredding is the real protection.
- Root/Frida/debugger detection and the APK self-check are bypassable on a rooted device.
- 2FA is skipped on the password path when no biometrics are available (product decision).

Verification still required:
- Device build, `connectedAndroidTest`, release build with R8 (keep rules in `android/app/proguard-rules.pro` are untested), release signing with `FILEVAULT_SIGNING_CERT_SHA256`.
- Independent third-party review before any claim beyond "hardened". No software can honestly be certified "military grade" by its own author.
