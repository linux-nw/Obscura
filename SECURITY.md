# Security Policy

Obscura FileVault is a local, offline encrypted vault app. Its security model is documented in
[CRYPTO_PROTOCOL_SPEC.md](CRYPTO_PROTOCOL_SPEC.md).

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/linux-nw/Obscura/security) of this repository.
2. Click "Report a vulnerability".
3. Describe the issue, including steps to reproduce and the affected component (JS/TS service,
   native Android module, build/signing config, etc.).

Do not open a public GitHub issue for a security vulnerability.

This is a single-maintainer project. There is no guaranteed response time, but reports are taken
seriously and will be addressed on a best-effort basis. You will get an acknowledgement once the
report has been reviewed.

## Scope

In scope:
- The cryptographic implementation and key-custody lifecycle (`src/services/`,
  `src/native/`, `android/app/src/main/java/com/filevault/app/`)
- Authentication, lockout, and decoy/duress-vault logic
- Backup and restore
- Build, signing, and dependency-verification configuration

Out of scope (already documented as accepted limitations, see `CRYPTO_PROTOCOL_SPEC.md`):
- Attacks that require a rooted device with a sophisticated, actively-hooking adversary (Magisk
  Zygisk/Shamiko, a stealth-configured Frida attach) — the app's root/tamper detection is
  explicitly advisory-only, not a security boundary
- Attacks requiring physical possession of an already-unlocked, unattended device

## Supported versions

Only the current `main` branch is supported. There are no maintained older release branches.
