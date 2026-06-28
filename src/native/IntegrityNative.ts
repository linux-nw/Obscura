/**
 * IntegrityNative — TypeScript bridge for the native Android IntegrityModule
 * (native module name "IntegrityNative", registered in FileVaultPackage.kt).
 *
 * Only the methods used by the L7 APK-integrity self-check are typed here. Every
 * wrapper tolerates the module being absent (Expo Go, unit tests, a future iOS
 * build): the verdict then degrades to "unverifiable" — never to a false "valid".
 *
 * Threat-model note: an on-device self-check is defeatable by an attacker who
 * patches out the call before re-signing. This raises the bar against naive
 * repackaging / re-signing; it is NOT server-verified attestation. See the
 * spec §15 Layer 7 boundary for what it does and does not buy.
 */

import { NativeModules } from 'react-native';

interface IntegrityNativeModule {
  verifyPinnedSignature(): Promise<{ configured: boolean; isValid: boolean; actualHash: string }>;
  getSignatureFingerprint(): Promise<string>;
  checkInstallerIntegrity(): Promise<{ installer: string; fromTrustedSource: boolean }>;
}

const Native = NativeModules.IntegrityNative as IntegrityNativeModule | undefined;

export type SignatureVerdict = 'valid' | 'invalid' | 'unverifiable';

/** True only when the native IntegrityModule is actually linked into this build. */
export function isIntegrityNativeAvailable(): boolean {
  return !!Native?.verifyPinnedSignature;
}

/**
 * Compare the running APK's signing cert against the build-time-pinned hash
 * (BuildConfig.SIGNING_CERT_SHA256).
 *   - 'valid'        cert matches the compiled-in hash
 *   - 'invalid'      cert present but does NOT match (repackaged / re-signed)
 *   - 'unverifiable' native module absent, OR the build pinned no hash (debug)
 *
 * Fail-closed: any error, absence, or unconfigured build yields 'unverifiable',
 * never 'valid'. Only 'invalid' is a positive tamper signal.
 */
export async function verifyPinnedSignature(): Promise<SignatureVerdict> {
  if (!Native?.verifyPinnedSignature) return 'unverifiable';
  try {
    const r = await Native.verifyPinnedSignature();
    if (!r.configured) return 'unverifiable';
    return r.isValid ? 'valid' : 'invalid';
  } catch {
    return 'unverifiable';
  }
}

/**
 * Installer provenance: was the package installed by a trusted store, or
 * side-loaded / installed by an unknown source. Advisory only.
 */
export async function checkInstallerIntegrity(): Promise<{
  installer: string;
  fromTrustedSource: boolean;
}> {
  if (!Native?.checkInstallerIntegrity) {
    return { installer: 'unknown', fromTrustedSource: false };
  }
  try {
    return await Native.checkInstallerIntegrity();
  } catch {
    return { installer: 'unknown', fromTrustedSource: false };
  }
}
