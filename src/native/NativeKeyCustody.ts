/**
 * NativeKeyCustody — TypeScript bridge for the libsodium secure-memory custody module
 * (NativeKeyCustodyModule.kt). L3 Phase 2b.
 *
 * Every function is async because the native side resolves Promises. The raw key crosses the
 * bridge ONLY in registerRawKey (audit B1/B5 one-time touch); every other call addresses an
 * opaque 128-bit handle. KeyCustody.ts uses `isAvailable()` to decide whether to install the
 * native backing (on device) or the JS-backed fallback (Jest / dev without the native module).
 *
 * Passphrases (openVault/rewrapVault) are passed RAW — NFC normalisation happens natively, in
 * the module, so a non-JS caller cannot diverge the KEK (R-03 / W-04).
 */

import { NativeModules } from 'react-native';

interface NativeKeyCustodyBridge {
  registerRawKey(params: { handle: string; keyHex: string }): Promise<string>;
  openVault(params: {
    password: string; kekSaltHex: string; opslimit: number; memlimitKB: number;
    ivHex: string; ctHex: string; macHex: string;
  }): Promise<string>;
  unwrapVaultWithKek(params: { kekHex: string; ivHex: string; ctHex: string; macHex: string }): Promise<string>;
  rewrapVault(params: {
    handle: string; newPassword: string; newSaltHex: string;
    opslimit: number; memlimitKB: number; newIvHex: string;
  }): Promise<{ ivHex: string; ctHex: string; macHex: string }>;
  encryptContent(params: { handle: string; dataB64: string; nonceHex: string; aadHex?: string }):
    Promise<{ cipherHex: string; tagHex: string }>;
  decryptContent(params: { handle: string; cipherHex: string; nonceHex: string; tagHex: string; aadHex?: string }):
    Promise<string>;
  wrapKey(params: { handle: string; ivHex: string; plaintextHex: string }):
    Promise<{ ctHex: string; macHex: string }>;
  unwrapKey(params: { handle: string; ivHex: string; ctHex: string; macHex: string }): Promise<string>;
  hasHandle(params: { handle: string }): Promise<boolean>;
  closeVault(params: { handle: string }): Promise<boolean>;
  closeAll(): Promise<void>;
}

const Native = NativeModules.NativeKeyCustody as NativeKeyCustodyBridge | undefined;

/** True iff the native custody module is present (i.e. running on a real build, not Jest). */
export function isAvailable(): boolean {
  try {
    return !!NativeModules.NativeKeyCustody;
  } catch {
    return false;
  }
}

function bridge(): NativeKeyCustodyBridge {
  if (!Native) throw new Error('NativeKeyCustody native module not available');
  return Native;
}

/** Adopt a JS-minted handle over a raw key (audit B1/B5 one-time touch). */
export async function registerRawKey(handle: string, keyHex: string): Promise<string> {
  return bridge().registerRawKey({ handle, keyHex });
}

/** Passphrase login: native Argon2id KEK derive + EtM master-unwrap → handle (audit R3). */
export async function openVault(args: {
  password: string; kekSaltHex: string; opslimit: number; memlimitKB: number;
  ivHex: string; ctHex: string; macHex: string;
}): Promise<string> {
  return bridge().openVault(args);
}

/** Biometric login: EtM master-unwrap under an already-derived KEK → handle (audit R3, B3). */
export async function unwrapVaultWithKek(args: {
  kekHex: string; ivHex: string; ctHex: string; macHex: string;
}): Promise<string> {
  return bridge().unwrapVaultWithKek(args);
}

/** Passphrase change: re-wrap the live master under a new KEK natively (audit R3). */
export async function rewrapVault(args: {
  handle: string; newPassword: string; newSaltHex: string;
  opslimit: number; memlimitKB: number; newIvHex: string;
}): Promise<{ ivHex: string; ctHex: string; macHex: string }> {
  return bridge().rewrapVault(args);
}

/** Content XChaCha20-Poly1305 encrypt by handle (audit R1). */
export async function encryptContent(
  handle: string, dataB64: string, nonceHex: string, aadHex?: string
): Promise<{ cipherHex: string; tagHex: string }> {
  return bridge().encryptContent({ handle, dataB64, nonceHex, aadHex });
}

/** Content XChaCha20-Poly1305 decrypt by handle (audit R1). Returns Base64 plaintext. */
export async function decryptContent(
  handle: string, cipherHex: string, nonceHex: string, tagHex: string, aadHex?: string
): Promise<string> {
  return bridge().decryptContent({ handle, cipherHex, nonceHex, tagHex, aadHex });
}

/** File-key EtM wrap by handle (audit R2). plaintextHex = hex(utf8(fileKeyString)). */
export async function wrapKey(
  handle: string, ivHex: string, plaintextHex: string
): Promise<{ ctHex: string; macHex: string }> {
  return bridge().wrapKey({ handle, ivHex, plaintextHex });
}

/** File-key EtM unwrap by handle (audit R2). Returns the recovered file-key string. */
export async function unwrapKey(
  handle: string, ivHex: string, ctHex: string, macHex: string
): Promise<string> {
  return bridge().unwrapKey({ handle, ivHex, ctHex, macHex });
}

export async function hasHandle(handle: string): Promise<boolean> {
  return bridge().hasHandle({ handle });
}

export async function closeVault(handle: string): Promise<boolean> {
  return bridge().closeVault({ handle });
}

export async function closeAll(): Promise<void> {
  return bridge().closeAll();
}
