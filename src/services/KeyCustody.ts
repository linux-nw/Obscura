import CryptoJS from 'crypto-js';
import * as Native from '../native/NativeKeyCustody';

/**
 * KeyCustody — L3 Phase 2 custody seam.
 *
 * CryptoService no longer passes raw master / content keys around as function arguments. A key is
 * registered into custody, which returns an opaque 128-bit handle, and every crypto operation is
 * addressed by that handle. JS call sites see only the handle, never the key.
 *
 * Two backings, chosen ONCE at module load by native-module presence:
 *
 *  - NativeBackedKeyCustody (PHASE 2b, on device): the key lives in libsodium guarded secure memory
 *    (sodium_malloc) behind NativeKeyCustodyModule. The raw key NEVER crosses the bridge in steady
 *    state — content/file-key ops route through the native handle. A raw key touches JS at exactly
 *    one place, registerRawKey, the documented one-time touch at vault creation / rotation (audit
 *    B1/B5). resolve() does not exist here: the key is not retrievable in JS at all.
 *
 *  - JsBackedKeyCustody (Jest / dev without the native module): the 2a behaviour — the raw key sits
 *    in the JS heap inside the session map and resolve() hands it back to the JS crypto primitives.
 *    This is the ONLY place the pure-JS content fallback (AES-CBC / backend 0x02) can run; on device
 *    isNative === true and that path is unreachable. No silent downgrade.
 *
 * The crypto itself does not change across either backing: same keys, same AEAD / EtM-wrap
 * construction, same wire format, byte-identical. Only WHERE the key is addressed from changes.
 *
 * The native backing keeps liveness synchronously trackable (has() must stay sync — CryptoService
 * uses it inside currentMasterHandle) via a JS-side live-handle Set plus a per-handle readiness
 * Promise. Sync register/close return immediately; the actual native store/free run on the bridge,
 * and every async op awaits the handle's readiness first — so a store that fails surfaces as a HARD
 * error on the next op (and drops the handle from `live`), never a silent wrong/missing key.
 */

function validateHex(keyHex: string): void {
  if (keyHex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(keyHex)) {
    throw new Error('KeyCustody: keyHex must be even-length hex');
  }
}

/** 128-bit opaque token — NOT the key. Same 32-hex shape as the native handle. */
function newHandle(): string {
  // crypto-js exposes WordArray.random at runtime; its bundled types omit it.
  return (CryptoJS.lib.WordArray as any).random(16).toString(CryptoJS.enc.Hex);
}

// ──────────────────────────────────────────────────────────────────────────────
// JS-backed (Phase 2a behaviour) — Jest / dev fallback
// ──────────────────────────────────────────────────────────────────────────────

export interface JsBackedKeyCustody {
  readonly isNative: false;
  has(handle: string): boolean;
  /** Register a raw key (even-length hex) into custody; returns an opaque handle (one-time touch). */
  registerRawKey(keyHex: string): string;
  /** Zero + drop the key behind the handle. Idempotent; returns false if unknown. */
  close(handle: string): boolean;
  /** Zero + drop every live handle (vault lock / process teardown). */
  closeAll(): void;
  /**
   * JS-backed seam ONLY: hand back the raw key hex so the existing JS crypto primitives can run.
   * Does not exist on the native backing. Throws on an unknown / closed handle.
   */
  resolve(handle: string): string;
}

class JsBackedKeyCustodyImpl implements JsBackedKeyCustody {
  readonly isNative = false as const;
  // handle (128-bit hex token) -> raw key bytes (zeroable in place, like the old __mkBytes).
  private readonly sessions = new Map<string, Uint8Array>();

  registerRawKey(keyHex: string): string {
    validateHex(keyHex);
    const bytes = new Uint8Array(keyHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
    }
    const handle = newHandle();
    this.sessions.set(handle, bytes);
    return handle;
  }

  has(handle: string): boolean {
    return this.sessions.has(handle);
  }

  resolve(handle: string): string {
    const bytes = this.sessions.get(handle);
    if (!bytes) throw new Error('KeyCustody.resolve: invalid or closed handle');
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  }

  close(handle: string): boolean {
    const bytes = this.sessions.get(handle);
    if (!bytes) return false;
    bytes.fill(0); // zero the long-lived key copy in place before dropping the reference
    this.sessions.delete(handle);
    return true;
  }

  closeAll(): void {
    for (const bytes of this.sessions.values()) bytes.fill(0);
    this.sessions.clear();
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Native-backed (Phase 2b) — libsodium secure-memory custody on device
// ──────────────────────────────────────────────────────────────────────────────

export interface NativeBackedKeyCustody {
  readonly isNative: true;
  has(handle: string): boolean;
  /** Adopt a JS-minted handle over a raw key (audit B1/B5 one-time touch); returns the handle. */
  registerRawKey(keyHex: string): string;
  close(handle: string): boolean;
  closeAll(): void;

  // ── R3: master KEK-unwrap / re-wrap (master never returns to JS) ──
  /** Passphrase login → live master handle (adopted on resolve). */
  openVaultInstall(args: {
    password: string; kekSaltHex: string; opslimit: number; memlimitKB: number;
    ivHex: string; ctHex: string; macHex: string;
  }): Promise<string>;
  /** Biometric login (KEK already in hand) → live master handle. */
  unwrapVaultWithKekInstall(args: {
    kekHex: string; ivHex: string; ctHex: string; macHex: string;
  }): Promise<string>;
  /** Re-wrap the live master under a new passphrase; returns the new {iv,ct,mac} blob. */
  rewrapVault(handle: string, args: {
    newPassword: string; newSaltHex: string; opslimit: number; memlimitKB: number; newIvHex: string;
  }): Promise<{ ivHex: string; ctHex: string; macHex: string }>;

  // ── R1: content AEAD by handle ──
  encryptContent(handle: string, dataB64: string, nonceHex: string, aadHex: string):
    Promise<{ cipherHex: string; tagHex: string }>;
  /** Returns Base64 plaintext. */
  decryptContent(handle: string, cipherHex: string, nonceHex: string, tagHex: string, aadHex: string):
    Promise<string>;

  // ── R2: file-key EtM wrap by handle ──
  wrapKey(handle: string, ivHex: string, plaintextHex: string):
    Promise<{ ctHex: string; macHex: string }>;
  /** Returns the recovered file-key string. */
  unwrapKey(handle: string, ivHex: string, ctHex: string, macHex: string): Promise<string>;
}

class NativeBackedKeyCustodyImpl implements NativeBackedKeyCustody {
  readonly isNative = true as const;
  // Synchronous liveness shadow — has() reads this; the native store/free run async on the bridge.
  private readonly live = new Set<string>();
  // Per-handle readiness: resolves when the native store has landed, rejects (and drops the handle)
  // if it failed. Every op awaits this before touching the bridge, so a failed store is a hard error.
  private readonly ready = new Map<string, Promise<void>>();

  private track(handle: string, store: Promise<unknown>): void {
    this.live.add(handle);
    const guarded = store.then(() => undefined).catch((e) => {
      this.live.delete(handle);
      this.ready.delete(handle);
      throw e;
    });
    this.ready.set(handle, guarded);
  }

  /** Adopt a native-minted handle that is already stored (openVault / unwrapVaultWithKek). */
  private adopt(handle: string): void {
    this.live.add(handle);
    this.ready.set(handle, Promise.resolve());
  }

  private async awaitReady(handle: string): Promise<void> {
    const p = this.ready.get(handle);
    if (p) await p;
    if (!this.live.has(handle)) {
      throw new Error('KeyCustody: handle is not live (native store failed or handle closed)');
    }
  }

  has(handle: string): boolean {
    return this.live.has(handle);
  }

  registerRawKey(keyHex: string): string {
    validateHex(keyHex);
    const handle = newHandle();
    this.track(handle, Native.registerRawKey(handle, keyHex));
    return handle;
  }

  close(handle: string): boolean {
    if (!this.live.has(handle)) return false;
    this.live.delete(handle);
    const r = this.ready.get(handle);
    this.ready.delete(handle);
    // Free only after the store has landed, so we never race a close ahead of its own store.
    Promise.resolve(r)
      .catch(() => undefined)
      .then(() => Native.closeVault(handle))
      .catch(() => undefined);
    return true;
  }

  closeAll(): void {
    for (const handle of [...this.live]) this.close(handle);
  }

  async openVaultInstall(args: {
    password: string; kekSaltHex: string; opslimit: number; memlimitKB: number;
    ivHex: string; ctHex: string; macHex: string;
  }): Promise<string> {
    const handle = await Native.openVault(args);
    this.adopt(handle);
    return handle;
  }

  async unwrapVaultWithKekInstall(args: {
    kekHex: string; ivHex: string; ctHex: string; macHex: string;
  }): Promise<string> {
    const handle = await Native.unwrapVaultWithKek(args);
    this.adopt(handle);
    return handle;
  }

  async rewrapVault(handle: string, args: {
    newPassword: string; newSaltHex: string; opslimit: number; memlimitKB: number; newIvHex: string;
  }): Promise<{ ivHex: string; ctHex: string; macHex: string }> {
    await this.awaitReady(handle);
    return Native.rewrapVault({ handle, ...args });
  }

  async encryptContent(handle: string, dataB64: string, nonceHex: string, aadHex: string):
    Promise<{ cipherHex: string; tagHex: string }> {
    await this.awaitReady(handle);
    return Native.encryptContent(handle, dataB64, nonceHex, aadHex);
  }

  async decryptContent(handle: string, cipherHex: string, nonceHex: string, tagHex: string, aadHex: string):
    Promise<string> {
    await this.awaitReady(handle);
    return Native.decryptContent(handle, cipherHex, nonceHex, tagHex, aadHex);
  }

  async wrapKey(handle: string, ivHex: string, plaintextHex: string):
    Promise<{ ctHex: string; macHex: string }> {
    await this.awaitReady(handle);
    return Native.wrapKey(handle, ivHex, plaintextHex);
  }

  async unwrapKey(handle: string, ivHex: string, ctHex: string, macHex: string): Promise<string> {
    await this.awaitReady(handle);
    return Native.unwrapKey(handle, ivHex, ctHex, macHex);
  }
}

export type KeyCustody = JsBackedKeyCustody | NativeBackedKeyCustody;

/** Process-wide custody. Native libsodium on device; JS-backed fallback under Jest / dev. */
export const keyCustody: KeyCustody = Native.isAvailable()
  ? new NativeBackedKeyCustodyImpl()
  : new JsBackedKeyCustodyImpl();
export default keyCustody;
