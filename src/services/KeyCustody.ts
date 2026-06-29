import CryptoJS from 'crypto-js';

/**
 * KeyCustody — L3 Phase 2 custody seam.
 *
 * CryptoService no longer passes raw master / content keys around as function arguments.
 * A key is REGISTERED into custody, which returns an opaque 128-bit handle, and every crypto
 * operation is addressed by that handle. JS call sites see only the handle, never the key.
 *
 * PHASE 2a (this commit) is JS-BACKED and is NOT yet the security win: the raw key still
 * lives in the JS heap, here, inside the session map (held as a zeroable Uint8Array), and
 * `resolve()` hands it back to the existing JS crypto primitives. A memory scrape of the JS
 * heap still finds the key in this module. What 2a delivers is the REWIRING:
 *   - getMasterKey() is gone (throws),
 *   - the explicit `keyHex` argument is gone from the public crypto API,
 *   - the ONLY remaining seam between "handle" and "raw key" is resolve().
 *
 * PHASE 2b swaps this implementation for the native libsodium custody bridge
 * (sodium_malloc + openVault/encryptWithHandle/closeVault). At that point resolve() is
 * removed and the raw key never enters the JS heap at all.
 *
 * The crypto itself does not change across either phase: same keys, same AEAD / EtM-wrap
 * construction, same wire format. Only WHERE the key is addressed from changes.
 */
export interface KeyCustody {
  /** Register a raw key (even-length hex) into custody; returns an opaque handle. */
  register(keyHex: string): string;
  /** True iff the handle is live. */
  has(handle: string): boolean;
  /** Zero + drop the key behind the handle. Idempotent; returns false if unknown. */
  close(handle: string): boolean;
  /** Zero + drop every live handle (vault lock / process teardown). */
  closeAll(): void;
  /**
   * 2a JS-backed seam ONLY: hand back the raw key hex so the existing JS crypto primitives
   * can run. Removed in 2b (native custody routes each op without ever exposing the key).
   * Throws on an unknown / closed handle — no silent fallback to a wrong or missing key.
   */
  resolve(handle: string): string;
}

class JsBackedKeyCustody implements KeyCustody {
  // handle (128-bit hex token) -> raw key bytes (zeroable in place, like the old __mkBytes).
  private readonly sessions = new Map<string, Uint8Array>();

  /** 128-bit opaque token — NOT the key. Same 32-hex shape as the native handle. */
  private newHandle(): string {
    // crypto-js exposes WordArray.random at runtime; its bundled types omit it.
    return (CryptoJS.lib.WordArray as any).random(16).toString(CryptoJS.enc.Hex);
  }

  register(keyHex: string): string {
    if (keyHex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(keyHex)) {
      throw new Error('KeyCustody.register: keyHex must be even-length hex');
    }
    const bytes = new Uint8Array(keyHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
    }
    const handle = this.newHandle();
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

/** Process-wide JS-backed custody (Phase 2a). Replaced by the native bridge in Phase 2b. */
export const keyCustody: KeyCustody = new JsBackedKeyCustody();
export default keyCustody;
