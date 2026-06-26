/**
 * BlobVersionService (A3 rollback protection).
 *
 * A monotonic per-object version counter held in SecureStore (Android Keystore-
 * protected), used as a freshness anchor that a filesystem-write attacker cannot
 * forge or lower.
 *
 * Model:
 *   - The version is bound into each blob's AAD as `${id}:${role}:v${version}`, so a
 *     blob authenticates its OWN version (tamper the plaintext version → MAC fail).
 *   - The blob's version is also stored in its (plaintext) metadata, so a reader knows
 *     which version to feed to decrypt — the blob self-describes.
 *   - SecureStore holds the monotonic FLOOR. On read, `metaVersion < floor` ⇒ the blob
 *     was rolled back to a stale version ⇒ reject.
 *
 * Write order (caller): build+write the blob atomically (H3) FIRST, THEN advance the
 * floor. A crash between the two leaves floor one behind (read still works, at most a
 * one-version reuse window) rather than ahead (which would lock the object out).
 */

import * as SecureStore from 'expo-secure-store';

const PREFIX = 'filevault_blobver_';

export const BlobVersionService = {
  /** Current floor for an object id (0 if none stored yet). */
  async getFloor(id: string): Promise<number> {
    try {
      const raw = await SecureStore.getItemAsync(`${PREFIX}${id}`);
      const n = raw ? parseInt(raw, 10) : 0;
      return Number.isFinite(n) && n > 0 ? n : 0;
    } catch {
      return 0;
    }
  },

  /** The version a write should use: floor + 1 (does NOT persist — call advanceTo after the write). */
  async nextVersion(id: string): Promise<number> {
    return (await this.getFloor(id)) + 1;
  },

  /** Advance the stored floor to `version` (monotonic — never lowers it). */
  async advanceTo(id: string, version: number): Promise<void> {
    const current = await this.getFloor(id);
    if (version > current) {
      await SecureStore.setItemAsync(`${PREFIX}${id}`, String(version));
    }
  },

  /** Remove the counter for an object (on delete). */
  async remove(id: string): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(`${PREFIX}${id}`);
    } catch {
      // best-effort
    }
  },
};

export default BlobVersionService;
