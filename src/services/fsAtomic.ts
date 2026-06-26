/**
 * Atomic file writes (H3).
 *
 * `writeAsStringAsync` writes in place — a power-loss mid-write leaves a truncated
 * file that neither the old nor the new key can decrypt (permanent blob loss). We
 * write to a `.tmp` sibling and then rename: rename(2) is atomic on ext4/f2fs, so the
 * target is always either the complete old content or the complete new content.
 */

import * as FileSystem from 'expo-file-system/legacy';

/** Write `data` to `targetPath` atomically via temp file + rename. */
export async function writeFileAtomic(targetPath: string, data: string): Promise<void> {
  const tmpPath = `${targetPath}.tmp`;
  await FileSystem.writeAsStringAsync(tmpPath, data);
  // moveAsync overwrites an existing destination (rename semantics).
  await FileSystem.moveAsync({ from: tmpPath, to: targetPath });
}

/**
 * Startup cleanup of leftover `.tmp` files from an interrupted write.
 *
 * A leftover `.tmp` cannot be trusted to be complete (the crash may have happened
 * mid-write), so it is always DELETED rather than promoted to the target:
 *   - target exists  → the rename never happened; target is the intact old/new copy.
 *   - target missing → an in-progress create that never committed; drop the partial.
 * Promoting a possibly-truncated `.tmp` would surface corrupt "valid-looking" data.
 */
export async function cleanupTempFiles(dir: string): Promise<void> {
  try {
    const entries = await FileSystem.readDirectoryAsync(dir);
    for (const name of entries) {
      if (!name.endsWith('.tmp')) continue;
      await FileSystem.deleteAsync(`${dir}${name}`, { idempotent: true });
    }
  } catch {
    // best-effort — never block startup on cleanup
  }
}
