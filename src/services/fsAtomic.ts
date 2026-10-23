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
// Temp paths of writes currently in flight. cleanupTempFiles() skips them so a concurrent
// initialize()/getFiles() cannot delete a live temp between write and rename.
const inFlight = new Set<string>();
// Per-target queue: two concurrent writers to the same target would share `<target>.tmp`
// and could rename each other's half-written data.
const queues = new Map<string, Promise<void>>();

export function writeFileAtomic(targetPath: string, data: string): Promise<void> {
  const tmpPath = `${targetPath}.tmp`;
  const prev = queues.get(targetPath) ?? Promise.resolve();
  const run = prev.then(async () => {
    inFlight.add(tmpPath);
    try {
      await FileSystem.writeAsStringAsync(tmpPath, data);
      // moveAsync overwrites an existing destination (rename semantics).
      await FileSystem.moveAsync({ from: tmpPath, to: targetPath });
    } catch (e) {
      await FileSystem.deleteAsync(tmpPath, { idempotent: true }).catch(() => {});
      throw e;
    } finally {
      inFlight.delete(tmpPath);
    }
  });
  const tail = run.catch(() => {});
  queues.set(targetPath, tail);
  tail.then(() => { if (queues.get(targetPath) === tail) queues.delete(targetPath); });
  return run;
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
      if (inFlight.has(`${dir}${name}`)) continue;
      await FileSystem.deleteAsync(`${dir}${name}`, { idempotent: true });
    }
  } catch {
    // best-effort — never block startup on cleanup
  }
}
