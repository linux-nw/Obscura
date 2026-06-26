/**
 * Key Rotation Service
 * Regelmäßige Schlüsselrotation mit WAL-basierter Atomizität (R-02).
 *
 * WAL-Konzept:
 *   - Vor dem ersten Schritt wird ein Write-Ahead-Log angelegt.
 *   - Jede re-gewrappte File-Key-ID wird in `filesDone` eingetragen.
 *   - Bei Absturz entscheidet die Recovery:
 *       filesDone leer        → sicherer Rollback (nichts committed)
 *       filesDone == fileIds  → Roll-forward (neuen Master committen)
 *       filesDone teilweise   → noch fehlende Files fertigstellen, dann committen
 *   - INVARIANTE: Ein neu-gewrappter Key wird NIE mit dem alten Master entschlüsselt.
 *     `filesDone` enthält nur Keys, die bereits mit dem NEUEN Master gewrapped sind.
 */

import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from './CryptoService';
import { FileManager } from './FileManager';
import { NotesService } from './NotesService';

const WAL_KEY = 'filevault_keyrotation_wal';
// W-05: a rotation WAL older than this is "stale" — surfaced (warned) before resume.
const MAX_WAL_AGE_MS = 24 * 60 * 60 * 1000; // 24h

export interface KeyRotationInfo {
  lastRotation: number;
  nextRotation: number;
  rotationCount: number;
  enabled: boolean;
  rotationIntervalDays: number;
}

interface RotationWAL {
  /**
   * New master key wrapped with the OLD master key. Lets a post-crash resume
   * retrieve the new master key while the OLD master is still the installed one
   * (commit = installMasterKey happens last).
   */
  newMasterWrapped: { encryptedKey: string; iv: string; mac: string; createdAt: string };
  startedAt: number;
}

export class KeyRotationService {
  private static readonly LAST_ROTATION_KEY  = 'filevault_last_rotation';
  private static readonly NEXT_ROTATION_KEY  = 'filevault_next_rotation';
  private static readonly ROTATION_COUNT_KEY = 'filevault_rotation_count';
  private static readonly ROTATION_ENABLED_KEY = 'filevault_rotation_enabled';
  private static readonly ROTATION_INTERVAL_KEY = 'filevault_rotation_interval';
  private static readonly KEY_HISTORY_PREFIX = 'filevault_key_history_';

  private static readonly DEFAULT_ROTATION_INTERVAL = 90;

  static async initialize(): Promise<void> {
    try {
      // NOTE: rotation recovery is NOT run here. A resume needs the OLD master key
      // (and the passphrase to re-install the new one), neither of which is available
      // at cold startup. resumeRotationIfNeeded(passphrase) is called right after a
      // successful unlock instead (see AuthScreen).
      const enabled = await this.isRotationEnabled();
      if (enabled) {
        await this.checkAndRotate();
      }
    } catch (error) {
      console.error('KeyRotation: init failed:', error);
    }
  }

  /** True iff a rotation is currently in progress (WAL present). */
  static async hasPendingRotation(): Promise<boolean> {
    return !!(await SecureStore.getItemAsync(WAL_KEY));
  }

  // ─────────────────────────────── WAL-based secure rotation ───────────────────────────────

  /**
   * Atomically rotates the master key and RE-ENCRYPTS all file + note content
   * from the old master key to a fresh one. Requires the current passphrase.
   *
   * Content (file blobs + note fields) is encrypted directly with the master key,
   * so rotating the master key means re-encrypting every blob. This is done via
   * CryptoService.recryptBlob, which is per-blob idempotent (it detects the key a
   * blob is under by its own auth tag). Commit = installMasterKey, run LAST.
   *
   * Power-loss safety:
   *   - Crash during re-encryption → stored master is still OLD. After the next
   *     unlock, resumeRotationIfNeeded() finishes the migration idempotently.
   *   - Crash after install but before WAL delete → content is fully migrated;
   *     resume detects the new master can't unwrap the WAL and just clears it.
   */
  static async performSecureRotation(currentPassphrase: string): Promise<void> {
    const unlocked = await SecureCryptoService.unlock(currentPassphrase);
    if (!unlocked) throw new Error('Falsches Passwort — Rotation abgebrochen');

    const oldMasterKey = await SecureCryptoService.getMasterKey();
    if (!oldMasterKey) throw new Error('Kein Master-Key im Speicher');

    const newMasterKeyBuf = await SecureCryptoService.generateSecureBytes(32);
    const newMasterKeyHex = SecureCryptoService.bufferToHex(newMasterKeyBuf);

    // Wrap the new master key with the OLD master key so a resume can retrieve it
    // while the OLD master is still the installed one.
    const newMasterWrapped = await SecureCryptoService.encryptFileKeyWith(newMasterKeyHex, oldMasterKey);

    const wal: RotationWAL = { newMasterWrapped, startedAt: Date.now() };
    await SecureStore.setItemAsync(WAL_KEY, JSON.stringify(wal));

    await this.migrateContent(oldMasterKey, newMasterKeyHex);

    // Commit: install the new master key (wrap with passphrase, update cache), then drop the WAL.
    await SecureCryptoService.installMasterKey(newMasterKeyHex, currentPassphrase);
    await SecureStore.deleteItemAsync(WAL_KEY);

    await this.incrementRotationCount();
    await this.scheduleNextRotation();
  }

  /**
   * Resumes an interrupted rotation. MUST be called after a successful unlock
   * (the current master key must be in cache). No-op if no rotation is pending.
   */
  static async resumeRotationIfNeeded(currentPassphrase: string): Promise<void> {
    const walStr = await SecureStore.getItemAsync(WAL_KEY);
    if (!walStr) return;

    try {
      const wal = JSON.parse(walStr) as RotationWAL;
      const currentKey = await SecureCryptoService.getMasterKey();
      if (!currentKey) return; // not unlocked yet — caller must unlock first

      // W-05: surface a stale WAL. We still resume (per-blob idempotency makes it safe,
      // and finishing is the correct response to an attacker pausing rotation), but the
      // age is logged so the situation is visible rather than silently auto-resumed.
      const ageMs = Date.now() - (wal.startedAt ?? 0);
      if (ageMs > MAX_WAL_AGE_MS) {
        console.warn(`[KeyRotation] Resuming a STALE rotation: started ${Math.round(ageMs / 3600000)}h ago (> ${MAX_WAL_AGE_MS / 3600000}h). Completing it now.`);
      }

      let newMasterKeyHex: string;
      try {
        // Succeeds iff currentKey is the OLD master (the WAL was wrapped with it).
        newMasterKeyHex = await SecureCryptoService.decryptFileKeyWith(wal.newMasterWrapped, currentKey);
      } catch {
        // currentKey is NOT the old master → commit already happened (content fully
        // migrated, master already installed). Just clear the stale WAL.
        await SecureStore.deleteItemAsync(WAL_KEY);
        return;
      }

      // currentKey == old master: finish the migration idempotently, then commit.
      await this.migrateContent(currentKey, newMasterKeyHex);
      await SecureCryptoService.installMasterKey(newMasterKeyHex, currentPassphrase);
      await SecureStore.deleteItemAsync(WAL_KEY);

      await this.incrementRotationCount();
      await this.scheduleNextRotation();
    } catch (error) {
      console.error('KeyRotation: resume failed:', error);
      // Keep the WAL so the next unlock can retry.
    }
  }

  /** Re-encrypts all file + note content from oldKey to newKey (idempotent). */
  private static async migrateContent(oldKey: string, newKey: string): Promise<void> {
    await FileManager.reencryptAll(oldKey, newKey);
    await NotesService.reencryptAll(oldKey, newKey);
  }

  // ─────────────────────────────── Legacy rotation (stub) ───────────────────────────────

  static async performRotation(): Promise<void> {
    // Legacy stub — use performSecureRotation(passphrase) for real rotation.
    await this.incrementRotationCount();
    await this.scheduleNextRotation();
  }

  private static async checkAndRotate(): Promise<void> {
    try {
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) {
        await this.scheduleNextRotation();
        return;
      }
      if (Date.now() >= parseInt(nextRotation, 10)) {
        // Automatic rotation requires a passphrase; skip here and let the UI prompt.
        console.log('KeyRotation: Rotation due — awaiting user interaction');
      }
    } catch (error) {
      console.error('KeyRotation: checkAndRotate failed:', error);
    }
  }

  private static async incrementRotationCount(): Promise<void> {
    const count = await this.getRotationCount();
    await SecureStore.setItemAsync(this.ROTATION_COUNT_KEY, (count + 1).toString());
  }

  private static async scheduleNextRotation(): Promise<void> {
    const interval = await this.getRotationInterval();
    const nextRotation = Date.now() + interval * 24 * 60 * 60 * 1000;
    await SecureStore.setItemAsync(this.LAST_ROTATION_KEY, Date.now().toString());
    await SecureStore.setItemAsync(this.NEXT_ROTATION_KEY, nextRotation.toString());
  }

  // ─────────────────────────────── Settings Management ───────────────────────────────

  static async enableRotation(intervalDays: number = 90): Promise<void> {
    await SecureStore.setItemAsync(this.ROTATION_ENABLED_KEY, 'true');
    await SecureStore.setItemAsync(this.ROTATION_INTERVAL_KEY, intervalDays.toString());
    await this.scheduleNextRotation();
  }

  static async disableRotation(): Promise<void> {
    await SecureStore.deleteItemAsync(this.ROTATION_ENABLED_KEY);
    await SecureStore.deleteItemAsync(this.NEXT_ROTATION_KEY);
  }

  static async isRotationEnabled(): Promise<boolean> {
    const value = await SecureStore.getItemAsync(this.ROTATION_ENABLED_KEY);
    return value === 'true';
  }

  private static async getRotationInterval(): Promise<number> {
    const value = await SecureStore.getItemAsync(this.ROTATION_INTERVAL_KEY);
    return value ? parseInt(value, 10) : this.DEFAULT_ROTATION_INTERVAL;
  }

  private static async getRotationCount(): Promise<number> {
    const value = await SecureStore.getItemAsync(this.ROTATION_COUNT_KEY);
    return value ? parseInt(value, 10) : 0;
  }

  static async getKeyHistory(): Promise<{ rotationCount: number; history: { index: number; timestamp: number }[] }> {
    try {
      const count = await this.getRotationCount();
      const history: { index: number; timestamp: number }[] = [];
      for (let i = 0; i <= count; i++) {
        const item = await SecureStore.getItemAsync(`${this.KEY_HISTORY_PREFIX}${i}`);
        if (item) {
          const data = JSON.parse(item);
          // Nur Timestamp speichern — NIEMALS den echten Key!
          history.push({ index: i, timestamp: data.timestamp });
        }
      }
      return { rotationCount: count, history };
    } catch {
      return { rotationCount: 0, history: [] };
    }
  }

  static async getRotationInfo(): Promise<KeyRotationInfo> {
    try {
      const lastRotation  = await SecureStore.getItemAsync(this.LAST_ROTATION_KEY);
      const nextRotation  = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      const rotationCount = await this.getRotationCount();
      const interval      = await this.getRotationInterval();
      return {
        lastRotation: lastRotation ? parseInt(lastRotation, 10) : 0,
        nextRotation: nextRotation ? parseInt(nextRotation, 10) : 0,
        rotationCount,
        enabled: await this.isRotationEnabled(),
        rotationIntervalDays: interval,
      };
    } catch {
      return { lastRotation: 0, nextRotation: 0, rotationCount: 0, enabled: false, rotationIntervalDays: this.DEFAULT_ROTATION_INTERVAL };
    }
  }

  static async triggerManualRotation(): Promise<void> {
    // Manual rotation requires a passphrase — UI must call performSecureRotation(passphrase).
    // Only update rotation schedule here.
    await this.scheduleNextRotation();
  }

  /** Returns milliseconds until next scheduled rotation (0 if overdue or unknown). */
  static async getTimeUntilRotation(): Promise<number> {
    try {
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) return 0;
      const diff = parseInt(nextRotation, 10) - Date.now();
      return Math.max(0, diff);
    } catch {
      return 0;
    }
  }

  static async isRotationDue(): Promise<boolean> {
    try {
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) return false;
      const timeUntil = parseInt(nextRotation, 10) - Date.now();
      return timeUntil <= 7 * 24 * 60 * 60 * 1000;
    } catch {
      return false;
    }
  }

  static async cleanupOldKeys(daysToKeep: number = 180): Promise<void> {
    try {
      const history = await this.getKeyHistory();
      const cutoffDate = Date.now() - daysToKeep * 24 * 60 * 60 * 1000;
      for (const entry of history.history) {
        if (entry.timestamp < cutoffDate) {
          await SecureStore.deleteItemAsync(`${this.KEY_HISTORY_PREFIX}${entry.index}`);
        }
      }
    } catch (error) {
      console.error('KeyRotation: cleanup failed:', error);
    }
  }
}

export default KeyRotationService;
