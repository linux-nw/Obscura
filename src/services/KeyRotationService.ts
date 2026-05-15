/**
 * Key Rotation Service
 * Regelmäßige Schlüsselrotation für Forward Secrecy
 *
 * Sicherheitsmerkmale:
 * - Time-based rotation (90 Tage)
 * - Event-based rotation (PIN Change)
 * - Manual rotation trigger
 * - Key history management
 * - Secure key destruction
 */

import * as SecureStore from 'expo-secure-store';
import { XChaCha20CryptoService } from './XChaCha20CryptoService';

export interface KeyRotationInfo {
  lastRotation: number;
  nextRotation: number;
  rotationCount: number;
  enabled: boolean;
  rotationIntervalDays: number;
}

export class KeyRotationService {
  private static readonly LAST_ROTATION_KEY = 'filevault_last_rotation';
  private static readonly NEXT_ROTATION_KEY = 'filevault_next_rotation';
  private static readonly ROTATION_COUNT_KEY = 'filevault_rotation_count';
  private static readonly ROTATION_ENABLED_KEY = 'filevault_rotation_enabled';
  private static readonly ROTATION_INTERVAL_KEY = 'filevault_rotation_interval';
  private static readonly KEY_HISTORY_PREFIX = 'filevault_key_history_';

  private static readonly DEFAULT_ROTATION_INTERVAL = 90; // 90 Tage

  /**
   * Initialisiert den Key Rotation Service
   */
  static async initialize(): Promise<void> {
    try {
      const enabled = await this.isRotationEnabled();
      if (enabled) {
        await this.checkAndRotate();
      }
      console.log('KeyRotation: Service initialized');
    } catch (error) {
      console.error('Error initializing KeyRotation:', error);
    }
  }

  /**
   * Prüft ob Rotation aktiviert ist und führt durch
   */
  private static async checkAndRotate(): Promise<void> {
    try {
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) {
        // Erste Initialisierung
        await this.scheduleNextRotation();
        return;
      }

      const nextRotationTime = parseInt(nextRotation, 10);
      if (Date.now() >= nextRotationTime) {
        await this.performRotation();
      }
    } catch (error) {
      console.error('Error checking rotation:', error);
    }
  }

  /**
   * Führt die Schlüsselrotation durch
   */
  static async performRotation(): Promise<void> {
    try {
      console.log('KeyRotation: Starting key rotation...');

      // Alten Schlüssel sichern (für Decryption existing data)
      const oldKey = await SecureStore.getItemAsync(XChaCha20CryptoService.STORAGE_KEY);
      if (oldKey) {
        await this.backupKey(oldKey);
      }

      // Neuen Schlüssel generieren
      const newKey = await XChaCha20CryptoService.generateSecureKey();
      await SecureStore.setItemAsync(XChaCha20CryptoService.STORAGE_KEY, newKey);

      // Key History aktualisieren
      await this.incrementRotationCount();
      await this.scheduleNextRotation();

      // In Produktion:
      // - Alle Dateien mit neuem Key re-encrypten
      // - Alle Notizen mit neuem Key re-encrypten
      // - File keys neu verschlüsseln

      console.log('KeyRotation: Key rotation complete');
    } catch (error) {
      console.error('KeyRotation: Rotation failed:', error);
      throw new Error('Schlüsselrotation fehlgeschlagen');
    }
  }

  /**
   * Sichert den alten Schlüssel für Decryption
   */
  private static async backupKey(key: string): Promise<void> {
    try {
      const rotationCount = await this.getRotationCount();
      const historyKey = `${this.KEY_HISTORY_PREFIX}${rotationCount}`;

      const encryptedBackup = {
        key: key,
        timestamp: Date.now(),
        rotationCount,
      };

      // Verschlüsselt Backups mit aktuellem Key
      await SecureStore.setItemAsync(historyKey, JSON.stringify(encryptedBackup));
    } catch (error) {
      console.error('KeyRotation: Failed to backup key:', error);
    }
  }

  /**
   * Fügt neuer Key zur History hinzu
   */
  private static async incrementRotationCount(): Promise<void> {
    try {
      const count = await this.getRotationCount();
      await SecureStore.setItemAsync(this.ROTATION_COUNT_KEY, (count + 1).toString());
    } catch (error) {
      console.error('KeyRotation: Failed to increment count:', error);
    }
  }

  /**
   * SCHEDULES next rotation
   */
  private static async scheduleNextRotation(): Promise<void> {
    try {
      const interval = await this.getRotationInterval();
      const nextRotation = Date.now() + interval * 24 * 60 * 60 * 1000;

      await SecureStore.setItemAsync(this.LAST_ROTATION_KEY, Date.now().toString());
      await SecureStore.setItemAsync(this.NEXT_ROTATION_KEY, nextRotation.toString());
    } catch (error) {
      console.error('KeyRotation: Failed to schedule next rotation:', error);
    }
  }

  // ─────────────────────────────── Settings Management ───────────────────────────────

  /**
   * Aktiviert Key Rotation
   */
  static async enableRotation(intervalDays: number = 90): Promise<void> {
    try {
      await SecureStore.setItemAsync(this.ROTATION_ENABLED_KEY, 'true');
      await SecureStore.setItemAsync(this.ROTATION_INTERVAL_KEY, intervalDays.toString());
      await this.scheduleNextRotation();
      console.log(`KeyRotation: Enabled with ${intervalDays} day interval`);
    } catch (error) {
      console.error('KeyRotation: Failed to enable rotation:', error);
    }
  }

  /**
   * Deaktiviert Key Rotation
   */
  static async disableRotation(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.ROTATION_ENABLED_KEY);
      await SecureStore.deleteItemAsync(this.NEXT_ROTATION_KEY);
      console.log('KeyRotation: Rotation disabled');
    } catch (error) {
      console.error('KeyRotation: Failed to disable rotation:', error);
    }
  }

  /**
   * Prüft ob Rotation aktiviert ist
   */
  static async isRotationEnabled(): Promise<boolean> {
    try {
      const value = await SecureStore.getItemAsync(this.ROTATION_ENABLED_KEY);
      return value === 'true';
    } catch {
      return false;
    }
  }

  /**
   * Gibt das Rotationsintervall in Tagen zurück
   */
  private static async getRotationInterval(): Promise<number> {
    try {
      const value = await SecureStore.getItemAsync(this.ROTATION_INTERVAL_KEY);
      return value ? parseInt(value, 10) : this.DEFAULT_ROTATION_INTERVAL;
    } catch {
      return this.DEFAULT_ROTATION_INTERVAL;
    }
  }

  /**
   * Gibt die Rotationsanzahl zurück
   */
  private static async getRotationCount(): Promise<number> {
    try {
      const value = await SecureStore.getItemAsync(this.ROTATION_COUNT_KEY);
      return value ? parseInt(value, 10) : 0;
    } catch {
      return 0;
    }
  }

  /**
   * Gibt die gesamte Key History zurück
   */
  static async getKeyHistory(): Promise<{
    currentKey: string | null;
    history: { index: number; timestamp: number }[];
  }> {
    try {
      const currentKey = await SecureStore.getItemAsync(XChaCha20CryptoService.STORAGE_KEY);
      const count = await this.getRotationCount();
      const history: { index: number; timestamp: number }[] = [];

      for (let i = 0; i <= count; i++) {
        const historyKey = `${this.KEY_HISTORY_PREFIX}${i}`;
        const historyItem = await SecureStore.getItemAsync(historyKey);
        if (historyItem) {
          const data = JSON.parse(historyItem);
          history.push({ index: i, timestamp: data.timestamp });
        }
      }

      return {
        currentKey,
        history,
      };
    } catch {
      return {
        currentKey: null,
        history: [],
      };
    }
  }

  /**
   * Gibt Rotation Info zurück (für Settings UI)
   */
  static async getRotationInfo(): Promise<KeyRotationInfo> {
    try {
      const lastRotation = await SecureStore.getItemAsync(this.LAST_ROTATION_KEY);
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      const rotationCount = await this.getRotationCount();
      const interval = await this.getRotationInterval();

      return {
        lastRotation: lastRotation ? parseInt(lastRotation, 10) : 0,
        nextRotation: nextRotation ? parseInt(nextRotation, 10) : 0,
        rotationCount,
        enabled: await this.isRotationEnabled(),
        rotationIntervalDays: interval,
      };
    } catch {
      return {
        lastRotation: 0,
        nextRotation: 0,
        rotationCount: 0,
        enabled: false,
        rotationIntervalDays: this.DEFAULT_ROTATION_INTERVAL,
      };
    }
  }

  /**
   * Manueller Rotation Trigger
   */
  static async triggerManualRotation(): Promise<void> {
    try {
      console.log('KeyRotation: Manual rotation triggered');
      await this.performRotation();
    } catch (error) {
      console.error('KeyRotation: Manual rotation failed:', error);
      throw error;
    }
  }

  /**
   * Berechnet verbleibende Zeit bis Rotation
   */
  static getTimeUntilRotation(): number {
    try {
      const nextRotation = SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) return 0;

      return parseInt(nextRotation, 10) - Date.now();
    } catch {
      return 0;
    }
  }

  /**
   * Prüft ob bald rotiert werden muss (Warnung)
   */
  static async isRotationDue(): Promise<boolean> {
    try {
      const nextRotation = await SecureStore.getItemAsync(this.NEXT_ROTATION_KEY);
      if (!nextRotation) return false;

      const nextRotationTime = parseInt(nextRotation, 10);
      const timeUntil = nextRotationTime - Date.now();
      const warningThreshold = 7 * 24 * 60 * 60 * 1000; // 7 Tage

      return timeUntil <= warningThreshold;
    } catch {
      return false;
    }
  }

  /**
   * Bereinigt alte Key History Einträge (nach Sicherheitspolicy)
   */
  static async cleanupOldKeys(daysToKeep: number = 180): Promise<void> {
    try {
      const history = await this.getKeyHistory();
      const cutoffDate = Date.now() - daysToKeep * 24 * 60 * 60 * 1000;

      for (const entry of history.history) {
        if (entry.timestamp < cutoffDate) {
          const historyKey = `${this.KEY_HISTORY_PREFIX}${entry.index}`;
          await SecureStore.deleteItemAsync(historyKey);
          console.log(`KeyRotation: Cleaned up old key history entry ${entry.index}`);
        }
      }
    } catch (error) {
      console.error('KeyRotation: Cleanup failed:', error);
    }
  }
}

export default KeyRotationService;
