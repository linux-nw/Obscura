/**
 * Auto Lock Service
 * Aggressive Auto-Locks nach Inaktivität
 *
 * Sicherheitsmerkmale:
 * - Configurable timeout (15s - 10min)
 * - Reset on user interaction
 * - Immediate lock on background
 * - Haptic feedback on lock
 */

import { Platform, Vibration, AppState } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { SettingsService } from './SettingsService';

export interface AutoLockSettings {
  enabled: boolean;
  timeoutSeconds: number;
  lastActivity: number;
}

export class AutoLockService {
  private static readonly SETTINGS_KEY = 'filevault_auto_lock_settings';
  private static readonly LAST_ACTIVITY_KEY = 'filevault_last_activity';
  private static readonly LOCKED_KEY = 'filevault_auto_locked';

  private static timeoutId: ReturnType<typeof setTimeout> | null = null;
  private static lockCallback: (() => void) | null = null;

  // F2/Picker: while a system picker (image/document) is open, the app
  // necessarily goes to background. Suppress the background-lock during that
  // controlled window so the master key survives until the picked file is saved.
  // Set ONLY around an explicit in-app picker launch; always cleared in finally.
  private static pickerActive = false;

  private static settings: AutoLockSettings = {
    enabled: true,
    timeoutSeconds: 300, // Default 5 Minuten (aus SettingsService)
    lastActivity: Date.now(),
  };

  /** True while a system picker launched from within the app is in progress. */
  static isPickerActive(): boolean {
    return this.pickerActive;
  }

  /** Call immediately BEFORE launching a system picker (document/image). */
  static beginPickerSession(): void {
    this.pickerActive = true;
  }

  /** Call in a finally AFTER the picker flow (incl. save) completes or cancels. */
  static endPickerSession(): void {
    this.pickerActive = false;
    // Reset the inactivity timer: the picker round-trip counts as activity.
    this.resetTimer();
  }

  /**
   * Setzt den Lock-Callback der aufgerufen wird wenn der Tresor gesperrt wird.
   * Wird von App.tsx gesetzt um setIsAuthenticated(false) auszulösen.
   */
  static setLockCallback(callback: () => void): void {
    this.lockCallback = callback;
  }

  /**
   * Initialisiert den Auto Lock Service und liest Timeout aus SettingsService.
   */
  static async initialize(): Promise<void> {
    try {
      await this.loadSettings();
      await this.setupAppStateListener();
      await this.checkAndLock();
      console.log('AutoLock: Service initialized');
    } catch (error) {
      console.error('Error initializing AutoLock:', error);
    }
  }

  /**
   * Lädt Einstellungen — liest autoLockTimeout aus SettingsService.
   */
  private static async loadSettings(): Promise<void> {
    try {
      // Timeout aus SettingsService lesen (Nutzereinstellung hat Priorität)
      const appSettings = await SettingsService.get();
      const t = appSettings.autoLockTimeout;
      if (t === -1) {
        // "Nie" — no inactivity timer
        this.settings.enabled = false;
      } else if (t === 0) {
        // "Sofort" — no inactivity timer; background locking via App.tsx AppState listener
        this.settings.enabled = false;
      } else {
        this.settings.enabled = true;
        this.settings.timeoutSeconds = t;
      }

      const lastActivity = await SecureStore.getItemAsync(this.LAST_ACTIVITY_KEY);
      if (lastActivity) {
        this.settings.lastActivity = parseInt(lastActivity, 10);
      }
    } catch (error) {
      console.error('Error loading auto lock settings:', error);
    }
  }

  /**
   * Speichert Einstellungen
   */
  private static async saveSettings(): Promise<void> {
    try {
      await SecureStore.setItemAsync(
        this.SETTINGS_KEY,
        JSON.stringify(this.settings),
      );
      await SecureStore.setItemAsync(
        this.LAST_ACTIVITY_KEY,
        this.settings.lastActivity.toString(),
      );
    } catch (error) {
      console.error('Error saving auto lock settings:', error);
    }
  }

  /**
   * Setup AppState Listener für Background/Foreground
   */
  private static async setupAppStateListener(): Promise<void> {
    AppState.addEventListener('change', (state) => {
      if (state === 'background') {
        this.triggerLock();
      } else if (state === 'active') {
        this.resetTimer();
      }
    });

    console.log('AutoLock: AppState listener set up');
  }

  // ─────────────────────────────── Timer Management ───────────────────────────────

  /**
   * Setzt den Lock Timer zurück
   */
  static resetTimer(): void {
    // Timer zurücksetzen
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }

    // Activityzeit aktualisieren
    this.settings.lastActivity = Date.now();
    this.saveSettings();

    // Neue Timer starten
    this.startTimer();
  }

  /**
   * Startet den Lock Timer
   */
  private static startTimer(): void {
    if (!this.settings.enabled) {
      return;
    }

    const timeoutMs = this.settings.timeoutSeconds * 1000;

    this.timeoutId = setTimeout(() => {
      this.triggerLock();
    }, timeoutMs);

    console.log(`AutoLock: Timer started (${this.settings.timeoutSeconds}s)`);
  }

  /**
   * Prüft und sperrt bei Bedarf
   */
  private static async checkAndLock(): Promise<void> {
    try {
      const lastActivity = await SecureStore.getItemAsync(this.LAST_ACTIVITY_KEY);
      if (lastActivity) {
        this.settings.lastActivity = parseInt(lastActivity, 10);
        const elapsed = Date.now() - this.settings.lastActivity;
        const timeoutMs = this.settings.timeoutSeconds * 1000;

        if (elapsed >= timeoutMs) {
          this.triggerLock();
        } else {
          this.startTimer();
        }
      }
    } catch (error) {
      console.error('Error checking auto lock:', error);
    }
  }

  // ─────────────────────────────── Lock Functions ───────────────────────────────

  /**
   * Löst sofortigen Lock aus und benachrichtigt App via Callback.
   */
  static async triggerLock(): Promise<void> {
    try {
      // F2/Picker: do not lock while a system picker launched from within the
      // app is in progress — that backgrounding is expected and controlled.
      if (this.pickerActive) {
        return;
      }
      if (Platform.OS === 'android') {
        Vibration.vibrate(100);
      }

      await SecureStore.setItemAsync(this.LOCKED_KEY, 'true');

      // Benachrichtige App.tsx (setzt isAuthenticated = false)
      if (this.lockCallback) {
        this.lockCallback();
      }
    } catch (error) {
      console.error('Error triggering lock:', error);
    }
  }

  /**
   * Entsperrt (z.B. nach PIN Eingabe)
   */
  static async unlock(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(this.LOCKED_KEY);
      this.resetTimer();
      console.log('AutoLock: Vault unlocked');
    } catch (error) {
      console.error('Error unlocking:', error);
    }
  }

  // ─────────────────────────────── Settings Management ───────────────────────────────

  /**
   * Aktiviert Auto Lock
   */
  static async enable(timeoutSeconds: number = 60): Promise<void> {
    this.settings.enabled = true;
    this.settings.timeoutSeconds = timeoutSeconds;
    this.saveSettings();
    this.resetTimer();
  }

  /**
   * Deaktiviert Auto Lock
   */
  static async disable(): Promise<void> {
    this.settings.enabled = false;
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
    this.saveSettings();
  }

  /**
   * Prüft ob aktuell gesperrt
   */
  static async isLocked(): Promise<boolean> {
    try {
      const value = await SecureStore.getItemAsync(this.LOCKED_KEY);
      return value === 'true';
    } catch {
      return false;
    }
  }

  /**
   * Gibt verbleibende Zeit zurück
   */
  static getTimeRemaining(): number {
    if (!this.settings.enabled || !this.timeoutId) {
      return 0;
    }
    const elapsed = Date.now() - this.settings.lastActivity;
    const remaining = this.settings.timeoutSeconds * 1000 - elapsed;
    return Math.max(0, remaining);
  }

  /**
   * Verlängert die Zeit (z.B. bei aktiver Nutzung)
   */
  static extendTimeout(extraSeconds: number = 30): void {
    this.settings.lastActivity = Date.now() - (extraSeconds * 1000);
    this.resetTimer();
  }

  /**
   * Prüft ob Timeout bald erreicht wird
   */
  static async isNearTimeout(): Promise<boolean> {
    try {
      const lastActivity = await SecureStore.getItemAsync(this.LAST_ACTIVITY_KEY);
      if (!lastActivity) return false;

      const elapsed = Date.now() - parseInt(lastActivity, 10);
      const threshold = this.settings.timeoutSeconds * 1000 * 0.9; // 90%

      return elapsed >= threshold;
    } catch {
      return false;
    }
  }
}

export default AutoLockService;
