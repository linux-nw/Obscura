import React, { useState, useEffect, useRef } from 'react';
import { View, StyleSheet, AppState, AppStateStatus, NativeModules } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import AuthScreen from './src/screens/AuthScreen';
import MainScreen from './src/screens/MainScreen';
import VaultMark from './src/components/VaultMark';
import { loadObscuraFonts } from './src/fonts';
import { SecureCryptoService as CryptoService } from './src/services/CryptoService';
import { FileManager } from './src/services/FileManager';
import { NotesService } from './src/services/NotesService';

// F1: Aktiviere natives Argon2id (libsodium crypto_pwhash) GLOBAL, im Modul-Scope —
// garantiert bevor irgendeine KDF läuft. Ohne dies fiel alles auf PBKDF2 zurück.
// Das native Modul RNFileVault implementiert Argon2id (siehe RNFileVaultModule.kt).
try {
  (global as any).__argon2_native_available = !!(NativeModules as any).RNFileVault;
} catch {
  (global as any).__argon2_native_available = false;
}
console.log(
  `[KDF] Argon2id native available: ${(global as any).__argon2_native_available} ` +
  `(RNFileVault module ${(NativeModules as any).RNFileVault ? 'LOADED' : 'MISSING'})`
);

// Neue Enterprise Services importieren
import { XChaCha20CryptoService } from './src/services/XChaCha20CryptoService';
import { DeviceSecurityService } from './src/services/DeviceSecurityService';
import { ScreenProtectionService } from './src/services/ScreenProtectionService';
import { AutoLockService } from './src/services/AutoLockService';
import { PanicService } from './src/services/PanicService';
import { DecoyVaultService } from './src/services/DecoyVaultService';
import { BackupService } from './src/services/BackupService';
import { KeyRotationService } from './src/services/KeyRotationService';
import { HardwareBackedStorage } from './src/services/HardwareKeystoreService';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isFirstLaunch, setIsFirstLaunch]     = useState<boolean | null>(null);
  const [isCryptoReady, setIsCryptoReady]     = useState(false);
  const [securityStatus, setSecurityStatus]   = useState<'secure' | 'warning' | 'critical'>('secure');
  const [isDecoy, setIsDecoy]                 = useState(false);

  const isAuthRef = useRef(false);
  isAuthRef.current = isAuthenticated;

  // Einmalige Initialisierung + AppState-Tracking
  useEffect(() => {
    // AutoLock-Callback: sperrt UI wenn Timer abläuft oder App in Background geht
    AutoLockService.setLockCallback(() => {
      CryptoService.clearAllCaches();
      setIsAuthenticated(false);
    });

    const appStateSubscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
      if (nextAppState === 'background') {
        // F2/Picker: skip the lock+clear when a system picker is open — that
        // backgrounding is an expected, controlled in-app action and the master
        // key must survive until the picked file is encrypted and saved.
        if (AutoLockService.isPickerActive()) {
          return;
        }
        // Nur In-Memory Caches löschen — KEINE SecureStore-Keys löschen!
        CryptoService.clearAllCaches();
        AutoLockService.triggerLock();
      } else if (nextAppState === 'active') {
        // Returning from a picker: do not lock — let the save flow finish.
        if (AutoLockService.isPickerActive()) {
          return;
        }
        // Prüfe ob AutoLock ausgelöst hat
        AutoLockService.isLocked().then(locked => {
          if (locked && isAuthRef.current) {
            CryptoService.clearAllCaches();
            setIsAuthenticated(false);
          } else if (!locked && isAuthRef.current) {
            AutoLockService.resetTimer();
          }
        });
      }
    });

    initializeApp();

    return () => {
      appStateSubscription.remove();
    };
  }, []);

  const initializeApp = async () => {
    try {
      // 0. Lade Obscura-Schriften (best-effort, blockiert App-Start nicht bei Fehler)
      await loadObscuraFonts();

      // 1. Initialisiere Kryptografie-Service
      await CryptoService.initialize();
      await XChaCha20CryptoService.initialize();
      console.log('CryptoService initialisiert');

      // 2. Initialisiere Datei-Manager
      await FileManager.initialize();
      console.log('FileManager initialisiert');

      // 3. Initialisiere Notizen-Service
      await NotesService.initialize();
      console.log('NotesService initialisiert');

      // 4. Initialisiere Auto Lock Service
      await AutoLockService.initialize();
      console.log('AutoLockService initialisiert');

      // 5. Initialisiere Screen Protection
      await ScreenProtectionService.enableScreenCaptureBlocking();
      console.log('ScreenProtectionService enabled');

      // 6. Initialisiere Backup Service
      await BackupService.initialize();
      console.log('BackupService initialisiert');

      // 7. Initialisiere Key Rotation
      await KeyRotationService.initialize();
      console.log('KeyRotationService initialisiert');

      // 8. Initialisiere Panic Service (früher: IntegrityService — entfernt, da alle Checks Stubs waren)
      await PanicService.initialize();
      console.log('PanicService initialisiert');

      // 10. Initialisiere Decoy Vault
      await DecoyVaultService.initialize();
      console.log('DecoyVaultService initialisiert');

      // M3: warn (once) if the device likely lacks a hardware-backed keystore.
      try {
        const hw = await HardwareBackedStorage.assessHardwareBacking();
        if (!hw.likelyHardwareBacked) {
          console.warn(`[security] Hardware-backed key storage not detected (${hw.reason}). Keys are protected by software keystore only — reduced protection against a rooted/compromised device.`);
        }
      } catch {}

    } catch (error) {
      console.error('Fehler beim Initialisieren von Services:', error);
      try {
        console.log('Versuche erneute Initialisierung...');
      } catch (e) {
        console.error('Kritischer Fehler - App kann nicht starten');
      }
    }

    setIsCryptoReady(true);

    try {
      const launched = await CryptoService.isAppInitialized();
      setIsFirstLaunch(!launched);
    } catch {
      setIsFirstLaunch(true);
    }

    // Sicherheitscheck durchführen
    try {
      const security = await DeviceSecurityService.checkDeviceSecurity();
      setSecurityStatus(security.securityLevel);
    } catch {
      // security check failure is non-fatal
    }

  };

  const handleAuthentication = async () => {
    setIsFirstLaunch(false);
    // Check whether panic PIN was used to activate decoy vault.
    try {
      const decoyFlag = await SecureStore.getItemAsync('filevault_decoy_activated');
      setIsDecoy(decoyFlag === 'true');
    } catch {
      setIsDecoy(false);
    }
    setIsAuthenticated(true);
    AutoLockService.resetTimer();
  };

  /**
   * Tresor sperren — löscht NUR In-Memory Caches, behält alle gespeicherten Keys.
   */
  const handleLogout = () => {
    CryptoService.clearAllCaches();
    // Clear decoy flag so next real login shows real data.
    SecureStore.deleteItemAsync('filevault_decoy_activated').catch(() => {});
    setIsDecoy(false);
    setIsAuthenticated(false);
  };

  /**
   * Ändert das Passwort via KEK-Rewrapping.
   * Der Master-Key bleibt unverändert, nur die Verschlüsselung ändert sich.
   */
  const handleChangePin = async (oldPin: string, newPin: string): Promise<boolean> => {
    try {
      return await CryptoService.changePassphrase(oldPin, newPin);
    } catch (error) {
      console.error('PIN-Änderung fehlgeschlagen:', error);
      return false;
    }
  };

  /**
   * Löscht den gesamten Tresor unwiderruflich.
   */
  const handleWipeVault = async (): Promise<void> => {
    try {
      await FileManager.clearVault();

      const notes = await NotesService.getNotes();
      for (const note of notes) {
        await NotesService.deleteNote(note.id);
      }

      await CryptoService.deletePinData();
      await CryptoService.deleteEncryptionKey();
      CryptoService.clearAllCaches();
      await CryptoService.setAppInitialized(false);

      setIsFirstLaunch(true);
    } catch (error) {
      console.error('Wipe-Fehler:', error);
      throw new Error('Tresor konnte nicht geleert werden');
    }
  };

  if (isFirstLaunch === null || !isCryptoReady) {
    return (
      <View style={styles.splash}>
        <VaultMark size={64} spinning />
      </View>
    );
  }

  return (
    <SafeAreaProvider>
    <View style={styles.root}>
      {isAuthenticated ? (
        <MainScreen
          onLogout={handleLogout}
          onChangePin={handleChangePin}
          onWipeVault={handleWipeVault}
          securityStatus={securityStatus}
          isDecoy={isDecoy}
        />
      ) : (
        <AuthScreen
          onAuthenticate={handleAuthentication}
          isFirstLaunch={isFirstLaunch}
          onWipeVault={handleWipeVault}
        />
      )}
    </View>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0A0A0C' },
  splash: { flex: 1, backgroundColor: '#0A0A0C', alignItems: 'center', justifyContent: 'center' },
});
