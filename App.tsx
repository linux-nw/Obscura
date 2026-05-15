import React, { useState, useEffect } from 'react';
import { View, StyleSheet, AppState, AppStateStatus } from 'react-native';
import AuthScreen from './src/screens/AuthScreen';
import MainScreen from './src/screens/MainScreen';
import { SecureCryptoService as CryptoService } from './src/services/CryptoService';
import { FileManager } from './src/services/FileManager';
import { NotesService } from './src/services/NotesService';

// Neue Enterprise Services importieren
import { XChaCha20CryptoService } from './src/services/XChaCha20CryptoService';
import { DeviceSecurityService } from './src/services/DeviceSecurityService';
import { MemoryProtection } from './src/services/MemorySafetyService';
import { ScreenProtectionService } from './src/services/ScreenProtectionService';
import { AutoLockService } from './src/services/AutoLockService';
import { PenTestService } from './src/services/PenTestService';
import { IntegrityService } from './src/services/IntegrityService';
import { PanicService } from './src/services/PanicService';
import { DecoyVaultService } from './src/services/DecoyVaultService';
import { SecureDeleteService } from './src/services/SecureDeleteService';
import { BackupService } from './src/services/BackupService';
import { KeyRotationService } from './src/services/KeyRotationService';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isFirstLaunch, setIsFirstLaunch] = useState<boolean | null>(null);
  const [isCryptoReady, setIsCryptoReady] = useState(false);
  const [appInitialized, setAppInitialized] = useState(false);
  const [securityStatus, setSecurityStatus] = useState<'secure' | 'warning' | 'critical'>('secure');

  // AppState für Background/Foreground Tracking
  useEffect(() => {
    const appStateSubscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
      if (nextAppState === 'background') {
        // Sofortige Sperrung bei Background
        AutoLockService.triggerLock();
        // Speicherschutz
        MemoryProtection.aggressiveZeroization();
      } else if (nextAppState === 'active' && isAuthenticated) {
        // Timer zurücksetzen bei Foreground
        AutoLockService.resetTimer();
      }
    });

    initializeApp();

    return () => {
      appStateSubscription.remove();
    };
  }, [isAuthenticated]);

  const initializeApp = async () => {
    try {
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

      // 8. Initialisiere Integrity Check
      await IntegrityService.checkIntegrity();
      console.log('IntegrityService check complete');

      // 9. Initialisiere Panic Service
      await PanicService.initialize();
      console.log('PanicService initialisiert');

      // 10. Initialisiere Decoy Vault
      await DecoyVaultService.initialize();
      console.log('DecoyVaultService initialisiert');

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
    const security = await DeviceSecurityService.checkDeviceSecurity();
    setSecurityStatus(security.securityLevel);

    setAppInitialized(true);
  };

  const handleAuthentication = async () => {
    setIsAuthenticated(true);
    // Timer zurücksetzen nach erfolgreicher Auth
    AutoLockService.resetTimer();
  };

  /**
   * Sicheres Logout - löscht alle sensitive Daten
   */
  const handleLogout = async () => {
    try {
      console.log('Logout: Lösche PIN-Hash...');
      await CryptoService.deletePinData();

      console.log('Logout: Lösche Verschlüsselungsschlüssel...');
      await CryptoService.deleteEncryptionKey();

      console.log('Logout: Setze App als nicht initialisiert...');
      await CryptoService.setAppInitialized(false);

      console.log('Logout: Nullt Speicher...');
      await MemoryProtection.aggressiveZeroization();

      setIsAuthenticated(false);
      console.log('Logout erfolgreich');
    } catch (error) {
      console.error('Logout-Fehler:', error);
      setIsAuthenticated(false);
    }
  };

  /**
   * Ändert die PIN
   */
  const handleChangePin = async (oldPin: string, newPin: string): Promise<boolean> => {
    try {
      const isValid = await CryptoService.verifyPin(oldPin);
      if (!isValid) {
        throw new Error('Alte PIN ist falsch');
      }

      const newKey = await CryptoService.deriveKeyFromPassphrase(newPin);
      await CryptoService.rotateEncryptionKey(newKey);
      await CryptoService.updatePinHash(newPin);

      // Key Rotation triggern
      await KeyRotationService.triggerManualRotation();

      console.log('PIN erfolgreich geändert');
      return true;
    } catch (error) {
      console.error('PIN-Änderung fehlgeschlagen:', error);
      return false;
    }
  };

  /**
   * Löscht den gesamten Tresor (Wipe)
   */
  const handleWipeVault = async (): Promise<void> => {
    try {
      console.log('Wipe: Lösche Dateien...');
      await FileManager.clearVault();

      console.log('Wipe: Lösche Notizen...');
      const notes = await NotesService.getNotes();
      for (const note of notes) {
        await NotesService.deleteNote(note.id);
      }

      console.log('Wipe: Lösche PIN...');
      await CryptoService.deletePinData();

      console.log('Wipe: Lösche Verschlüsselungsschlüssel...');
      await CryptoService.deleteEncryptionKey();

      console.log('Wipe: Nullt Speicher...');
      await MemoryProtection.aggressiveZeroization();

      console.log('Wipe: Setze App auf Erststart...');
      await CryptoService.setAppInitialized(false);

      console.log('Wipe abgeschlossen');
    } catch (error) {
      console.error('Wipe-Fehler:', error);
      throw new Error('Tresor konnte nicht geleert werden');
    }
  };

  // Security Check bei jeder App-Initialisierung
  useEffect(() => {
    const checkSecurity = async () => {
      const status = await DeviceSecurityService.checkDeviceSecurity();
      setSecurityStatus(status.securityLevel);

      if (status.detectedTampering) {
        // Tampering erkannt - sofortige Aktion
        await IntegrityService.triggerTamperResponse();
      }
    };
    checkSecurity();
  }, []);

  if (isFirstLaunch === null || !isCryptoReady) {
    return <View style={styles.blank} />;
  }

  return (
    <View style={styles.root}>
      {isAuthenticated ? (
        <MainScreen
          onLogout={handleLogout}
          onChangePin={handleChangePin}
          onWipeVault={handleWipeVault}
          securityStatus={securityStatus}
        />
      ) : (
        <AuthScreen
          onAuthenticate={handleAuthentication}
          isFirstLaunch={isFirstLaunch}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#090909' },
  blank: { flex: 1, backgroundColor: '#090909' },
});
