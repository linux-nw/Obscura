import React, { useState, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet, ScrollView,
  Switch, Alert, TextInput, ActivityIndicator,
  StatusBar, Modal,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as DocumentPicker from 'expo-document-picker';
import { SettingsService, AppSettings, AutoLockTimeout } from '../services/SettingsService';
import { FileManager } from '../services/FileManager';
import { BackupService } from '../services/BackupService';
import { KeyRotationService } from '../services/KeyRotationService';
import { PanicService } from '../services/PanicService';
import { DecoyVaultService } from '../services/DecoyVaultService';
import { AutoLockService } from '../services/AutoLockService';
import { SecureCryptoService } from '../services/CryptoService';
import Icon from '../components/Icon';
import { c, rs, font, radius, SAFE_TOP, SAFE_BOTTOM, useBottomInset } from '../theme';

interface PassPrompt {
  title: string;
  sub: string;
  cta: string;
  minLen: number;
  run: (pass: string) => Promise<void>;
}

interface Props {
  visible: boolean;
  onClose: () => void;
  onChangePin: (oldPin: string, newPin: string) => Promise<boolean>;
  onWipeVault: () => Promise<void>;
  onLogout: () => void;
  securityStatus: 'secure' | 'warning' | 'critical';
  appVersion?: string;
  /** When true, render inline (as a tab) instead of wrapping in a fullscreen Modal. */
  embedded?: boolean;
}

const AUTO_LOCK_OPTIONS: { label: string; value: AutoLockTimeout }[] = [
  { label: 'Sofort', value: 0 },
  { label: '1 Min', value: 60 },
  { label: '5 Min', value: 300 },
  { label: '15 Min', value: 900 },
  { label: '30 Min', value: 1800 },
  { label: 'Nie', value: -1 },
];

type Screen = 'main' | 'pin_current' | 'pin_new' | 'pin_confirm';

export default function SettingsScreen({
  visible, onClose, onChangePin, onWipeVault, onLogout,
  securityStatus, appVersion = '1.0.0', embedded = false,
}: Props) {
  const [settings, setSettings] = useState<AppSettings>({
    biometricsEnabled: false,
    bioAutoTrigger: false,
    require2FA: false,
    autoLockTimeout: 300,
    maxFailedAttempts: 5,
    maxFailedAttemptsAction: 'wipe',
    minPinLength: 8,
  });
  const [biometricsAvailable, setBiometricsAvailable] = useState(false);
  const [storageUsed, setStorageUsed] = useState(0);
  const [storageTotal, setStorageTotal] = useState(100 * 1024 * 1024);
  const [loading, setLoading] = useState(false);
  const safeBot = useBottomInset();

  // PIN change — no nested modal, just a screen state
  const [screen, setScreen] = useState<Screen>('main');
  const [currentPin, setCurrentPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [pinSaving, setPinSaving] = useState(false);

  // Generic passphrase prompt (rotation / backup / restore)
  const [pp, setPp] = useState<PassPrompt | null>(null);
  const [ppVal, setPpVal] = useState('');
  const [ppBusy, setPpBusy] = useState(false);
  const [ppErr, setPpErr] = useState('');
  // Backup restore picker
  const [backups, setBackups] = useState<{ id: string; timestamp: number; size: number }[] | null>(null);
  const [dataBusy, setDataBusy] = useState(false);
  const [includeSettingsCb, setIncludeSettingsCb] = useState(false);

  // Panic PIN + Decoy Vault
  const [hasPanicPin, setHasPanicPin] = useState(false);
  const [panicTrigger, setPanicTrigger] = useState<'lock' | 'wipe'>('lock');
  const [hasDecoy, setHasDecoy] = useState(false);
  // Set-secret-PIN modal: two-field confirm (panic PIN / decoy PIN)
  const [spModal, setSpModal] = useState<{ title: string; sub: string; onSubmit: (pin: string) => Promise<void> } | null>(null);
  const [spNew, setSpNew] = useState('');
  const [spConfirm, setSpConfirm] = useState('');
  const [spBusy, setSpBusy] = useState(false);
  const [spErr, setSpErr] = useState('');

  const [showPinPass, setShowPinPass] = useState(false);
  const [showPpPass, setShowPpPass] = useState(false);
  const [showSpNew, setShowSpNew] = useState(false);
  const [showSpConfirm, setShowSpConfirm] = useState(false);

  useEffect(() => {
    if (visible) {
      setScreen('main');
      loadData();
    }
  }, [visible]);

  const loadData = async () => {
    try {
      const [s, bio] = await Promise.all([
        SettingsService.get(),
        checkBiometrics(),
      ]);
      setSettings(s);
      setBiometricsAvailable(bio);
    } catch {}

    try {
      const storage = await FileManager.getStorageUsage();
      setStorageUsed(storage.used);
      setStorageTotal(storage.total);
    } catch {}

    try {
      const [panicHas, decoyHas, trigger] = await Promise.all([
        PanicService.hasPanicPin(),
        DecoyVaultService.hasDecoyVault(),
        PanicService.getTriggerAction(),
      ]);
      setHasPanicPin(panicHas);
      setHasDecoy(decoyHas);
      setPanicTrigger(trigger);
    } catch {}
  };

  const checkBiometrics = async (): Promise<boolean> => {
    try {
      const hw = await LocalAuthentication.hasHardwareAsync();
      return !!(hw && await LocalAuthentication.isEnrolledAsync());
    } catch { return false; }
  };

  const updateSetting = async <K extends keyof AppSettings>(key: K, val: AppSettings[K]) => {
    const next = { ...settings, [key]: val };
    setSettings(next);
    await SettingsService.save(next);
  };

  // ── PIN change flow ──────────────────────────────────────────

  const startPinChange = () => {
    setCurrentPin(''); setNewPin(''); setConfirmPin('');
    setPinError('');
    setShowPinPass(false);
    setScreen('pin_current');
  };

  const handlePinNext = async () => {
    const minLen = 8;
    if (screen === 'pin_current') {
      if (currentPin.length < minLen) { setPinError(`Mindestens ${minLen} Zeichen`); return; }
      setPinError(''); setShowPinPass(false); setScreen('pin_new');
    } else if (screen === 'pin_new') {
      if (newPin.length < minLen) { setPinError(`Mindestens ${minLen} Zeichen`); return; }
      setPinError(''); setShowPinPass(false); setScreen('pin_confirm');
    } else if (screen === 'pin_confirm') {
      if (confirmPin !== newPin) {
        setPinError('PINs stimmen nicht überein');
        setConfirmPin('');
        return;
      }
      setPinSaving(true);
      try {
        const ok = await onChangePin(currentPin, newPin);
        if (ok) {
          setScreen('main');
          Alert.alert('Erfolg', 'PIN wurde geändert.');
        } else {
          setPinError('Aktuelle PIN ist falsch');
          setCurrentPin(''); setNewPin(''); setConfirmPin('');
          setScreen('pin_current');
        }
      } catch {
        setPinError('Fehler beim Ändern der PIN');
      } finally {
        setPinSaving(false);
      }
    }
  };

  // ── Vault wipe ───────────────────────────────────────────────

  const handleWipe = () => {
    Alert.alert(
      'Tresor leeren',
      'Dies löscht ALLE Dateien und Notizen ENDGÜLTIG und kann nicht rückgängig gemacht werden.',
      [
        { text: 'Abbrechen', style: 'cancel' },
        {
          text: 'Alles löschen', style: 'destructive',
          onPress: async () => {
            setLoading(true);
            try {
              await onWipeVault();
              onClose();
              onLogout();
            } catch {
              Alert.alert('Fehler', 'Tresor konnte nicht geleert werden.');
            } finally {
              setLoading(false);
            }
          },
        },
      ]
    );
  };

  // ── Data: key rotation + backup/restore ──────────────────────

  const openPrompt = (cfg: PassPrompt) => {
    setPpVal(''); setPpErr(''); setShowPpPass(false); setPp(cfg);
  };

  const submitPrompt = async () => {
    if (!pp) return;
    if (ppVal.length < pp.minLen) { setPpErr(`Mindestens ${pp.minLen} Zeichen`); return; }
    setPpBusy(true); setPpErr('');
    try {
      await pp.run(ppVal);
      setPp(null); setPpVal('');
    } catch (e: any) {
      setPpErr(e?.message || 'Vorgang fehlgeschlagen');
    } finally {
      setPpBusy(false);
    }
  };

  const handleRotate = () => openPrompt({
    title: 'Schlüssel rotieren',
    sub: 'Aktuelles Passwort eingeben. Alle Dateien und Notizen werden mit einem frischen Master-Schlüssel neu verschlüsselt.',
    cta: 'Rotieren',
    minLen: 8,
    run: async (pass) => {
      await KeyRotationService.performSecureRotation(pass);
      Alert.alert('Erfolg', 'Schlüssel rotiert — alle Daten neu verschlüsselt.');
    },
  });

  const handleBackupCreate = () => openPrompt({
    title: 'Backup erstellen',
    sub: 'Backup-Passwort wählen. Du brauchst es zum Wiederherstellen — es ist NICHT dein Tresor-Passwort.',
    cta: 'Erstellen',
    minLen: 8,
    run: async (pass) => {
      const id = await BackupService.createBackup(pass, includeSettingsCb);
      await BackupService.shareBackup(id);
    },
  });

  const handleImportFromFile = async () => {
    AutoLockService.beginPickerSession();
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: 'application/json',
        copyToCacheDirectory: true,
      });
      if (!result.canceled && result.assets?.[0]) {
        const uri = result.assets[0].uri;
        openPrompt({
          title: 'Backup entschlüsseln',
          sub: 'Backup-Passwort eingeben.',
          cta: 'Importieren',
          minLen: 1,
          run: async (pass) => {
            const ok = await BackupService.importBackupFromFile(pass, uri);
            if (!ok) throw new Error('Falsches Passwort oder beschädigtes Backup');
            Alert.alert('Importiert', 'Backup wurde wiederhergestellt.');
          },
        });
      }
    } catch (e) {
      Alert.alert('Fehler', String(e));
    } finally {
      AutoLockService.endPickerSession();
    }
  };

  const handleRestoreOpen = async () => {
    setDataBusy(true);
    try {
      const list = await BackupService.listBackups();
      if (list.length === 0) { Alert.alert('Keine Backups', 'Es wurde noch kein Backup erstellt.'); return; }
      setBackups(list);
    } catch {
      Alert.alert('Fehler', 'Backups konnten nicht geladen werden.');
    } finally {
      setDataBusy(false);
    }
  };

  const handleRestorePick = (b: { id: string }) => {
    setBackups(null);
    openPrompt({
      title: 'Backup wiederherstellen',
      sub: 'Backup-Passwort eingeben. Die Inhalte werden in den Tresor importiert.',
      cta: 'Wiederherstellen',
      minLen: 1,
      run: async (pass) => {
        const ok = await BackupService.restoreBackup(pass, b.id);
        if (!ok) throw new Error('Falsches Passwort oder beschädigtes Backup');
        Alert.alert('Wiederhergestellt', 'Backup wurde importiert.');
      },
    });
  };

  // ── Panic PIN + Decoy Vault handlers ─────────────────────────

  const openSetPinModal = (cfg: { title: string; sub: string; onSubmit: (pin: string) => Promise<void> }) => {
    setSpNew(''); setSpConfirm(''); setSpErr('');
    setShowSpNew(false); setShowSpConfirm(false);
    setSpModal(cfg);
  };

  const submitSetPin = async () => {
    if (!spModal) return;
    const minLen = 8;
    if (spNew.length < minLen) { setSpErr(`Mindestens ${minLen} Zeichen`); return; }
    if (spNew !== spConfirm) { setSpErr('PINs stimmen nicht überein'); setSpConfirm(''); return; }
    setSpBusy(true); setSpErr('');
    try {
      await spModal.onSubmit(spNew);
      setSpModal(null);
    } catch (e: any) {
      setSpErr(e?.message || 'Fehler beim Speichern');
    } finally {
      setSpBusy(false);
    }
  };

  const handleBioToggle = async (enable: boolean) => {
    if (!enable) {
      await SecureCryptoService.disableBioUnlock();
      await updateSetting('biometricsEnabled', false);
      return;
    }
    // Enable: ask passphrase so we can derive + store the bio KEK.
    // The SecureStore write with requireAuthentication triggers one intentional biometric prompt.
    openPrompt({
      title: 'Biometrie aktivieren',
      sub: 'Aktuelles Tresor-Passwort eingeben, um Biometrie freizuschalten.',
      cta: 'Aktivieren',
      minLen: 8,
      run: async (pass) => {
        const ok = await SecureCryptoService.enableBioUnlock(pass);
        if (!ok) throw new Error('Falsches Passwort');
        await updateSetting('biometricsEnabled', true);
      },
    });
  };

  const handleSetPanicPin = () => openSetPinModal({
    title: 'Panic-PIN setzen',
    sub: 'Diese PIN löst beim Entsperren eine Sicherheitsaktion aus. Nutze sie in Bedrohungsszenarien.',
    onSubmit: async (pin) => {
      await PanicService.setPanicPin(pin);
      setHasPanicPin(true);
      Alert.alert('Panic-PIN gesetzt', 'Eingabe dieser PIN beim Login löst die konfigurierte Aktion aus.');
    },
  });

  const handleClearPanicPin = () => {
    Alert.alert('Panic-PIN löschen', 'Die Panic-PIN wird deaktiviert.', [
      { text: 'Abbrechen', style: 'cancel' },
      { text: 'Löschen', style: 'destructive', onPress: async () => {
        await PanicService.clearPanicPin();
        setHasPanicPin(false);
      }},
    ]);
  };

  const handlePanicTrigger = async (action: 'lock' | 'wipe') => {
    await PanicService.setTriggerAction(action).catch(() => {});
    setPanicTrigger(action);
  };

  const handleToggleDecoy = async (enable: boolean) => {
    if (!enable) {
      Alert.alert('Täusch-Tresor deaktivieren', 'Alle Fake-Daten werden unwiderruflich gelöscht.', [
        { text: 'Abbrechen', style: 'cancel' },
        { text: 'Deaktivieren', style: 'destructive', onPress: async () => {
          await DecoyVaultService.destroyDecoyVault().catch(() => {});
          setHasDecoy(false);
        }},
      ]);
    } else {
      try {
        await DecoyVaultService.enableDecoyVault();
        await DecoyVaultService.createFakeFiles();
        await DecoyVaultService.createFakeNotes();
        setHasDecoy(true);
        Alert.alert('Täusch-Tresor aktiv', 'Fake-Daten wurden erstellt. Setze jetzt eine Täusch-PIN.');
      } catch {
        Alert.alert('Fehler', 'Täusch-Tresor konnte nicht aktiviert werden.');
      }
    }
  };

  const handleSetDecoyPin = () => openSetPinModal({
    title: 'Täusch-PIN setzen',
    sub: 'Eingabe dieser PIN beim Login öffnet den Täusch-Tresor statt des echten Tresors.',
    onSubmit: async (pin) => {
      await DecoyVaultService.setDecoyPin(pin);
      Alert.alert('Täusch-PIN gesetzt', 'Login mit dieser PIN öffnet künftig den Täusch-Tresor.');
    },
  });

  // ── Helpers ──────────────────────────────────────────────────

  const usedPct = storageTotal > 0 ? Math.min(storageUsed / storageTotal, 1) : 0;
  const fmtBytes = (b: number) => {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1024 / 1024).toFixed(1)} MB`;
  };
  const secColor = securityStatus === 'critical' ? c.danger
    : securityStatus === 'warning' ? c.warning : c.success;
  const secLabel = securityStatus === 'critical' ? 'Kritisch'
    : securityStatus === 'warning' ? 'Warnung' : 'Sicher';

  // ── PIN screen helpers ────────────────────────────────────────

  const pinScreenTitle = screen === 'pin_current' ? 'Aktuelles Passwort eingeben'
    : screen === 'pin_new' ? 'Neues Passwort wählen'
    : 'Neues Passwort bestätigen';
  const pinValue = screen === 'pin_current' ? currentPin
    : screen === 'pin_new' ? newPin : confirmPin;
  const setPinValue = screen === 'pin_current' ? setCurrentPin
    : screen === 'pin_new' ? setNewPin : setConfirmPin;

  // ── Render ───────────────────────────────────────────────────

  const body = (
      <View style={[s.root, embedded && s.rootEmbedded]}>
        {!embedded && <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />}

        {/* ── Header ── (hidden on the main screen when embedded as a tab) */}
        {(!embedded || screen !== 'main') && (
          <View style={s.header}>
            {screen !== 'main' ? (
              <TouchableOpacity style={s.headerSide} onPress={() => setScreen('main')} activeOpacity={0.7}>
                <Text style={s.headerBack}>‹ Zurück</Text>
              </TouchableOpacity>
            ) : (
              <View style={s.headerSide} />
            )}
            <Text style={s.headerTitle}>
              {screen === 'main' ? 'Einstellungen' : 'Passwort ändern'}
            </Text>
            {embedded ? (
              <View style={s.headerSide} />
            ) : (
              <TouchableOpacity style={s.headerSide} onPress={onClose} activeOpacity={0.7}>
                <Text style={s.headerDone}>Fertig</Text>
              </TouchableOpacity>
            )}
          </View>
        )}

        {/* ── PIN change screens ── */}
        {screen !== 'main' ? (
          <View style={s.pinPage}>
            <Text style={s.pinPageTitle}>{pinScreenTitle}</Text>

            <View style={s.pinSteps}>
              {(['pin_current', 'pin_new', 'pin_confirm'] as Screen[]).map((step, i) => (
                <View
                  key={step}
                  style={[s.pinStep, screen === step && s.pinStepActive]}
                />
              ))}
            </View>

            <View style={s.passField}>
              <Icon name="key" size={rs(17)} color={c.textTer} />
              <TextInput
                style={s.passInput}
                value={pinValue}
                onChangeText={v => { setPinValue(v.slice(0, 128)); setPinError(''); }}
                keyboardType="default"
                secureTextEntry={!showPinPass}
                placeholder="Passwort eingeben"
                placeholderTextColor={c.textTer}
                autoFocus
                autoCapitalize="none"
                autoCorrect={false}
                maxLength={128}
              />
              <TouchableOpacity
                style={s.eyeBtn}
                onPress={() => setShowPinPass(v => !v)}
                activeOpacity={0.7}
                hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
              >
                <Icon name={showPinPass ? 'eye-off' : 'eye'} size={rs(17)} color={c.textTer} />
              </TouchableOpacity>
            </View>

            {!!pinError && <Text style={s.pinError}>{pinError}</Text>}

            <View style={s.pinBtns}>
              <TouchableOpacity style={s.pinCancelBtn} onPress={() => setScreen('main')} activeOpacity={0.7}>
                <Text style={s.pinCancelTxt}>Abbrechen</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[s.pinNextBtn, (pinValue.length < 8 || pinSaving) && s.pinNextDisabled]}
                onPress={handlePinNext}
                disabled={pinValue.length < 8 || pinSaving}
                activeOpacity={0.7}
              >
                {pinSaving
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={s.pinNextTxt}>{screen === 'pin_confirm' ? 'Speichern' : 'Weiter'}</Text>
                }
              </TouchableOpacity>
            </View>
          </View>
        ) : (

          /* ── Main settings ── */
          <ScrollView
            style={s.scroll}
            contentContainerStyle={[s.content, { paddingBottom: safeBot + rs(24) }]}
            showsVerticalScrollIndicator={false}
            keyboardShouldPersistTaps="handled"
          >

            {/* ─── KONTO ─── */}
            <Text style={s.sectionLabel}>KONTO</Text>
            <View style={s.card}>

              <TouchableOpacity style={s.row} onPress={startPinChange} activeOpacity={0.7}>
                <View style={s.rowIcon}><Icon name="key" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Passwort ändern</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>

              <View style={s.sep} />

              <TouchableOpacity
                style={s.row}
                onPress={() => { onClose(); setTimeout(onLogout, 300); }}
                activeOpacity={0.7}
              >
                <View style={s.rowIcon}><Icon name="log-out" size={rs(17)} color={c.accent} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Tresor sperren</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>
            </View>

            {/* ─── SICHERHEIT ─── */}
            <Text style={s.sectionLabel}>SICHERHEIT</Text>
            <View style={s.card}>

              {/* Biometrie */}
              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="fingerprint" size={rs(17)} color={c.accent} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Biometrie</Text>
                  <Text style={s.rowSub}>
                    {biometricsAvailable ? 'Face ID / Touch ID' : 'Kein biometrischer Sensor'}
                  </Text>
                </View>
                <Switch
                  value={settings.biometricsEnabled && biometricsAvailable}
                  onValueChange={handleBioToggle}
                  disabled={!biometricsAvailable}
                  trackColor={{ false: c.border, true: c.accent }}
                  thumbColor="#fff"
                />
              </View>

              <View style={s.sep} />

              {/* Bio auto-trigger (only when bio is on) */}
              {settings.biometricsEnabled && biometricsAvailable && (
                <>
                  <View style={s.row}>
                    <View style={s.rowIcon}><Icon name="scan-face" size={rs(17)} color={c.textSec} /></View>
                    <View style={s.rowInfo}>
                      <Text style={s.rowTitle}>Automatisch beim Start</Text>
                      <Text style={s.rowSub}>Biometrie-Abfrage ohne Button-Druck</Text>
                    </View>
                    <Switch
                      value={settings.bioAutoTrigger}
                      onValueChange={v => updateSetting('bioAutoTrigger', v)}
                      trackColor={{ false: c.border, true: c.accent }}
                      thumbColor="#fff"
                    />
                  </View>
                  <View style={s.sep} />
                </>
              )}

              {/* 2FA */}
              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="shield-check" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={[s.rowTitle, (!biometricsAvailable || !settings.biometricsEnabled) && s.dimmed]}>
                    2FA-Modus
                  </Text>
                  <Text style={[s.rowSub, (!biometricsAvailable || !settings.biometricsEnabled) && s.dimmed]}>
                    {settings.require2FA && settings.biometricsEnabled
                      ? 'Biometrie UND Passwort — beide erforderlich'
                      : 'Aus: Biometrie reicht zum Entsperren'}
                  </Text>
                </View>
                <Switch
                  value={settings.require2FA && biometricsAvailable && settings.biometricsEnabled}
                  onValueChange={v => updateSetting('require2FA', v)}
                  disabled={!biometricsAvailable || !settings.biometricsEnabled}
                  trackColor={{ false: c.border, true: c.accent }}
                  thumbColor="#fff"
                />
              </View>

              <View style={s.sep} />

              {/* Auto-Sperre */}
              <View style={s.block}>
                <View style={s.blockHeader}>
                  <View style={s.rowIcon}><Icon name="clock" size={rs(17)} color={c.textSec} /></View>
                  <View style={s.rowInfo}>
                    <Text style={s.rowTitle}>Auto-Sperre</Text>
                    <Text style={s.rowSub}>Sperren nach Inaktivität</Text>
                  </View>
                </View>
                <View style={s.chips}>
                  {AUTO_LOCK_OPTIONS.map(opt => (
                    <TouchableOpacity
                      key={String(opt.value)}
                      style={[s.chip, settings.autoLockTimeout === opt.value && s.chipOn]}
                      onPress={() => updateSetting('autoLockTimeout', opt.value)}
                      activeOpacity={0.7}
                    >
                      <Text style={[s.chipTxt, settings.autoLockTimeout === opt.value && s.chipTxtOn]}>
                        {opt.label}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              <View style={s.sep} />

              {/* Max. Fehlversuche */}
              <View style={s.block}>
                <View style={s.blockHeader}>
                  <View style={s.rowIcon}><Icon name="alert-triangle" size={rs(17)} color={c.textSec} /></View>
                  <View style={s.rowInfo}>
                    <Text style={s.rowTitle}>Max. Fehlversuche</Text>
                    <Text style={s.rowSub}>Danach: Tresor gesperrt</Text>
                  </View>
                </View>
                <View style={s.chips}>
                  {[3, 5, 10].map(n => (
                    <TouchableOpacity
                      key={n}
                      style={[s.chip, settings.maxFailedAttempts === n && s.chipOn]}
                      onPress={() => updateSetting('maxFailedAttempts', n)}
                      activeOpacity={0.7}
                    >
                      <Text style={[s.chipTxt, settings.maxFailedAttempts === n && s.chipTxtOn]}>
                        {n}×
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              <View style={s.sep} />

              {/* Aktion bei max. Fehlversuchen */}
              <View style={s.block}>
                <View style={s.blockHeader}>
                  <View style={s.rowIcon}><Icon name="shield-off" size={rs(17)} color={c.textSec} /></View>
                  <View style={s.rowInfo}>
                    <Text style={s.rowTitle}>Aktion bei max. Fehlversuchen</Text>
                    <Text style={s.rowSub}>Was bei zu vielen falschen Passwörtern passiert</Text>
                  </View>
                </View>
                <View style={s.chips}>
                  {([
                    { label: 'Sperren', value: 'lock' as const },
                    { label: 'Löschen', value: 'wipe' as const },
                  ]).map(opt => (
                    <TouchableOpacity
                      key={opt.value}
                      style={[s.chip, settings.maxFailedAttemptsAction === opt.value && s.chipOn]}
                      onPress={() => updateSetting('maxFailedAttemptsAction', opt.value)}
                      activeOpacity={0.7}
                    >
                      <Text style={[s.chipTxt, settings.maxFailedAttemptsAction === opt.value && s.chipTxtOn]}>
                        {opt.label}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

            </View>

            {/* ─── DATEN ─── */}
            <Text style={s.sectionLabel}>DATEN</Text>
            <View style={s.card}>

              <TouchableOpacity style={s.row} onPress={handleRotate} activeOpacity={0.7} disabled={dataBusy}>
                <View style={s.rowIcon}><Icon name="rotate-ccw" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Schlüssel rotieren</Text>
                  <Text style={s.rowSub}>Neuer Master-Key, alle Daten neu verschlüsselt</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>

              <View style={s.sep} />

              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="settings" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Einstellungen einschließen</Text>
                  <Text style={s.rowSub}>App-Einstellungen ins Backup aufnehmen</Text>
                </View>
                <Switch
                  value={includeSettingsCb}
                  onValueChange={setIncludeSettingsCb}
                  trackColor={{ false: c.border2, true: c.accentBorder }}
                  thumbColor={includeSettingsCb ? c.accent : c.textTer}
                />
              </View>

              <View style={s.sep} />

              <TouchableOpacity style={s.row} onPress={handleBackupCreate} activeOpacity={0.7} disabled={dataBusy}>
                <View style={s.rowIcon}><Icon name="hard-drive" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Backup erstellen</Text>
                  <Text style={s.rowSub}>Verschlüsseltes Backup mit eigenem Passwort</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>

              <View style={s.sep} />

              <TouchableOpacity style={s.row} onPress={handleRestoreOpen} activeOpacity={0.7} disabled={dataBusy}>
                <View style={s.rowIcon}><Icon name="download" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Backup wiederherstellen</Text>
                  <Text style={s.rowSub}>Inhalte aus einem Backup importieren</Text>
                </View>
                {dataBusy
                  ? <ActivityIndicator size="small" color={c.accent} />
                  : <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
                }
              </TouchableOpacity>

              <View style={s.sep} />

              <TouchableOpacity style={s.row} onPress={handleImportFromFile} activeOpacity={0.7} disabled={dataBusy}>
                <View style={s.rowIcon}><Icon name="upload" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Aus Datei importieren</Text>
                  <Text style={s.rowSub}>Backup-Datei (.json) von Gerät laden</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>
            </View>

            {/* ─── PANIC-PIN ─── */}
            <Text style={s.sectionLabel}>PANIC-PIN</Text>
            <View style={s.card}>

              <View style={s.row}>
                <View style={[s.rowIcon, s.rowIconDanger]}>
                  <Icon name="alert-triangle" size={rs(17)} color={c.danger} />
                </View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Status</Text>
                  <Text style={s.rowSub}>{hasPanicPin ? 'Aktiv — Panic-PIN konfiguriert' : 'Nicht konfiguriert'}</Text>
                </View>
                {hasPanicPin && (
                  <TouchableOpacity onPress={handleClearPanicPin} activeOpacity={0.7} style={s.trailingBtn}>
                    <Icon name="x" size={rs(17)} color={c.danger} />
                  </TouchableOpacity>
                )}
              </View>

              <View style={s.sep} />

              <TouchableOpacity style={s.row} onPress={handleSetPanicPin} activeOpacity={0.7}>
                <View style={s.rowIcon}><Icon name="key" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>{hasPanicPin ? 'Panic-PIN ändern' : 'Panic-PIN setzen'}</Text>
                  <Text style={s.rowSub}>Notfall-Passphrase für Bedrohungsszenarien</Text>
                </View>
                <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
              </TouchableOpacity>

              <View style={s.sep} />

              <View style={s.block}>
                <View style={s.blockHeader}>
                  <View style={s.rowIcon}><Icon name="zap" size={rs(17)} color={c.textSec} /></View>
                  <View style={s.rowInfo}>
                    <Text style={[s.rowTitle, !hasPanicPin && s.dimmed]}>Aktion bei Panic-PIN</Text>
                    <Text style={[s.rowSub, !hasPanicPin && s.dimmed]}>Was passiert bei Panic-Eingabe</Text>
                  </View>
                </View>
                <View style={s.chips}>
                  {([
                    { label: 'Sperren', value: 'lock' as const },
                    { label: 'Löschen', value: 'wipe' as const },
                  ]).map(opt => (
                    <TouchableOpacity
                      key={opt.value}
                      style={[s.chip, panicTrigger === opt.value && s.chipOn]}
                      onPress={() => handlePanicTrigger(opt.value)}
                      disabled={!hasPanicPin}
                      activeOpacity={0.7}
                    >
                      <Text style={[s.chipTxt, panicTrigger === opt.value && s.chipTxtOn, !hasPanicPin && { opacity: 0.35 }]}>
                        {opt.label}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>
            </View>

            {/* ─── TÄUSCH-TRESOR ─── */}
            <Text style={s.sectionLabel}>TÄUSCH-TRESOR</Text>
            <View style={s.card}>

              <View style={s.row}>
                <View style={[s.rowIcon, { backgroundColor: c.purpleDim }]}>
                  <Icon name="layers" size={rs(17)} color={c.purple} />
                </View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Täusch-Tresor</Text>
                  <Text style={s.rowSub}>Zeigt Fake-Daten in Bedrohungsszenarien</Text>
                </View>
                <Switch
                  value={hasDecoy}
                  onValueChange={handleToggleDecoy}
                  trackColor={{ false: c.border, true: c.purple }}
                  thumbColor="#fff"
                />
              </View>

              {hasDecoy && (
                <>
                  <View style={s.sep} />
                  <TouchableOpacity style={s.row} onPress={handleSetDecoyPin} activeOpacity={0.7}>
                    <View style={s.rowIcon}><Icon name="key" size={rs(17)} color={c.textSec} /></View>
                    <View style={s.rowInfo}>
                      <Text style={s.rowTitle}>Täusch-PIN setzen</Text>
                      <Text style={s.rowSub}>Öffnet bei Login den Täusch-Tresor</Text>
                    </View>
                    <Icon name="chevron-right" size={rs(17)} color={c.textFaint} />
                  </TouchableOpacity>
                </>
              )}
            </View>

            {/* ─── SPEICHER ─── */}
            <Text style={s.sectionLabel}>SPEICHER</Text>
            <View style={s.card}>

              <View style={s.block}>
                <View style={s.storageRow}>
                  <Text style={s.storageLabel}>Belegt</Text>
                  <Text style={s.storageValue}>{fmtBytes(storageUsed)} / {fmtBytes(storageTotal)}</Text>
                </View>
                <View style={s.storageBar}>
                  <View style={[s.storageBarFill, { width: `${Math.round(usedPct * 100)}%` }]} />
                </View>
              </View>

              <View style={s.sep} />

              <TouchableOpacity style={s.row} onPress={handleWipe} activeOpacity={0.7} disabled={loading}>
                <View style={[s.rowIcon, s.rowIconDanger]}><Icon name="trash-2" size={rs(17)} color={c.danger} /></View>
                <View style={s.rowInfo}>
                  <Text style={[s.rowTitle, { color: c.danger }]}>Tresor leeren</Text>
                  <Text style={s.rowSub}>Alle Daten endgültig löschen</Text>
                </View>
                {loading
                  ? <ActivityIndicator size="small" color={c.danger} />
                  : <Icon name="chevron-right" size={rs(17)} color={c.danger} />
                }
              </TouchableOpacity>
            </View>

            {/* ─── APP ─── */}
            <Text style={s.sectionLabel}>APP</Text>
            <View style={s.card}>

              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="shield" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Sicherheitsstatus</Text>
                </View>
                <View style={[s.badge, { backgroundColor: secColor + '22' }]}>
                  <View style={[s.badgeDot, { backgroundColor: secColor }]} />
                  <Text style={[s.badgeTxt, { color: secColor }]}>{secLabel}</Text>
                </View>
              </View>

              <View style={s.sep} />

              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="info" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Version</Text>
                </View>
                <Text style={s.rowVal}>Obscura {appVersion}</Text>
              </View>

              <View style={s.sep} />

              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="lock" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Verschlüsselung</Text>
                </View>
                <Text style={s.rowVal}>XChaCha20-Poly1305</Text>
              </View>

              <View style={s.sep} />

              <View style={s.row}>
                <View style={s.rowIcon}><Icon name="key" size={rs(17)} color={c.textSec} /></View>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Key Derivation</Text>
                </View>
                <Text style={s.rowVal}>Argon2id / PBKDF2</Text>
              </View>

            </View>

          </ScrollView>
        )}

        {/* ── Backup restore picker ── */}
        <Modal visible={backups !== null} transparent animationType="fade" onRequestClose={() => setBackups(null)}>
          <View style={s.promptOverlay}>
            <View style={s.promptBox}>
              <Text style={s.promptTitle}>Backup wählen</Text>
              <ScrollView style={{ maxHeight: rs(280) }}>
                {(backups ?? []).map((b) => (
                  <TouchableOpacity key={b.id} style={s.backupRow} onPress={() => handleRestorePick(b)} activeOpacity={0.7}>
                    <Text style={s.backupId}>{b.id}</Text>
                    <Text style={s.backupMeta}>{fmtBytes(b.size)}</Text>
                  </TouchableOpacity>
                ))}
              </ScrollView>
              <TouchableOpacity style={s.pinCancelBtn} onPress={() => setBackups(null)} activeOpacity={0.7}>
                <Text style={s.pinCancelTxt}>Abbrechen</Text>
              </TouchableOpacity>
            </View>
          </View>
        </Modal>

        {/* ── Set-secret-PIN modal (panic PIN / decoy PIN) — two-field confirm ── */}
        <Modal visible={spModal !== null} transparent animationType="fade" onRequestClose={() => !spBusy && setSpModal(null)}>
          <View style={s.promptOverlay}>
            <View style={s.promptBox}>
              <Text style={s.promptTitle}>{spModal?.title}</Text>
              <Text style={s.promptSub}>{spModal?.sub}</Text>
              <View style={[s.passField, { marginBottom: rs(8) }]}>
                <Icon name="key" size={rs(17)} color={c.textTer} />
                <TextInput
                  style={s.passInput}
                  value={spNew}
                  onChangeText={(v) => { setSpNew(v.slice(0, 128)); setSpErr(''); }}
                  secureTextEntry={!showSpNew}
                  placeholder="Neue PIN (min. 8 Zeichen)"
                  placeholderTextColor={c.textTer}
                  autoFocus
                  autoCapitalize="none"
                  autoCorrect={false}
                  maxLength={128}
                  editable={!spBusy}
                />
                <TouchableOpacity
                  style={s.eyeBtn}
                  onPress={() => setShowSpNew(v => !v)}
                  activeOpacity={0.7}
                  hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
                >
                  <Icon name={showSpNew ? 'eye-off' : 'eye'} size={rs(17)} color={c.textTer} />
                </TouchableOpacity>
              </View>
              <View style={s.passField}>
                <Icon name="key" size={rs(17)} color={c.textTer} />
                <TextInput
                  style={s.passInput}
                  value={spConfirm}
                  onChangeText={(v) => { setSpConfirm(v.slice(0, 128)); setSpErr(''); }}
                  secureTextEntry={!showSpConfirm}
                  placeholder="PIN bestätigen"
                  placeholderTextColor={c.textTer}
                  autoCapitalize="none"
                  autoCorrect={false}
                  maxLength={128}
                  editable={!spBusy}
                />
                <TouchableOpacity
                  style={s.eyeBtn}
                  onPress={() => setShowSpConfirm(v => !v)}
                  activeOpacity={0.7}
                  hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
                >
                  <Icon name={showSpConfirm ? 'eye-off' : 'eye'} size={rs(17)} color={c.textTer} />
                </TouchableOpacity>
              </View>
              {!!spErr && <Text style={s.pinError}>{spErr}</Text>}
              <View style={s.pinBtns}>
                <TouchableOpacity style={s.pinCancelBtn} onPress={() => !spBusy && setSpModal(null)} activeOpacity={0.7} disabled={spBusy}>
                  <Text style={s.pinCancelTxt}>Abbrechen</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[s.pinNextBtn, spBusy && s.pinNextDisabled]}
                  onPress={submitSetPin}
                  disabled={spBusy}
                  activeOpacity={0.7}
                >
                  {spBusy
                    ? <ActivityIndicator color="#fff" size="small" />
                    : <Text style={s.pinNextTxt}>Speichern</Text>
                  }
                </TouchableOpacity>
              </View>
            </View>
          </View>
        </Modal>

        {/* ── Generic passphrase prompt ── */}
        <Modal visible={pp !== null} transparent animationType="fade" onRequestClose={() => !ppBusy && setPp(null)}>
          <View style={s.promptOverlay}>
            <View style={s.promptBox}>
              <Text style={s.promptTitle}>{pp?.title}</Text>
              <Text style={s.promptSub}>{pp?.sub}</Text>
              <View style={s.passField}>
                <Icon name="key" size={rs(17)} color={c.textTer} />
                <TextInput
                  style={s.passInput}
                  value={ppVal}
                  onChangeText={(v) => { setPpVal(v.slice(0, 128)); setPpErr(''); }}
                  secureTextEntry={!showPpPass}
                  placeholder="Passwort eingeben"
                  placeholderTextColor={c.textTer}
                  autoFocus
                  autoCapitalize="none"
                  autoCorrect={false}
                  maxLength={128}
                  editable={!ppBusy}
                />
                <TouchableOpacity
                  style={s.eyeBtn}
                  onPress={() => setShowPpPass(v => !v)}
                  activeOpacity={0.7}
                  hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
                >
                  <Icon name={showPpPass ? 'eye-off' : 'eye'} size={rs(17)} color={c.textTer} />
                </TouchableOpacity>
              </View>
              {!!ppErr && <Text style={s.pinError}>{ppErr}</Text>}
              <View style={s.pinBtns}>
                <TouchableOpacity style={s.pinCancelBtn} onPress={() => !ppBusy && setPp(null)} activeOpacity={0.7} disabled={ppBusy}>
                  <Text style={s.pinCancelTxt}>Abbrechen</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[s.pinNextBtn, ppBusy && s.pinNextDisabled]}
                  onPress={submitPrompt}
                  disabled={ppBusy}
                  activeOpacity={0.7}
                >
                  {ppBusy
                    ? <ActivityIndicator color="#fff" size="small" />
                    : <Text style={s.pinNextTxt}>{pp?.cta}</Text>}
                </TouchableOpacity>
              </View>
            </View>
          </View>
        </Modal>
      </View>
  );

  if (embedded) return body;
  return (
    <Modal
      visible={visible}
      animationType="slide"
      presentationStyle="fullScreen"
      onRequestClose={() => screen === 'main' ? onClose() : setScreen('main')}
    >
      {body}
    </Modal>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────

const s = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: c.bg,
    paddingTop: SAFE_TOP,
  },
  rootEmbedded: {
    paddingTop: 0,
  },

  // Header
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: rs(16),
    paddingVertical: rs(14),
    borderBottomWidth: 1,
    borderBottomColor: c.border,
  },
  headerSide: { minWidth: rs(70) },
  headerTitle: { fontFamily: font.monoBold, fontSize: rs(12), letterSpacing: rs(1.5), textTransform: 'uppercase', color: c.text, textAlign: 'center' },
  headerDone: { fontFamily: font.mono, fontSize: rs(14), color: c.accent, textAlign: 'right' },
  headerBack: { fontFamily: font.mono, fontSize: rs(14), color: c.accent },

  // Main scroll
  scroll: { flex: 1 },
  content: { padding: rs(16) },

  // Section label
  sectionLabel: {
    fontFamily: font.monoBold,
    fontSize: rs(10),
    color: c.textTer,
    letterSpacing: rs(2),
    textTransform: 'uppercase',
    marginTop: rs(22),
    marginBottom: rs(8),
    marginLeft: rs(4),
  },

  // Card
  card: {
    backgroundColor: c.surface,
    borderRadius: radius.card,
    borderWidth: 1,
    borderColor: c.border,
  },

  // Row
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: rs(13),
    paddingHorizontal: rs(15),
    gap: rs(13),
    minHeight: rs(54),
  },
  rowIcon: {
    width: rs(30), height: rs(30), borderRadius: rs(2),
    backgroundColor: c.surface2,
    alignItems: 'center', justifyContent: 'center',
  },
  rowIconDanger: { backgroundColor: c.dangerDim },
  rowInfo: { flex: 1 },
  rowTitle: { fontFamily: font.sansMed, fontSize: rs(15), color: c.text },
  rowSub: { fontFamily: font.sans, fontSize: rs(12), color: c.textTer, marginTop: rs(2) },
  rowVal: { fontFamily: font.mono, fontSize: rs(12), color: c.textTer },
  dimmed: { opacity: 0.4 },

  // Block (for chips section)
  block: { paddingVertical: rs(13), paddingHorizontal: rs(14), gap: rs(10) },
  blockHeader: { flexDirection: 'row', alignItems: 'center', gap: rs(12) },

  // Separator
  sep: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: c.sep,
    marginLeft: rs(54),
  },

  // Chips
  chips: { flexDirection: 'row', flexWrap: 'wrap', gap: rs(8), paddingLeft: rs(43) },
  chip: {
    paddingHorizontal: rs(12),
    paddingVertical: rs(7),
    borderRadius: radius.input,
    backgroundColor: c.inset,
    borderWidth: 1,
    borderColor: c.border2,
  },
  chipOn: { backgroundColor: c.accentDim, borderColor: c.accentBorder },
  chipTxt: { fontFamily: font.mono, fontSize: rs(12), color: c.textSec },
  chipTxtOn: { color: c.accent },

  // Storage bar
  storageRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: rs(8) },
  storageLabel: { fontFamily: font.mono, fontSize: rs(12), color: c.textSec },
  storageValue: { fontFamily: font.mono, fontSize: rs(12), color: c.textSec },
  storageBar: {
    height: rs(4),
    backgroundColor: c.inset,
    overflow: 'hidden',
  },
  storageBarFill: {
    height: '100%',
    backgroundColor: c.accent,
  },

  // Status badge
  badge: { flexDirection: 'row', alignItems: 'center', gap: rs(5), paddingHorizontal: rs(8), paddingVertical: rs(4), borderRadius: rs(2) },
  badgeDot: { width: rs(6), height: rs(6) },
  badgeTxt: { fontFamily: font.monoBold, fontSize: rs(10), letterSpacing: rs(0.5), textTransform: 'uppercase' },

  // Min PIN length stepper
  sliderContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(12),
    paddingLeft: rs(40),
    paddingTop: rs(4),
  },
  sliderValue: {
    fontFamily: font.monoBold,
    fontSize: rs(18),
    color: c.accent,
    minWidth: rs(28),
    textAlign: 'center',
  },
  sliderTrack: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(6),
  },
  sliderDot: {
    flex: 1,
    height: rs(8),
    backgroundColor: c.border2,
  },
  sliderDotActive: {
    backgroundColor: c.accent,
    height: rs(10),
  },

  // Password field with eye toggle (shared across PIN change + modals)
  passField: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(11),
    backgroundColor: c.inset,
    borderRadius: radius.input,
    borderWidth: 1,
    borderColor: c.border2,
    paddingHorizontal: rs(14),
    height: rs(58),
    marginBottom: rs(12),
  },
  passInput: {
    flex: 1,
    fontFamily: font.mono,
    fontSize: rs(16),
    color: c.text,
    letterSpacing: rs(0.6),
    padding: 0,
  },
  eyeBtn: {
    padding: rs(6),
  },

  // PIN change page
  pinPage: {
    flex: 1,
    padding: rs(24),
  },
  pinPageTitle: {
    fontFamily: font.displayBold,
    fontSize: rs(22),
    color: c.text,
    marginBottom: rs(20),
  },
  pinSteps: {
    flexDirection: 'row',
    gap: rs(6),
    marginBottom: rs(24),
  },
  pinStep: {
    flex: 1,
    height: rs(4),
    backgroundColor: c.border2,
  },
  pinStepActive: {
    backgroundColor: c.accent,
  },
  pinInput: {
    backgroundColor: c.inset,
    borderRadius: radius.input,
    borderWidth: 1,
    borderColor: c.border2,
    paddingHorizontal: rs(16),
    paddingVertical: rs(16),
    fontFamily: font.mono,
    fontSize: rs(18),
    color: c.text,
    letterSpacing: rs(4),
    marginBottom: rs(12),
  },
  pinError: {
    fontFamily: font.mono,
    fontSize: rs(12),
    color: c.danger,
    marginBottom: rs(12),
  },
  pinBtns: { flexDirection: 'row', gap: rs(12), marginTop: rs(8) },
  pinCancelBtn: {
    flex: 1,
    paddingVertical: rs(14),
    borderRadius: radius.btn,
    backgroundColor: 'transparent',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: c.border2,
  },
  pinCancelTxt: { fontFamily: font.monoBold, fontSize: rs(13), letterSpacing: rs(1), textTransform: 'uppercase', color: c.textSec },
  pinNextBtn: {
    flex: 1,
    paddingVertical: rs(14),
    borderRadius: radius.btn,
    backgroundColor: c.accent,
    alignItems: 'center',
  },
  pinNextDisabled: { backgroundColor: c.surface2 },
  pinNextTxt: { fontFamily: font.monoBold, fontSize: rs(13), letterSpacing: rs(1), textTransform: 'uppercase', color: c.accentFg },

  // Prompt / picker modals
  promptOverlay: {
    flex: 1,
    backgroundColor: '#000000aa',
    justifyContent: 'center',
    padding: rs(24),
  },
  promptBox: {
    backgroundColor: c.surface,
    borderRadius: radius.card,
    borderWidth: 1,
    borderColor: c.border2,
    padding: rs(20),
    gap: rs(8),
  },
  promptTitle: { fontFamily: font.displaySemi, fontSize: rs(17), color: c.text },
  promptSub: { fontFamily: font.sans, fontSize: rs(13), color: c.textSec, marginBottom: rs(8) },
  backupRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: rs(12),
    paddingHorizontal: rs(8),
    borderBottomWidth: 1,
    borderBottomColor: c.border,
  },
  backupId: { fontFamily: font.mono, fontSize: rs(12), color: c.text, flex: 1 },
  backupMeta: { fontFamily: font.mono, fontSize: rs(11), color: c.textSec, marginLeft: rs(8) },
  trailingBtn: {
    width: rs(34),
    height: rs(34),
    alignItems: 'center',
    justifyContent: 'center',
  },
});
