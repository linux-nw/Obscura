import React, { useState, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet, ScrollView,
  Switch, Alert, TextInput, ActivityIndicator,
  StatusBar, Modal,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import { SettingsService, AppSettings, AutoLockTimeout } from '../services/SettingsService';
import { FileManager } from '../services/FileManager';
import { c, rs, SAFE_TOP, SAFE_BOTTOM } from '../theme';

interface Props {
  visible: boolean;
  onClose: () => void;
  onChangePin: (oldPin: string, newPin: string) => Promise<boolean>;
  onWipeVault: () => Promise<void>;
  onLogout: () => void;
  securityStatus: 'secure' | 'warning' | 'critical';
  appVersion?: string;
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
  securityStatus, appVersion = '1.0.0',
}: Props) {
  const [settings, setSettings] = useState<AppSettings>({
    biometricsEnabled: true,
    require2FA: false,
    autoLockTimeout: 300,
    maxFailedAttempts: 5,
    minPinLength: 6,
  });
  const [biometricsAvailable, setBiometricsAvailable] = useState(false);
  const [storageUsed, setStorageUsed] = useState(0);
  const [storageTotal, setStorageTotal] = useState(100 * 1024 * 1024);
  const [loading, setLoading] = useState(false);

  // PIN change — no nested modal, just a screen state
  const [screen, setScreen] = useState<Screen>('main');
  const [currentPin, setCurrentPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [pinSaving, setPinSaving] = useState(false);

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
    setScreen('pin_current');
  };

  const handlePinNext = async () => {
    const minLen = settings.minPinLength;
    if (screen === 'pin_current') {
      if (currentPin.length < minLen) { setPinError(`Mindestens ${minLen} Zeichen`); return; }
      setPinError(''); setScreen('pin_new');
    } else if (screen === 'pin_new') {
      if (newPin.length < minLen) { setPinError(`Mindestens ${minLen} Zeichen`); return; }
      setPinError(''); setScreen('pin_confirm');
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

  return (
    <Modal
      visible={visible}
      animationType="slide"
      presentationStyle="fullScreen"
      onRequestClose={() => screen === 'main' ? onClose() : setScreen('main')}
    >
      <View style={s.root}>
        <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

        {/* ── Header ── */}
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
          <TouchableOpacity style={s.headerSide} onPress={onClose} activeOpacity={0.7}>
            <Text style={s.headerDone}>Fertig</Text>
          </TouchableOpacity>
        </View>

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

            <TextInput
              style={s.pinInput}
              value={pinValue}
              onChangeText={v => { setPinValue(v.slice(0, 128)); setPinError(''); }}
              keyboardType="default"
              secureTextEntry
              placeholder="Passwort eingeben"
              placeholderTextColor={c.textTer}
              autoFocus
              autoCapitalize="none"
              autoCorrect={false}
              maxLength={128}
            />

            {!!pinError && <Text style={s.pinError}>{pinError}</Text>}

            <View style={s.pinBtns}>
              <TouchableOpacity style={s.pinCancelBtn} onPress={() => setScreen('main')} activeOpacity={0.7}>
                <Text style={s.pinCancelTxt}>Abbrechen</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[s.pinNextBtn, (pinValue.length < settings.minPinLength || pinSaving) && s.pinNextDisabled]}
                onPress={handlePinNext}
                disabled={pinValue.length < settings.minPinLength || pinSaving}
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
            contentContainerStyle={[s.content, { paddingBottom: SAFE_BOTTOM + rs(24) }]}
            showsVerticalScrollIndicator={false}
            keyboardShouldPersistTaps="handled"
          >

            {/* ─── SICHERHEIT ─── */}
            <Text style={s.sectionLabel}>SICHERHEIT</Text>
            <View style={s.card}>

              {/* Biometrie */}
              <View style={s.row}>
                <Text style={s.rowIcon}>🔬</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Biometrie</Text>
                  <Text style={s.rowSub}>
                    {biometricsAvailable ? 'Face ID / Touch ID' : 'Kein biometrischer Sensor'}
                  </Text>
                </View>
                <Switch
                  value={settings.biometricsEnabled && biometricsAvailable}
                  onValueChange={v => updateSetting('biometricsEnabled', v)}
                  disabled={!biometricsAvailable}
                  trackColor={{ false: c.border, true: c.accent }}
                  thumbColor="#fff"
                />
              </View>

              <View style={s.sep} />

              {/* 2FA */}
              <View style={s.row}>
                <Text style={s.rowIcon}>🔐</Text>
                <View style={s.rowInfo}>
                  <Text style={[s.rowTitle, (!biometricsAvailable || !settings.biometricsEnabled) && s.dimmed]}>
                    2FA-Modus
                  </Text>
                  <Text style={[s.rowSub, (!biometricsAvailable || !settings.biometricsEnabled) && s.dimmed]}>
                    Biometrie UND PIN erforderlich
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
                  <Text style={s.rowIcon}>⏱</Text>
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
                  <Text style={s.rowIcon}>🚫</Text>
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

              {/* Min. PIN-Länge */}
              <View style={s.block}>
                <View style={s.blockHeader}>
                  <Text style={s.rowIcon}>🔢</Text>
                  <View style={s.rowInfo}>
                    <Text style={s.rowTitle}>Min. PIN-Länge</Text>
                    <Text style={s.rowSub}>{settings.minPinLength} Zeichen (4-16)</Text>
                  </View>
                </View>
                <View style={s.sliderContainer}>
                  <Text style={s.sliderValue}>{settings.minPinLength}</Text>
                  <View style={s.sliderTrack}>
                    {Array.from({ length: 13 }, (_, i) => {
                      const val = i + 4;
                      const active = settings.minPinLength === val;
                      return (
                        <TouchableOpacity
                          key={val}
                          style={[s.sliderDot, active && s.sliderDotActive]}
                          onPress={() => updateSetting('minPinLength', val)}
                          activeOpacity={0.7}
                        />
                      );
                    })}
                  </View>
                </View>
              </View>
            </View>

            {/* ─── KONTO ─── */}
            <Text style={s.sectionLabel}>KONTO</Text>
            <View style={s.card}>

              <TouchableOpacity style={s.row} onPress={startPinChange} activeOpacity={0.7}>
                <Text style={s.rowIcon}>🔑</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Passwort ändern</Text>
                </View>
                <Text style={s.chevron}>›</Text>
              </TouchableOpacity>

              <View style={s.sep} />

              <TouchableOpacity
                style={s.row}
                onPress={() => { onClose(); setTimeout(onLogout, 300); }}
                activeOpacity={0.7}
              >
                <Text style={s.rowIcon}>🔒</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Tresor sperren</Text>
                </View>
                <Text style={s.chevron}>›</Text>
              </TouchableOpacity>
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
                <Text style={s.rowIcon}>🗑️</Text>
                <View style={s.rowInfo}>
                  <Text style={[s.rowTitle, { color: c.danger }]}>Tresor leeren</Text>
                  <Text style={s.rowSub}>Alle Daten endgültig löschen</Text>
                </View>
                {loading
                  ? <ActivityIndicator size="small" color={c.danger} />
                  : <Text style={[s.chevron, { color: c.danger }]}>›</Text>
                }
              </TouchableOpacity>
            </View>

            {/* ─── APP ─── */}
            <Text style={s.sectionLabel}>APP</Text>
            <View style={s.card}>

              <View style={s.row}>
                <Text style={s.rowIcon}>🛡️</Text>
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
                <Text style={s.rowIcon}>ℹ️</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Version</Text>
                </View>
                <Text style={s.rowVal}>Obscura {appVersion}</Text>
              </View>

              <View style={s.sep} />

              <View style={s.row}>
                <Text style={s.rowIcon}>🔒</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Verschlüsselung</Text>
                </View>
                <Text style={s.rowVal}>AES-256-CBC</Text>
              </View>

              <View style={s.sep} />

              <View style={s.row}>
                <Text style={s.rowIcon}>🔑</Text>
                <View style={s.rowInfo}>
                  <Text style={s.rowTitle}>Key Derivation</Text>
                </View>
                <Text style={s.rowVal}>Argon2id / PBKDF2</Text>
              </View>

            </View>

          </ScrollView>
        )}
      </View>
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

  // Header
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: rs(16),
    paddingVertical: rs(14),
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: c.sep,
  },
  headerSide: { minWidth: rs(70) },
  headerTitle: { fontSize: rs(17), fontWeight: '600', color: c.text, textAlign: 'center' },
  headerDone: { fontSize: rs(16), fontWeight: '600', color: c.accent, textAlign: 'right' },
  headerBack: { fontSize: rs(16), color: c.accent },

  // Main scroll
  scroll: { flex: 1 },
  content: { padding: rs(16) },

  // Section label
  sectionLabel: {
    fontSize: rs(11),
    fontWeight: '600',
    color: c.textSec,
    letterSpacing: 0.8,
    marginTop: rs(22),
    marginBottom: rs(8),
    marginLeft: rs(6),
  },

  // Card
  card: {
    backgroundColor: c.card,
    borderRadius: rs(14),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
  },

  // Row
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: rs(13),
    paddingHorizontal: rs(14),
    gap: rs(12),
    minHeight: rs(52),
  },
  rowIcon: { fontSize: rs(20), width: rs(28), textAlign: 'center' },
  rowInfo: { flex: 1 },
  rowTitle: { fontSize: rs(15), fontWeight: '500', color: c.text },
  rowSub: { fontSize: rs(12), color: c.textSec, marginTop: rs(2) },
  rowVal: { fontSize: rs(13), color: c.textSec },
  chevron: { fontSize: rs(22), color: c.textSec, fontWeight: '300' },
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
  chips: { flexDirection: 'row', flexWrap: 'wrap', gap: rs(8), paddingLeft: rs(40) },
  chip: {
    paddingHorizontal: rs(12),
    paddingVertical: rs(6),
    borderRadius: rs(8),
    backgroundColor: c.bg,
    borderWidth: 1,
    borderColor: c.border,
  },
  chipOn: { backgroundColor: c.accentDim, borderColor: c.accentBorder },
  chipTxt: { fontSize: rs(13), fontWeight: '500', color: c.textSec },
  chipTxtOn: { color: c.accent, fontWeight: '600' },

  // Storage bar
  storageRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: rs(8) },
  storageLabel: { fontSize: rs(13), color: c.textSec },
  storageValue: { fontSize: rs(13), color: c.textSec },
  storageBar: {
    height: rs(4),
    backgroundColor: c.bg,
    borderRadius: rs(2),
    overflow: 'hidden',
  },
  storageBarFill: {
    height: '100%',
    backgroundColor: c.accent,
    borderRadius: rs(2),
  },

  // Status badge
  badge: { flexDirection: 'row', alignItems: 'center', gap: rs(5), paddingHorizontal: rs(8), paddingVertical: rs(4), borderRadius: rs(6) },
  badgeDot: { width: rs(6), height: rs(6), borderRadius: rs(3) },
  badgeTxt: { fontSize: rs(12), fontWeight: '600' },

  // Min PIN length stepper
  sliderContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(12),
    paddingLeft: rs(40),
    paddingTop: rs(4),
  },
  sliderValue: {
    fontSize: rs(20),
    fontWeight: '700',
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
    borderRadius: rs(4),
    backgroundColor: c.border,
  },
  sliderDotActive: {
    backgroundColor: c.accent,
    height: rs(10),
  },

  // PIN change page
  pinPage: {
    flex: 1,
    padding: rs(24),
  },
  pinPageTitle: {
    fontSize: rs(22),
    fontWeight: '700',
    color: c.text,
    marginBottom: rs(20),
  },
  pinSteps: {
    flexDirection: 'row',
    gap: rs(8),
    marginBottom: rs(24),
  },
  pinStep: {
    flex: 1,
    height: rs(4),
    borderRadius: rs(2),
    backgroundColor: c.border,
  },
  pinStepActive: {
    backgroundColor: c.accent,
  },
  pinInput: {
    backgroundColor: c.card,
    borderRadius: rs(12),
    borderWidth: 1,
    borderColor: c.border,
    paddingHorizontal: rs(16),
    paddingVertical: rs(16),
    fontSize: rs(20),
    color: c.text,
    letterSpacing: rs(6),
    marginBottom: rs(12),
  },
  pinError: {
    fontSize: rs(13),
    color: c.danger,
    marginBottom: rs(12),
  },
  pinBtns: { flexDirection: 'row', gap: rs(12), marginTop: rs(8) },
  pinCancelBtn: {
    flex: 1,
    paddingVertical: rs(14),
    borderRadius: rs(12),
    backgroundColor: c.card,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: c.border,
  },
  pinCancelTxt: { fontSize: rs(15), color: c.textSec },
  pinNextBtn: {
    flex: 1,
    paddingVertical: rs(14),
    borderRadius: rs(12),
    backgroundColor: c.accent,
    alignItems: 'center',
  },
  pinNextDisabled: { opacity: 0.4 },
  pinNextTxt: { fontSize: rs(15), fontWeight: '600', color: '#fff' },
});
