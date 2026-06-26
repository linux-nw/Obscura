import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  Animated, Vibration, Platform, StatusBar,
  Alert, ActivityIndicator,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from '../services/CryptoService';
import { KeyRotationService } from '../services/KeyRotationService';
import { PanicService } from '../services/PanicService';
import { DecoyVaultService } from '../services/DecoyVaultService';
import { DeviceSecurityService } from '../services/DeviceSecurityService';
import { SettingsService, AppSettings } from '../services/SettingsService';
import VaultMark, { CornerFrame } from '../components/VaultMark';
import Icon from '../components/Icon';
import { c, rs, font, radius, SAFE_TOP, SAFE_BOTTOM, useBottomInset } from '../theme';

const ATTEMPTS_KEY = 'filevault_auth_attempts';

interface Props {
  onAuthenticate: () => void;
  isFirstLaunch: boolean;
  onWipeVault?: () => Promise<void>;
}

export default function AuthScreen({ onAuthenticate, isFirstLaunch, onWipeVault }: Props) {
  const safeBot = useBottomInset();
  const [pass, setPass]           = useState('');
  const [confirm, setConfirm]     = useState('');
  const [phase, setPhase]         = useState<'enter' | 'confirm'>('enter');
  const [showPass, setShowPass]   = useState(false);
  const [hasBio, setHasBio]       = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [errMsg, setErrMsg]       = useState('');
  const [isHashing, setIsHashing] = useState(false);
  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [bioPassedFor2FA, setBioPassedFor2FA] = useState(false);

  const shakeX      = useRef(new Animated.Value(0)).current;
  const errOpacity  = useRef(new Animated.Value(0)).current;
  const errTimer    = useRef<ReturnType<typeof setTimeout> | null>(null);
  const authFiredRef = useRef(false);
  const inputRef    = useRef<TextInput>(null);

  const doAuth = () => {
    if (authFiredRef.current) return;
    authFiredRef.current = true;
    onAuthenticate();
  };

  useEffect(() => {
    (async () => {
      try {
        const [settings, storedAttempts] = await Promise.all([
          SettingsService.get(),
          SecureStore.getItemAsync(ATTEMPTS_KEY),
        ]);
        setAppSettings(settings);
        if (storedAttempts) setFailedAttempts(parseInt(storedAttempts, 10));

        const hw  = await LocalAuthentication.hasHardwareAsync();
        const ok  = hw && await LocalAuthentication.isEnrolledAsync();
        const bioEnabled = settings.biometricsEnabled && ok;
        setHasBio(!!bioEnabled);

        if (!isFirstLaunch && bioEnabled && settings.bioAutoTrigger) {
          setTimeout(() => triggerBio(settings), 600);
        }
      } catch {}
    })();
    return () => { if (errTimer.current) clearTimeout(errTimer.current); };
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const security = await DeviceSecurityService.checkDeviceSecurity();
        if (security.detectedTampering) {
          console.warn('Security: Device tampering detected');
        }
      } catch {}
    })();
  }, []);

  const shake = () => {
    if (Platform.OS !== 'web') Vibration.vibrate(40);
    Animated.sequence([
      Animated.timing(shakeX, { toValue:  11, duration: 55, useNativeDriver: true }),
      Animated.timing(shakeX, { toValue: -11, duration: 55, useNativeDriver: true }),
      Animated.timing(shakeX, { toValue:   7, duration: 50, useNativeDriver: true }),
      Animated.timing(shakeX, { toValue:  -7, duration: 50, useNativeDriver: true }),
      Animated.timing(shakeX, { toValue:   0, duration: 50, useNativeDriver: true }),
    ]).start();
  };

  const showError = (msg: string) => {
    if (errTimer.current) clearTimeout(errTimer.current);
    setErrMsg(msg);
    errOpacity.setValue(1);
    shake();
    errTimer.current = setTimeout(() => {
      Animated.timing(errOpacity, { toValue: 0, duration: 400, useNativeDriver: true })
        .start(() => setErrMsg(''));
    }, 1800);
  };

  const triggerBio = async (settings?: AppSettings) => {
    const s = settings ?? appSettings;
    if (!s?.biometricsEnabled) return;
    if (s?.require2FA) {
      try {
        const res = await LocalAuthentication.authenticateAsync({
          promptMessage: 'Biometrie bestätigen',
          fallbackLabel: 'Passwort eingeben',
        });
        if (res.success) setBioPassedFor2FA(true);
      } catch {}
    } else {
      try {
        // If a key rotation was interrupted, it can only be finished after a
        // passphrase login (resume needs the passphrase to re-install the master
        // key). Skip biometric auto-unlock so the user enters the passphrase and
        // resumeRotationIfNeeded() runs — otherwise content stays half-migrated.
        if (await KeyRotationService.hasPendingRotation()) {
          showError('Bitte Passwort eingeben (Wartung läuft)');
          return;
        }
        const success = await SecureCryptoService.loadMasterKeyForBiometric();
        if (success) {
          setUnlocking(true);
          setTimeout(doAuth, 500);
        } else {
          showError('Biometrie fehlgeschlagen');
        }
      } catch {
        showError('Biometrie fehlgeschlagen');
      }
    }
  };

  const checkLoginPass = async (entered: string) => {
    if (isHashing) return;
    setIsHashing(true);
    try {
      const lockStatus = await SecureCryptoService.getLockStatus();
      if (lockStatus.locked) {
        const isPermanent = lockStatus.unlockAt >= Number.MAX_SAFE_INTEGER - 86400000;
        if (isPermanent) {
          showError('Tresor dauerhaft gesperrt.');
        } else {
          const secsLeft = Math.ceil((lockStatus.unlockAt - Date.now()) / 1000);
          showError(`Zu viele Versuche — noch ${secsLeft}s warten`);
        }
        setPass('');
        return;
      }

      // R-01: All three checks run in parallel — no timing leak between paths.
      // unlock() loads the real master key into cache if passphrase is correct.
      // verifyPanicPin() and verifyDecoyPin() are independent.
      const [panicMatch, realMatch, decoyMatch] = await Promise.all([
        PanicService.verifyPanicPin(entered),
        SecureCryptoService.unlock(entered),
        DecoyVaultService.verifyDecoyPin(entered),
      ]);

      if (panicMatch) {
        // Panic PIN: clear master key, then dispatch wipe or permanent lock.
        SecureCryptoService.clearAllCaches();
        const triggerAction = await PanicService.getTriggerAction();

        if (triggerAction === 'wipe') {
          try { await onWipeVault?.(); } catch {}
          return;
        }

        // 'lock' — permanent, no way back.
        try { await SecureStore.setItemAsync('filevault_lock_until', String(Number.MAX_SAFE_INTEGER)); } catch {}
        showError('Tresor dauerhaft gesperrt.');
        setPass('');
        return;
      }

      if (realMatch) {
        setFailedAttempts(0);
        await SecureStore.deleteItemAsync(ATTEMPTS_KEY);
        try {
          await KeyRotationService.resumeRotationIfNeeded(entered);
        } catch (e) {
          console.error('KeyRotation: resume after unlock failed:', e);
        }
        setUnlocking(true);
        setTimeout(doAuth, 300);
      } else if (decoyMatch) {
        // Decoy PIN: clear real master key (loaded by parallel unlock()), show empty vault.
        SecureCryptoService.clearAllCaches();
        setFailedAttempts(0);
        await SecureStore.deleteItemAsync(ATTEMPTS_KEY);
        try {
          await SecureStore.setItemAsync('filevault_decoy_activated', 'true');
        } catch {
          showError('Fehler beim Aktivieren des Täusch-Tresors');
          setPass('');
          return;
        }
        setUnlocking(true);
        setTimeout(doAuth, 300);
      } else {
        const maxAttempts = appSettings?.maxFailedAttempts ?? 5;
        const newCount = failedAttempts + 1;
        setFailedAttempts(newCount);
        await SecureStore.setItemAsync(ATTEMPTS_KEY, String(newCount));

        if (newCount >= maxAttempts) {
          const action = appSettings?.maxFailedAttemptsAction ?? 'wipe';
          if (action === 'lock') {
            await SecureStore.deleteItemAsync(ATTEMPTS_KEY);
            try { await SecureStore.setItemAsync('filevault_lock_until', String(Number.MAX_SAFE_INTEGER)); } catch {}
            showError('Tresor dauerhaft gesperrt.');
            setPass('');
          } else {
            Alert.alert(
              'Tresor gelöscht',
              `${maxAttempts} falsche Passwörter — alle Daten werden unwiderruflich gelöscht.`,
              [{
                text: 'Löschen',
                style: 'destructive',
                onPress: async () => {
                  await SecureStore.deleteItemAsync(ATTEMPTS_KEY);
                  await onWipeVault?.();
                },
              }],
              { cancelable: false },
            );
          }
        } else {
          const remaining = maxAttempts - newCount;
          showError(`Falsches Passwort — noch ${remaining} ${remaining === 1 ? 'Versuch' : 'Versuche'}`);
        }
        setPass('');
      }
    } catch {
      showError('Fehler beim Prüfen des Passworts');
      setPass('');
    } finally {
      setIsHashing(false);
    }
  };

  const checkConfirmPass = async (original: string, entered: string) => {
    if (isHashing) return;

    if (original !== entered) {
      showError('Passwörter stimmen nicht überein');
      setConfirm('');
      inputRef.current?.focus();
      return;
    }

    const minLen = 8;
    if (entered.length < minLen) {
      showError(`Mindestens ${minLen} Zeichen erforderlich`);
      setConfirm('');
      return;
    }

    setIsHashing(true);
    try {
      // Sequential: setAppInitialized only after setupMasterKey succeeds.
      // If setupMasterKey throws (e.g. crypto error), the app must NOT appear
      // initialized — otherwise the user gets stuck on "Entsperren" with no key.
      await SecureCryptoService.setupMasterKey(entered);
      await SecureCryptoService.setAppInitialized(true);
      setUnlocking(true);
      setTimeout(doAuth, 300);
    } catch (error) {
      console.error('Fehler beim Speichern des Passworts:', error);
      showError('Konnte Passwort nicht speichern');
      setConfirm('');
    } finally {
      setIsHashing(false);
    }
  };

  const handleAdvance = () => {
    const current = phase === 'confirm' ? confirm : pass;
    if (current.length < 8 || unlocking || isHashing) return;

    if (isFirstLaunch && phase === 'enter') {
      setPhase('confirm');
      setConfirm('');
      setTimeout(() => inputRef.current?.focus(), 80);
    } else if (isFirstLaunch && phase === 'confirm') {
      checkConfirmPass(pass, confirm);
    } else if (!isFirstLaunch) {
      checkLoginPass(pass);
    }
  };

  const handleBack = () => {
    setPhase('enter');
    setConfirm('');
    setTimeout(() => inputRef.current?.focus(), 80);
  };

  const currentVal  = phase === 'confirm' ? confirm : pass;
  const setCurrentVal = phase === 'confirm' ? setConfirm : setPass;
  const minLen = 8;
  const canAdvance  = currentVal.length >= minLen && !unlocking && !isHashing;

  const phaseLabel = isFirstLaunch
    ? (phase === 'enter' ? 'Passwort erstellen' : 'Passwort bestätigen')
    : bioPassedFor2FA ? '2FA – Passwort eingeben'
    : 'Entsperren';

  const subtitle = isHashing
    ? (phase === 'confirm' ? 'Passwort wird gespeichert...' : 'Passwort wird geprüft...')
    : bioPassedFor2FA
    ? 'Biometrie bestätigt — Passwort eingeben'
    : isFirstLaunch
    ? (phase === 'enter' ? 'Mindestens 8 Zeichen' : 'Passwort erneut eingeben')
    : 'Geben Sie Ihr Passwort ein';

  const submitLabel = isFirstLaunch
    ? (phase === 'enter' ? 'Weiter' : 'Speichern')
    : 'Entsperren';

  // H4: lightweight, no-dependency strength estimate (charset × length → bits).
  const strength = (() => {
    const pw = currentVal;
    if (!pw) return { label: '', frac: 0, color: c.border };
    let charset = 0;
    if (/[a-z]/.test(pw)) charset += 26;
    if (/[A-Z]/.test(pw)) charset += 26;
    if (/[0-9]/.test(pw)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) charset += 32;
    const bits = pw.length * Math.log2(charset || 1);
    const frac = Math.min(bits / 90, 1);
    if (bits >= 70) return { label: 'Stark', frac, color: c.success };
    if (bits >= 55) return { label: 'Gut', frac, color: c.warning };
    if (bits >= 40) return { label: 'Mittel', frac, color: c.warning };
    return { label: 'Schwach', frac, color: c.danger };
  })();
  const showStrength = isFirstLaunch && phase === 'enter' && currentVal.length > 0;

  const segActive = Math.round(strength.frac * 4);

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

      {/* ── Hero: aperture mark in registration frame + wordmark ── */}
      <View style={s.brand}>
        <View style={s.markWrap}>
          <CornerFrame size={rs(116)} />
          <VaultMark size={rs(66)} locked={!unlocking} spinning={unlocking} />
        </View>
        <Text style={s.appName}>Obscura</Text>
        <View style={s.overline}>
          <View style={s.overlineTick} />
          <Text style={s.overlineTxt}>{phaseLabel}</Text>
        </View>
        <Text style={s.sub}>{subtitle}</Text>
      </View>

      {/* ── Input + error ── */}
      <Animated.View style={[s.inputSection, { transform: [{ translateX: shakeX }] }]}>
        <View style={[s.field, errMsg ? s.fieldErr : null]}>
          <Icon name="key" size={rs(18)} color={c.textTer} />
          <TextInput
            ref={inputRef}
            style={s.input}
            value={currentVal}
            onChangeText={v => { setCurrentVal(v); }}
            secureTextEntry={!showPass}
            keyboardType={showPass ? 'visible-password' : 'default'}
            autoComplete="off"
            textContentType="none"
            importantForAutofill="no"
            spellCheck={false}
            placeholder="Passphrase eingeben"
            placeholderTextColor={c.textFaint}
            autoFocus
            autoCapitalize="none"
            autoCorrect={false}
            returnKeyType="done"
            onSubmitEditing={handleAdvance}
            editable={!unlocking && !isHashing}
            maxLength={256}
          />
          <TouchableOpacity
            style={s.eyeBtn}
            onPress={() => setShowPass(v => !v)}
            activeOpacity={0.7}
            hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
          >
            <Icon name={showPass ? 'eye-off' : 'eye'} size={rs(18)} color={c.textTer} />
          </TouchableOpacity>
        </View>

        {showStrength && (
          <View style={s.strengthWrap}>
            <View style={s.strength}>
              {[0, 1, 2, 3].map(i => (
                <View key={i} style={[s.strSeg, { backgroundColor: i < segActive ? strength.color : c.border2 }]} />
              ))}
            </View>
            <View style={s.strengthRow}>
              <Text style={s.strHint}>min. 8 Zeichen</Text>
              {!!strength.label && <Text style={[s.strLabel, { color: strength.color }]}>{strength.label}</Text>}
            </View>
          </View>
        )}
        <Animated.Text style={[s.errText, { opacity: errOpacity }]}>
          {errMsg}
        </Animated.Text>
      </Animated.View>

      {/* ── Action buttons ── */}
      <View style={s.actions}>
        {isFirstLaunch && phase === 'confirm' && (
          <TouchableOpacity style={s.backBtn} onPress={handleBack} activeOpacity={0.7}>
            <Icon name="chevron-left" size={rs(15)} color={c.accent} />
            <Text style={s.backTxt}>Zurück</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity
          style={[s.submitBtn, !canAdvance && s.submitDisabled]}
          onPress={handleAdvance}
          disabled={!canAdvance}
          activeOpacity={0.85}
        >
          {isHashing ? (
            <ActivityIndicator color={c.accentFg} size="small" />
          ) : (
            <>
              <Icon
                name={isFirstLaunch ? (phase === 'confirm' ? 'shield-check' : 'chevron-right') : 'unlock'}
                size={rs(18)}
                color={canAdvance ? c.accentFg : c.textFaint}
              />
              <Text style={[s.submitTxt, !canAdvance && s.submitTxtDisabled]}>{submitLabel}</Text>
            </>
          )}
        </TouchableOpacity>

        {!isFirstLaunch && hasBio && !bioPassedFor2FA && (
          <>
            <View style={s.divider}>
              <View style={s.divLine} />
              <Text style={s.divTxt}>oder</Text>
              <View style={s.divLine} />
            </View>
            <TouchableOpacity style={s.bioBtn} onPress={() => triggerBio()} activeOpacity={0.75}>
              <Icon name="fingerprint" size={rs(20)} color={c.text} />
              <Text style={s.bioTxt}>Mit Biometrie entsperren</Text>
            </TouchableOpacity>
          </>
        )}
      </View>

      <View style={{ height: safeBot + rs(8) }} />
    </View>
  );
}

// ─────────────────────────────── Styles ───────────────────────────────

const s = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: c.bg,
    paddingTop: SAFE_TOP,
    alignItems: 'center',
    justifyContent: 'space-between',
  },

  brand: {
    alignItems: 'center',
    paddingTop: rs(28),
  },
  markWrap: {
    width: rs(116),
    height: rs(116),
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: rs(24),
  },
  appName: {
    fontFamily: font.monoBold,
    fontSize: rs(22),
    color: c.text,
    letterSpacing: rs(4),
    textTransform: 'uppercase',
  },
  overline: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(8),
    marginTop: rs(12),
  },
  overlineTick: { width: rs(10), height: 2, backgroundColor: c.accent },
  overlineTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(10),
    letterSpacing: rs(2),
    textTransform: 'uppercase',
    color: c.accent,
  },
  sub: {
    fontFamily: font.sans,
    fontSize: rs(13.5),
    color: c.textSec,
    marginTop: rs(10),
  },

  inputSection: {
    width: '86%',
    alignSelf: 'center',
  },
  field: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(11),
    backgroundColor: c.inset,
    borderWidth: 1,
    borderColor: c.border2,
    borderRadius: radius.input,
    paddingHorizontal: rs(14),
    height: rs(58),
  },
  fieldErr: {
    borderColor: c.danger,
  },
  input: {
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
  errText: {
    fontFamily: font.mono,
    fontSize: rs(12),
    color: c.danger,
    minHeight: rs(18),
    textAlign: 'center',
    marginTop: rs(10),
  },
  strengthWrap: {
    marginTop: rs(12),
    gap: rs(8),
  },
  strength: {
    flexDirection: 'row',
    gap: rs(4),
  },
  strSeg: {
    flex: 1,
    height: rs(4),
  },
  strengthRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  strHint: {
    fontFamily: font.mono,
    fontSize: rs(11),
    color: c.textTer,
  },
  strLabel: {
    fontFamily: font.monoBold,
    fontSize: rs(11),
  },

  actions: {
    width: '86%',
    alignSelf: 'center',
    gap: rs(12),
  },
  backBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(2),
    alignSelf: 'flex-start',
    paddingVertical: rs(4),
  },
  backTxt: {
    fontFamily: font.mono,
    fontSize: rs(14),
    color: c.accent,
  },
  submitBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: rs(9),
    backgroundColor: c.accent,
    borderRadius: radius.btn,
    paddingVertical: rs(16),
  },
  submitDisabled: {
    backgroundColor: c.surface2,
  },
  submitTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(13),
    letterSpacing: rs(1),
    textTransform: 'uppercase',
    color: c.accentFg,
  },
  submitTxtDisabled: {
    color: c.textFaint,
  },
  divider: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(12),
    marginVertical: rs(2),
  },
  divLine: { flex: 1, height: 1, backgroundColor: c.border },
  divTxt: {
    fontFamily: font.mono,
    fontSize: rs(11),
    color: c.textFaint,
  },
  bioBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: rs(9),
    borderWidth: 1,
    borderColor: c.border2,
    borderRadius: radius.btn,
    paddingVertical: rs(15),
  },
  bioTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(13),
    letterSpacing: rs(1),
    textTransform: 'uppercase',
    color: c.text,
  },
});
