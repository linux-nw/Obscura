import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  Animated, Vibration, Platform, StatusBar,
  Alert, ActivityIndicator,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import { SecureCryptoService } from '../services/CryptoService';
import { DeviceSecurityService } from '../services/DeviceSecurityService';
import { SettingsService, AppSettings } from '../services/SettingsService';
import LockIcon from '../components/LockIcon';
import { c, rs, SAFE_TOP, SAFE_BOTTOM } from '../theme';

const ATTEMPTS_KEY = 'filevault_auth_attempts';

interface Props {
  onAuthenticate: () => void;
  isFirstLaunch: boolean;
  onWipeVault?: () => Promise<void>;
}

export default function AuthScreen({ onAuthenticate, isFirstLaunch, onWipeVault }: Props) {
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

        if (!isFirstLaunch && bioEnabled) {
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
        const secsLeft = Math.ceil((lockStatus.unlockAt - Date.now()) / 1000);
        showError(`Zu viele Versuche — noch ${secsLeft}s warten`);
        setPass('');
        return;
      }

      const isValid = await SecureCryptoService.unlock(entered);

      if (isValid) {
        setFailedAttempts(0);
        await SecureStore.deleteItemAsync(ATTEMPTS_KEY);
        setUnlocking(true);
        setTimeout(doAuth, 300);
      } else {
        const maxAttempts = appSettings?.maxFailedAttempts ?? 5;
        const newCount = failedAttempts + 1;
        setFailedAttempts(newCount);
        await SecureStore.setItemAsync(ATTEMPTS_KEY, String(newCount));

        if (newCount >= maxAttempts) {
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

    const minLen = appSettings?.minPinLength ?? 6;
    if (entered.length < minLen) {
      showError(`Mindestens ${minLen} Zeichen erforderlich`);
      setConfirm('');
      return;
    }

    setIsHashing(true);
    try {
      await Promise.all([
        SecureCryptoService.setupMasterKey(entered),
        SecureCryptoService.setAppInitialized(true),
      ]);
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
    const minLen = appSettings?.minPinLength ?? 6;
    if (current.length < minLen || unlocking || isHashing) return;

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
  const minLen = appSettings?.minPinLength ?? 6;
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
    ? (() => {
        const minLen = appSettings?.minPinLength ?? 6;
        return (phase === 'enter' ? `Mindestens ${minLen} Zeichen` : 'Passwort erneut eingeben');
      })()
    : 'Geben Sie Ihr Passwort ein';

  const submitLabel = isFirstLaunch
    ? (phase === 'enter' ? 'Weiter' : 'Speichern')
    : 'Entsperren';

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

      {/* ── Lock icon + branding ── */}
      <View style={s.brand}>
        <LockIcon
          locked
          size={rs(90)}
          animating={unlocking}
          onAnimationComplete={doAuth}
        />
        <Text style={s.appName}>Obscura</Text>
        <Text style={s.phase}>{phaseLabel}</Text>
        <Text style={s.sub}>{subtitle}</Text>
      </View>

      {/* ── Input + error ── */}
      <Animated.View style={[s.inputSection, { transform: [{ translateX: shakeX }] }]}>
        <View style={s.inputRow}>
          <TextInput
            ref={inputRef}
            style={s.input}
            value={currentVal}
            onChangeText={v => { setCurrentVal(v); }}
            secureTextEntry={!showPass}
            placeholder="Passwort eingeben"
            placeholderTextColor={c.textTer}
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
          >
            <Text style={s.eyeIcon}>{showPass ? '🙈' : '👁'}</Text>
          </TouchableOpacity>
        </View>
        <Animated.Text style={[s.errText, { opacity: errOpacity }]}>
          {errMsg}
        </Animated.Text>
      </Animated.View>

      {/* ── Action buttons ── */}
      <View style={s.actions}>
        {isFirstLaunch && phase === 'confirm' && (
          <TouchableOpacity style={s.backBtn} onPress={handleBack} activeOpacity={0.7}>
            <Text style={s.backTxt}>‹ Zurück</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity
          style={[s.submitBtn, !canAdvance && s.submitDisabled]}
          onPress={handleAdvance}
          disabled={!canAdvance}
          activeOpacity={0.8}
        >
          {isHashing
            ? <ActivityIndicator color="#fff" size="small" />
            : <Text style={s.submitTxt}>{submitLabel}</Text>
          }
        </TouchableOpacity>

        {!isFirstLaunch && hasBio && !bioPassedFor2FA && (
          <TouchableOpacity
            style={s.bioBtn}
            onPress={() => triggerBio()}
            activeOpacity={0.7}
          >
            <Text style={s.bioTxt}>Biometrie verwenden</Text>
          </TouchableOpacity>
        )}
      </View>

      <View style={{ height: SAFE_BOTTOM + rs(8) }} />
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
    paddingTop: rs(12),
  },
  appName: {
    fontSize: rs(36),
    fontWeight: '700',
    color: c.text,
    letterSpacing: -1,
    marginTop: rs(20),
    marginBottom: rs(6),
  },
  phase: {
    fontSize: rs(18),
    fontWeight: '600',
    color: c.text,
    marginBottom: rs(4),
  },
  sub: {
    fontSize: rs(14),
    color: c.textSec,
    letterSpacing: 0.1,
  },

  inputSection: {
    width: '88%',
    alignSelf: 'center',
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: c.card,
    borderRadius: rs(14),
    borderWidth: 1,
    borderColor: c.border,
    paddingHorizontal: rs(16),
    marginBottom: rs(10),
  },
  input: {
    flex: 1,
    paddingVertical: rs(16),
    fontSize: rs(18),
    color: c.text,
    letterSpacing: 0.5,
  },
  eyeBtn: {
    padding: rs(8),
    marginLeft: rs(4),
  },
  eyeIcon: {
    fontSize: rs(18),
  },
  errText: {
    fontSize: rs(13),
    fontWeight: '500',
    color: c.danger,
    minHeight: rs(18),
    textAlign: 'center',
  },

  actions: {
    width: '88%',
    alignSelf: 'center',
    gap: rs(12),
  },
  backBtn: {
    alignSelf: 'flex-start',
    paddingVertical: rs(4),
  },
  backTxt: {
    fontSize: rs(15),
    color: c.accent,
  },
  submitBtn: {
    backgroundColor: c.accent,
    borderRadius: rs(14),
    paddingVertical: rs(16),
    alignItems: 'center',
  },
  submitDisabled: {
    opacity: 0.35,
  },
  submitTxt: {
    fontSize: rs(16),
    fontWeight: '600',
    color: '#fff',
  },
  bioBtn: {
    paddingVertical: rs(12),
    alignItems: 'center',
  },
  bioTxt: {
    fontSize: rs(14),
    color: c.textSec,
  },
});
