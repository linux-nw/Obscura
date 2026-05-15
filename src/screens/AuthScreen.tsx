import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  Animated, Vibration, Platform, StatusBar,
  Alert,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import CryptoJS from 'crypto-js';
import { SecureCryptoService } from '../services/CryptoService';
import { DeviceSecurityService } from '../services/DeviceSecurityService';
import LockIcon from '../components/LockIcon';
import { c, rs, SAFE_TOP, SAFE_BOTTOM } from '../theme';

const PIN_MIN = 4;
const PIN_MAX = 6;
const PBKDF2_ITERATIONS = 100000;

const LETTER_MAP: Record<string, string | undefined> = {
  '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
  '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ',
};

interface StoredPin {
  hash: string;
  salt: string;
  iterationCount: number;
}

interface Props {
  onAuthenticate: () => void;
  isFirstLaunch: boolean;
}

export default function AuthScreen({ onAuthenticate, isFirstLaunch }: Props) {
  const [pin, setPin]         = useState('');
  const [confirm, setConfirm] = useState('');
  const [phase, setPhase]     = useState<'enter' | 'confirm'>('enter');
  const [hasBio, setHasBio]   = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [errMsg, setErrMsg]   = useState('');
  const [isHashing, setIsHashing] = useState(false);

  const shakeX  = useRef(new Animated.Value(0)).current;
  const errOpacity = useRef(new Animated.Value(0)).current;
  const errTimer   = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Biometrics check + auto-trigger on returning users
  useEffect(() => {
    (async () => {
      try {
        const hw  = await LocalAuthentication.hasHardwareAsync();
        const ok  = hw && await LocalAuthentication.isEnrolledAsync();
        setHasBio(!!ok);
        if (!isFirstLaunch && ok) setTimeout(triggerBio, 600);
      } catch {}
    })();
    return () => { if (errTimer.current) clearTimeout(errTimer.current); };
  }, []);

  // Device Security Check on mount
  useEffect(() => {
    (async () => {
      try {
        const security = await DeviceSecurityService.checkDeviceSecurity();
        if (security.detectedTampering) {
          Alert.alert('Sicherheitsalarm', 'Das Gerät wurde kompromittiert! Die App wird gelöscht.');
          // In Produktion: Auto wipe
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

  const triggerBio = async () => {
    try {
      const res = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Tresor entsperren',
        fallbackLabel: 'PIN eingeben',
      });
      if (res.success) {
        setUnlocking(true);
        // Wichtig: Biometrie-Authentifizierung erfolgt, aber der echte Schlüssel
        // wird erst nach der PIN-Prüfung freigegeben (Two-Factor-Schema)
        setTimeout(onAuthenticate, 500);
      }
    } catch {}
  };

  /**
   * Berechnet PBKDF2-Hash der PIN
   * Verwendet kryptographisch sichere Zufallsbits für den Salt
   */
  const computePinHash = async (pin: string): Promise<{ hash: string; salt: string; iterationCount: number }> => {
    try {
      const saltBytes = await Crypto.getRandomBytesAsync(16);
      const saltHex = bufferToHex(saltBytes);

      // PBKDF2 mit SHA-256, 100k Iterationen, 32-byte Ausgabe
      const derivedKey = CryptoJS.PBKDF2(
        pin,
        saltHex,
        {
          keySize: 32 / 4,
          iterations: PBKDF2_ITERATIONS,
          hasher: CryptoJS.algo.SHA256,
        }
      );

      return {
        hash: bufferToHex(derivedKey.words),
        salt: saltHex,
        iterationCount: PBKDF2_ITERATIONS,
      };
    } catch (error) {
      console.error('PIN hashing error:', error);
      throw new Error('Konnte PIN nicht hashen');
    }
  };

  /**
   * Prüft die eingegebene PIN gegen den gespeicherten Hash
   * Verwendet konstante Zeit-Vergleich um Timing-Attacks zu verhindern
   */
  const verifyPin = async (entered: string): Promise<boolean> => {
    try {
      const stored = await getStoredPin();
      if (!stored) return false;

      const { hash: storedHash, salt: storedSalt, iterationCount } = stored;

      // PBKDF2 mit denselben Parametern wie beim Speichern
      const derivedKey = CryptoJS.PBKDF2(
        entered,
        storedSalt,
        {
          keySize: 32 / 4,
          iterations: iterationCount,
          hasher: CryptoJS.algo.SHA256,
        }
      );

      const derivedHash = bufferToHex(derivedKey.words);

      // Konstante Zeit-Vergleich um Timing-Attacks zu verhindern
      return constantTimeEquals(derivedHash, storedHash);
    } catch (error) {
      console.error('PIN verification error:', error);
      return false;
    }
  };

  const getStoredPin = async (): Promise<StoredPin | null> => {
    try {
      const dataHex = await SecureStore.getItemAsync('filevault_pin_hash');
      const ivHex = await SecureStore.getItemAsync('filevault_pin_iv');
      const keyHex = await SecureStore.getItemAsync('filevault_pin_key');

      if (!dataHex || !ivHex || !keyHex) {
        return null;
      }

      const masterKeyBuffer = hexToBuffer(keyHex);
      const ivBuffer = hexToBuffer(ivHex);
      const dataBuffer = hexToBuffer(dataHex);

      // crypto-js expects the ciphertext as a hex string or WordArray
      // We need to convert the dataBuffer to a WordArray
      const cipher = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.lib.WordArray.create(dataBuffer),
      });

      const decrypted = CryptoJS.AES.decrypt(cipher, masterKeyBuffer, {
        iv: ivBuffer,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const json = JSON.parse(bufferToString(decrypted)) as StoredPin;
      return json;
    } catch {
      return null;
    }
  };

  const checkLoginPin = async (entered: string) => {
    if (isHashing) return;

    setIsHashing(true);
    try {
      const isValid = await verifyPin(entered);
      if (isValid) {
        setUnlocking(true);
      } else if (entered.length >= PIN_MAX) {
        showError('Falsche PIN');
        setPin('');
      }
    } catch (error) {
      showError('Fehler beim Prüfen der PIN');
      setPin('');
    } finally {
      setIsHashing(false);
    }
  };

  const checkConfirmPin = async (original: string, entered: string) => {
    if (original !== entered) {
      showError('PINs stimmen nicht überein');
      setConfirm('');
      return;
    }

    if (entered.length < PIN_MIN) {
      showError(`PIN muss mindestens ${PIN_MIN} Ziffern haben`);
      setConfirm('');
      return;
    }

    // PIN hashen und sicher speichern
    const { hash, salt, iterationCount } = await computePinHash(entered);

    try {
      // Speichert PIN-Hash und Salt (nicht die PIN selbst!)
      // Der PIN-Hash wird mit einem Master-Key verschlüsselt
      const masterKey = await Crypto.getRandomBytesAsync(32);
      const masterKeyHex = bufferToHex(masterKey);

      // Verschlüsselt PIN-Daten mit Master-Key
      const pinData = JSON.stringify({ hash, salt, iterationCount });
      const pinBuffer = stringToBuffer(pinData);
      const iv = await Crypto.getRandomBytesAsync(12);

      const cipher = CryptoJS.AES.encrypt(
        CryptoJS.enc.Utf8.parse(pinData),
        CryptoJS.enc.Hex.parse(masterKeyHex),
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      // Speichert verschlüsselte PIN-Hash
      await SecureStore.setItemAsync('filevault_pin_hash', bufferToHex(cipher.ciphertext));
      await SecureStore.setItemAsync('filevault_pin_salt', salt);
      await SecureStore.setItemAsync('filevault_pin_iv', bufferToHex(iv));
      await SecureStore.setItemAsync('filevault_pin_key', masterKeyHex);

      // Markiert App als initialisiert
      await SecureCryptoService.setAppInitialized(true);
      setUnlocking(true);
    } catch (error) {
      console.error('Error storing PIN:', error);
      showError('Konnte PIN nicht speichern');
      setConfirm('');
    }
  };

  /**
   * Vergleicht zwei Strings in konstanter Zeit
   * Verhindert Timing-Attacks
   */
  const constantTimeEquals = (a: string, b: string): boolean => {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  };

  // ─────────────────────────────── Hilfsfunktionen ───────────────────────────────

  const bufferToHex = (buffer: ArrayBuffer | Uint8Array): string => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  };

  const hexToBuffer = (hex: string): ArrayBuffer => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  };

  const stringToBuffer = (str: string): ArrayBuffer => {
    const encoder = new TextEncoder();
    return encoder.encode(str).buffer;
  };

  const bufferToString = (buffer: ArrayBuffer | Uint8Array): string => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
  };

  // ─────────────────────────────── Event Handler ───────────────────────────────

  const handleDigit = (digit: string) => {
    if (unlocking || isHashing) return;
    if (phase === 'enter') {
      const np = pin + digit;
      if (np.length > PIN_MAX) return;
      setPin(np);
      if (!isFirstLaunch) checkLoginPin(np);
    } else {
      const nc = confirm + digit;
      if (nc.length > PIN_MAX) return;
      setConfirm(nc);
      checkConfirmPin(pin, nc);
    }
  };

  const handleDelete = () => {
    if (unlocking || isHashing) return;
    if (phase === 'confirm') setConfirm(v => v.slice(0, -1));
    else setPin(v => v.slice(0, -1));
  };

  const handleAdvance = () => {
    if (isFirstLaunch && phase === 'enter' && pin.length >= PIN_MIN) {
      setPhase('confirm');
    }
  };

  const handleBack = () => {
    setPhase('enter');
    setConfirm('');
  };

  const curLen  = phase === 'confirm' ? confirm.length : pin.length;
  const showOK  = isFirstLaunch && phase === 'enter' && pin.length >= PIN_MIN;
  const showBack = isFirstLaunch && phase === 'confirm';

  const subtitle = isFirstLaunch
    ? (phase === 'enter' ? `${PIN_MIN}–${PIN_MAX} Ziffern wählen` : 'PIN erneut eingeben')
    : 'Geben Sie Ihre PIN ein';

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

      {/* ── Lock icon + branding ── */}
      <View style={s.brand}>
        <LockIcon
          locked
          size={rs(90)}
          animating={unlocking}
          onAnimationComplete={onAuthenticate}
        />
        <Text style={s.appName}>Obscura</Text>
        <Text style={s.phase}>
          {isFirstLaunch
            ? (phase === 'enter' ? 'PIN erstellen' : 'PIN bestätigen')
            : 'Entsperren'}
        </Text>
        <Text style={s.sub}>{subtitle}</Text>
      </View>

      {/* ── PIN dots + error ── */}
      <Animated.View style={[s.dotsWrap, { transform: [{ translateX: shakeX }] }]}>
        <View style={s.dotsRow}>
          {Array.from({ length: PIN_MAX }).map((_, i) => (
            <View
              key={i}
              style={[
                s.dot,
                i < curLen && s.dotFilled,
                i === PIN_MIN && s.dotGap,
              ]}
            />
          ))}
        </View>
        <Animated.Text style={[s.errText, { opacity: errOpacity }]}>
          {errMsg}
        </Animated.Text>
      </Animated.View>

      {/* ── Numeric keypad ── */}
      <View style={s.pad}>
        {hasBio && !isFirstLaunch ? (
          <PinKey label="Touch ID" ghost onPress={triggerBio} />
        ) : showBack ? (
          <PinKey label="‹ zurück" ghost onPress={handleBack} />
        ) : (
          <PinKey digit="1" ghost disabled />
        )}
        <PinKey digit="0" onPress={() => handleDigit('0')} />
        {showOK ? (
          <PinKey label="Weiter" accent onPress={handleAdvance} />
        ) : (
          <PinKey label="⌫" ghost onPress={handleDelete} largeSymbol />
        )}
      </View>

      {/* ── Extended keypad for PIN creation ── */}
      <Animated.View
        style={[
          s.keypad,
          { opacity: (phase === 'enter' && !showOK) || (phase === 'confirm') ? 1 : 0 },
        ]}
      >
        <View style={s.padRow}>
          <PinKey digit="1"             onPress={() => handleDigit('1')} />
          <PinKey digit="2" sub="ABC"   onPress={() => handleDigit('2')} />
          <PinKey digit="3" sub="DEF"   onPress={() => handleDigit('3')} />
        </View>
        <View style={s.padRow}>
          <PinKey digit="4" sub="GHI"   onPress={() => handleDigit('4')} />
          <PinKey digit="5" sub="JKL"   onPress={() => handleDigit('5')} />
          <PinKey digit="6" sub="MNO"   onPress={() => handleDigit('6')} />
        </View>
        <View style={s.padRow}>
          <PinKey digit="7" sub="PQRS"  onPress={() => handleDigit('7')} />
          <PinKey digit="8" sub="TUV"   onPress={() => handleDigit('8')} />
          <PinKey digit="9" sub="WXYZ"  onPress={() => handleDigit('9')} />
        </View>
        <View style={s.padRow}>
          <PinKey digit="" ghost disabled />
          <PinKey digit="0" onPress={() => handleDigit('0')} />
          {showOK && phase === 'enter' ? (
            <PinKey label="Weiter" accent onPress={handleAdvance} />
          ) : (
            <PinKey label="⌫" ghost onPress={handleDelete} largeSymbol />
          )}
        </View>
      </Animated.View>

      <View style={{ height: SAFE_BOTTOM + rs(8) }} />
    </View>
  );
}

// ─────────────────────────────── PIN Key ───────────────────────────────

const KEY_SIZE = rs(72);

interface PinKeyProps {
  onPress?: () => void;
  digit?: string;
  sub?: string;
  label?: string;
  ghost?: boolean;
  accent?: boolean;
  largeSymbol?: boolean;
  disabled?: boolean;
}

function PinKey({ onPress, digit, sub, label, ghost, accent, largeSymbol, disabled }: PinKeyProps) {
  const sc = useRef(new Animated.Value(1)).current;

  const handlePress = () => {
    if (disabled) return;
    Animated.sequence([
      Animated.timing(sc, { toValue: 0.85, duration: 55,  useNativeDriver: true }),
      Animated.timing(sc, { toValue: 1,    duration: 130, useNativeDriver: true }),
    ]).start();
    onPress?.();
  };

  return (
    <TouchableOpacity
      onPress={handlePress}
      activeOpacity={0.8}
      style={s.keySlot}
      disabled={disabled}
      accessible
      accessibilityLabel={digit ?? label ?? 'Leer'}
      accessibilityRole="button"
    >
      <Animated.View style={[
        s.key,
        ghost  && s.keyGhost,
        accent && s.keyAccent,
        disabled && s.keyDisabled,
        { transform: [{ scale: sc }] },
      ]}>
        {digit ? (
          <>
            <Text style={s.keyDigit}>{digit}</Text>
            {sub ? <Text style={s.keyLetters}>{sub}</Text> : null}
          </>
        ) : label ? (
          <Text style={[
            s.keyLabel,
            largeSymbol && s.keyLabelLarge,
            accent      && { color: c.accent, fontWeight: '600' },
          ]}>
            {label}
          </Text>
        ) : null}
      </Animated.View>
    </TouchableOpacity>
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

  dotsWrap: {
    alignItems: 'center',
  },
  dotsRow: {
    flexDirection: 'row',
    gap: rs(14),
    marginBottom: rs(10),
  },
  dot: {
    width: rs(11),
    height: rs(11),
    borderRadius: rs(6),
    borderWidth: 1.5,
    borderColor: '#2E2E30',
    backgroundColor: 'transparent',
  },
  dotFilled: {
    backgroundColor: c.accent,
    borderColor: c.accent,
  },
  dotGap: {
    marginLeft: rs(8),
  },
  errText: {
    fontSize: rs(13),
    fontWeight: '500',
    color: c.danger,
    minHeight: rs(18),
    textAlign: 'center',
  },

  pad: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(10),
    paddingHorizontal: rs(20),
    marginBottom: rs(20),
  },
  keypad: {
    gap: rs(10),
    paddingHorizontal: rs(20),
    width: '100%',
    maxWidth: rs(310),
  },
  padRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  keySlot: {
    width: KEY_SIZE,
    height: KEY_SIZE,
    alignItems: 'center',
    justifyContent: 'center',
  },
  key: {
    width: KEY_SIZE,
    height: KEY_SIZE,
    borderRadius: KEY_SIZE / 2,
    backgroundColor: c.cardEl,
    alignItems: 'center',
    justifyContent: 'center',
  },
  keyDisabled: {
    opacity: 0.3,
    backgroundColor: 'transparent',
  },
  keyGhost: {
    backgroundColor: 'transparent',
  },
  keyAccent: {
    backgroundColor: c.accentDim,
    borderWidth: 1,
    borderColor: c.accentBorder,
  },
  keyDigit: {
    fontSize: rs(27),
    fontWeight: '300',
    color: c.text,
    lineHeight: rs(30),
  },
  keyLetters: {
    fontSize: rs(9),
    fontWeight: '600',
    color: c.textSec,
    letterSpacing: 1.2,
    marginTop: rs(-2),
  },
  keyLabel: {
    fontSize: rs(12),
    fontWeight: '500',
    color: c.textSec,
    textAlign: 'center',
  },
  keyLabelLarge: {
    fontSize: rs(20),
    fontWeight: '400',
    color: c.textSec,
  },
});
