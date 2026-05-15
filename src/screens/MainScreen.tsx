import React, { useState, useRef, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  Alert, StatusBar, Animated, Image,
} from 'react-native';
import FilesView from './FilesView';
import NotesScreen from './NotesScreen';
import { c, rs, SAFE_TOP, SAFE_BOTTOM, TAB_BAR_HEIGHT } from '../theme';

type Tab = 'files' | 'notes';

interface Props {
  onLogout: () => void;
  onChangePin?: (oldPin: string, newPin: string) => Promise<boolean>;
  onWipeVault?: () => Promise<void>;
  securityStatus?: 'secure' | 'warning' | 'critical';
}

export default function MainScreen({ onLogout, onChangePin, onWipeVault, securityStatus = 'secure' }: Props) {
  const [tab, setTab] = useState<Tab>('files');
  const [showSettings, setShowSettings] = useState(false);

  const filesOpacity = useRef(new Animated.Value(1)).current;
  const notesOpacity = useRef(new Animated.Value(0)).current;

  // Fade in animation on mount
  useEffect(() => {
    Animated.timing(filesOpacity, {
      toValue: 1,
      duration: 300,
      useNativeDriver: true,
    }).start();
  }, []);

  const switchTab = (next: Tab) => {
    if (next === tab) return;
    const fadeIn  = next === 'files' ? filesOpacity : notesOpacity;
    const fadeOut = next === 'files' ? notesOpacity : filesOpacity;

    Animated.parallel([
      Animated.timing(fadeOut, { toValue: 0, duration: 120, useNativeDriver: true }),
      Animated.timing(fadeIn,  { toValue: 1, duration: 160, useNativeDriver: true }),
    ]).start();

    setTab(next);
  };

  const handleLogout = () => {
    Alert.alert(
      'Tresor sperren',
      'Möchten Sie den Tresor wirklich sperren? Die Daten sind weiterhin verschlüsselt gespeichert.',
      [
        { text: 'Abbrechen', style: 'cancel' },
        { text: 'Sperren', style: 'destructive', onPress: onLogout },
      ],
    );
  };

  const handleOpenSettings = () => {
    setShowSettings(true);
  };

  const handleCloseSettings = () => {
    setShowSettings(false);
  };

  const handlePinChange = async () => {
    setShowSettings(false);
    Alert.prompt(
      'PIN ändern',
      'Bitte geben Sie Ihre aktuelle und neue PIN ein.',
      [
        {
          text: 'Abbrechen',
          style: 'cancel',
        },
        {
          text: 'Übernehmen',
          style: 'default',
          onPress: async (data: string | undefined) => {
            if (data) {
              // this would require a PIN change screen
              Alert.alert('Hinweis', 'PIN-Änderung erfordert Eingabe aller PINs.');
            }
          },
        },
      ],
      undefined
    );
  };

  const handleWipeVault = async () => {
    setShowSettings(false);

    Alert.alert(
      'Tresor leeren',
      'Dies löscht ALLE Dateien und Notizen ENDGÜLTIG. Diese Aktion kann nicht rückgängig gemacht werden. Verschlüsselungsschlüssel werden gelöscht.',
      [
        { text: 'Abbrechen', style: 'cancel' },
        {
          text: 'ALLES LÖSCHEN',
          style: 'destructive',
          onPress: async () => {
            try {
              if (onWipeVault) {
                await onWipeVault();
                onLogout();
                Alert.alert('Erfolg', 'Tresor wurde geleert.');
              }
            } catch (error) {
              Alert.alert('Fehler', 'Tresor konnte nicht geleert werden.');
            }
          },
        },
      ]
    );
  };

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

      {/* ── App header ── */}
      <View style={s.header}>
        {/* Security status indicator */}
        {securityStatus !== 'secure' && (
          <View style={s.securityStatus}>
            <Text style={
              securityStatus === 'critical' ? ss.securityCritical : ss.securityWarning
            }>
              {securityStatus === 'critical' ? '⚠️' : 'ℹ️'}
            </Text>
            <Text style={ss.securityText}>
              {securityStatus === 'critical' ? 'Sicherheitsalert!' : 'Sicherheitshinweis'}
            </Text>
          </View>
        )}
        <View style={s.headerLeft}>
          <Image
            source={require('../../assets/logo-mark.png')}
            style={s.headerLogoMark}
            resizeMode="contain"
          />
          <Text style={s.headerTitle}>Obscura</Text>
        </View>

        <View style={s.headerButtons}>
          <TouchableOpacity
            style={s.settingsBtn}
            onPress={handleOpenSettings}
            activeOpacity={0.7}
            accessibilityLabel="Einstellungen"
          >
            <Text style={s.settingsIcon}>⚙️</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={s.lockBtn}
            onPress={handleLogout}
            activeOpacity={0.7}
            accessibilityLabel="Sperren"
          >
            <Text style={s.lockIcon}>🔒</Text>
            <Text style={s.lockTxt}>Sperren</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* ── Tab content (layered, animated opacity) ── */}
      <View style={s.content}>
        <Animated.View
          style={[StyleSheet.absoluteFill, { opacity: filesOpacity }]}
          pointerEvents={tab === 'files' ? 'auto' : 'none'}
        >
          <FilesView />
        </Animated.View>

        <Animated.View
          style={[StyleSheet.absoluteFill, { opacity: notesOpacity }]}
          pointerEvents={tab === 'notes' ? 'auto' : 'none'}
        >
          <NotesScreen />
        </Animated.View>
      </View>

      {/* ── Bottom tab bar ── */}
      <View style={s.tabBar}>
        <TabItem
          icon="🗂️"
          label="Dateien"
          active={tab === 'files'}
          onPress={() => switchTab('files')}
        />
        <TabItem
          icon="📝"
          label="Notizen"
          active={tab === 'notes'}
          onPress={() => switchTab('notes')}
        />
      </View>

      {/* ── Settings overlay ── */}
      {showSettings && (
        <Animated.View style={s.settingsOverlay}>
          <TouchableOpacity
            style={s.settingsClose}
            onPress={handleCloseSettings}
            activeOpacity={0.7}
            accessibilityLabel="Schließen"
          >
            <Text style={s.settingsCloseIcon}>✕</Text>
          </TouchableOpacity>

          <View style={s.settingsMenu}>
            <Text style={s.settingsTitle}>Einstellungen</Text>

            <TouchableOpacity
              style={s.settingsItem}
              onPress={handlePinChange}
              activeOpacity={0.7}
            >
              <Text style={s.settingsItemIcon}>🔑</Text>
              <Text style={s.settingsItemText}>PIN ändern</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={s.settingsItemDanger}
              onPress={handleWipeVault}
              activeOpacity={0.7}
            >
              <Text style={s.settingsItemIcon}>🗑️</Text>
              <Text style={s.settingsItemTextDanger}>Tresor leeren</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={s.settingsItem}
              onPress={handleCloseSettings}
              activeOpacity={0.7}
            >
              <Text style={s.settingsItemIcon}>✕</Text>
              <Text style={s.settingsItemText}>Schließen</Text>
            </TouchableOpacity>
          </View>
        </Animated.View>
      )}
    </View>
  );
}

// ─────────────────────────────── Tab Item ───────────────────────────────

interface TabItemProps {
  icon: string;
  label: string;
  active: boolean;
  onPress: () => void;
}

function TabItem({ icon, label, active, onPress }: TabItemProps) {
  const sc = useRef(new Animated.Value(1)).current;

  const handlePress = () => {
    Animated.sequence([
      Animated.timing(sc, { toValue: 0.88, duration: 80,  useNativeDriver: true }),
      Animated.timing(sc, { toValue: 1,    duration: 130, useNativeDriver: true }),
    ]).start();
    onPress();
  };

  return (
    <TouchableOpacity
      style={ts.item}
      onPress={handlePress}
      activeOpacity={1}
      accessibilityRole="tab"
      accessibilityState={{ selected: active }}
    >
      <Animated.View style={[ts.inner, { transform: [{ scale: sc }] }]}>
        {active && <View style={ts.pill} />}
        <Text style={ts.icon}>{icon}</Text>
        <Text style={[ts.label, active && ts.labelActive]}>{label}</Text>
      </Animated.View>
    </TouchableOpacity>
  );
}

// ─────────────────────────────── Styles ───────────────────────────────

const s = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: c.bg,
  },

  // Header
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: SAFE_TOP,
    paddingBottom: rs(12),
    paddingHorizontal: rs(18),
    backgroundColor: c.bg,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: c.sep,
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(8),
  },
  headerLogoMark: {
    width: rs(34),
    height: rs(34),
  },
  headerTitle: {
    fontSize: rs(20),
    fontWeight: '700',
    color: c.text,
    letterSpacing: -0.4,
  },
  headerButtons: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(10),
  },
  lockBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(5),
    backgroundColor: c.card,
    paddingHorizontal: rs(12),
    paddingVertical: rs(7),
    borderRadius: rs(10),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
  },
  lockIcon: { fontSize: rs(13) },
  lockTxt: {
    fontSize: rs(13),
    fontWeight: '500',
    color: c.textSec,
  },
  settingsBtn: {
    width: rs(36),
    height: rs(36),
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: c.card,
    borderRadius: rs(10),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
  },
  settingsIcon: { fontSize: rs(18) },

  // Content area
  content: {
    flex: 1,
  },

  // Tab bar
  tabBar: {
    flexDirection: 'row',
    height: TAB_BAR_HEIGHT,
    backgroundColor: c.surface,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: c.sep,
    paddingBottom: SAFE_BOTTOM,
  },

  // Settings overlay
  settingsOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0,0,0,0.85)',
    alignItems: 'center',
    justifyContent: 'flex-end',
    zIndex: 100,
  },
  settingsClose: {
    position: 'absolute',
    top: SAFE_TOP + rs(20),
    right: rs(20),
    width: rs(40),
    height: rs(40),
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(255,255,255,0.1)',
    borderRadius: rs(20),
  },
  settingsCloseIcon: {
    fontSize: rs(24),
    color: c.text,
    fontWeight: '300',
  },
  settingsMenu: {
    backgroundColor: c.card,
    width: '100%',
    borderTopLeftRadius: rs(20),
    borderTopRightRadius: rs(20),
    paddingVertical: rs(20),
    paddingHorizontal: rs(24),
    gap: rs(4),
  },
  settingsTitle: {
    fontSize: rs(18),
    fontWeight: '700',
    color: c.text,
    textAlign: 'center',
    marginBottom: rs(16),
  },
  settingsItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: rs(16),
    paddingHorizontal: rs(12),
    backgroundColor: c.bg,
    borderRadius: rs(12),
    gap: rs(14),
  },
  settingsItemDanger: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: rs(16),
    paddingHorizontal: rs(12),
    backgroundColor: 'rgba(255,0,0,0.1)',
    borderRadius: rs(12),
    gap: rs(14),
  },
  settingsItemIcon: {
    fontSize: rs(20),
  },
  settingsItemText: {
    fontSize: rs(16),
    fontWeight: '500',
    color: c.text,
  },
  settingsItemTextDanger: {
    fontSize: rs(16),
    fontWeight: '600',
    color: '#ff4444',
  },
});

const ts = StyleSheet.create({
  item: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  inner: {
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
    paddingTop: rs(6),
    width: rs(80),
  },
  pill: {
    position: 'absolute',
    top: rs(0),
    width: rs(28),
    height: rs(3),
    borderRadius: rs(2),
    backgroundColor: c.accent,
  },
  icon: {
    fontSize: rs(22),
    marginBottom: rs(2),
  },
  label: {
    fontSize: rs(11),
    fontWeight: '500',
    color: c.textSec,
    letterSpacing: 0.2,
  },
  labelActive: {
    color: c.accent,
    fontWeight: '600',
  },
});

// ─────────────────────────────── Security Status Styles ───────────────────────────────

const ss = StyleSheet.create({
  securityStatus: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: 30,
    backgroundColor: securityStatus === 'critical' ? '#ff4444' : '#3366ff',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10,
  },
  securityCritical: {
    fontSize: rs(10),
    fontWeight: '600',
    color: '#fff',
    padding: rs(4),
  },
  securityWarning: {
    fontSize: rs(10),
    fontWeight: '500',
    color: '#fff',
    padding: rs(4),
  },
  securityText: {
    fontSize: rs(10),
    fontWeight: '500',
    color: '#fff',
    marginLeft: rs(4),
  },
});
