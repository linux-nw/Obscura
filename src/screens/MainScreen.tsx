import React, { useState, useRef, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  Alert, StatusBar, Animated,
} from 'react-native';
import FilesView from './FilesView';
import NotesScreen from './NotesScreen';
import SettingsScreen from './SettingsScreen';
import VaultMark from '../components/VaultMark';
import Icon from '../components/Icon';
import { c, rs, font, SAFE_TOP, SAFE_BOTTOM, TAB_BAR_HEIGHT, useBottomInset } from '../theme';

type Tab = 'files' | 'notes' | 'settings';

interface Props {
  onLogout: () => void;
  onChangePin?: (oldPin: string, newPin: string) => Promise<boolean>;
  onWipeVault?: () => Promise<void>;
  securityStatus: 'secure' | 'warning' | 'critical';
  isDecoy?: boolean;
}

const TAB_META: Record<Tab, { title: string; sub: string; icon: string }> = {
  files:    { title: 'Dateien',       sub: 'Ende-zu-Ende verschlüsselt', icon: 'folder' },
  notes:    { title: 'Notizen',       sub: 'Vertraulich notiert',         icon: 'sticky-note' },
  settings: { title: 'Einstellungen', sub: 'Lokal & verschlüsselt',       icon: 'settings' },
};

export default function MainScreen({ onLogout, onChangePin, onWipeVault, securityStatus, isDecoy = false }: Props) {
  const [tab, setTab] = useState<Tab>('files');
  const safeBot = useBottomInset();
  const dynTabHeight = rs(56) + safeBot;

  const filesOpacity = useRef(new Animated.Value(1)).current;
  const notesOpacity = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.timing(filesOpacity, { toValue: 1, duration: 300, useNativeDriver: true }).start();
  }, []);

  const switchTab = (next: Tab) => {
    if (next === tab) return;
    if (next === 'files' || next === 'notes') {
      const fadeIn  = next === 'files' ? filesOpacity : notesOpacity;
      const fadeOut = next === 'files' ? notesOpacity : filesOpacity;
      Animated.parallel([
        Animated.timing(fadeOut, { toValue: 0, duration: 120, useNativeDriver: true }),
        Animated.timing(fadeIn,  { toValue: 1, duration: 160, useNativeDriver: true }),
      ]).start();
    }
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

  const meta = TAB_META[tab];

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />

      {/* ── Header: brand row ── */}
      <View style={s.header}>
        {securityStatus !== 'secure' && (
          <View style={[s.secBanner, { backgroundColor: securityStatus === 'critical' ? c.danger : c.warning }]}>
            <Text style={s.secTxt}>
              {securityStatus === 'critical' ? 'Sicherheitsalarm' : 'Sicherheitshinweis'}
            </Text>
          </View>
        )}

        <View style={s.brandRow}>
          <VaultMark size={rs(26)} />
          <View style={{ flex: 1 }}>
            <Text style={s.wordmark}>OBSCURA</Text>
            <View style={s.statusRow}>
              <View style={s.statusDot} />
              <Text style={s.statusTxt}>ENTSPERRT</Text>
            </View>
          </View>
          <TouchableOpacity style={s.iconBtn} onPress={handleLogout} activeOpacity={0.7} accessibilityLabel="Sperren">
            <Icon name="lock" size={rs(19)} color={c.textSec} />
          </TouchableOpacity>
        </View>

        {/* ── Title row ── */}
        <View style={s.titleRow}>
          <Text style={s.title}>{meta.title}</Text>
          <View style={s.subRow}>
            <View style={s.subTick} />
            <Text style={s.subTxt}>{meta.sub}</Text>
          </View>
        </View>
      </View>

      {/* ── Tab content ── */}
      <View style={s.content}>
        <Animated.View
          style={[StyleSheet.absoluteFill, { opacity: filesOpacity }]}
          pointerEvents={tab === 'files' ? 'auto' : 'none'}
        >
          <FilesView isDecoy={isDecoy} />
        </Animated.View>

        <Animated.View
          style={[StyleSheet.absoluteFill, { opacity: notesOpacity }]}
          pointerEvents={tab === 'notes' ? 'auto' : 'none'}
        >
          <NotesScreen isDecoy={isDecoy} />
        </Animated.View>

        {tab === 'settings' && (
          <View style={StyleSheet.absoluteFill}>
            <SettingsScreen
              embedded
              visible
              onClose={() => switchTab('files')}
              onChangePin={onChangePin ?? (() => Promise.resolve(false))}
              onWipeVault={onWipeVault ?? (() => Promise.resolve())}
              onLogout={onLogout}
              securityStatus={securityStatus}
            />
          </View>
        )}
      </View>

      {/* ── Bottom tab bar ── */}
      <View style={[s.tabBar, { height: dynTabHeight, paddingBottom: safeBot }]}>
        {(['files', 'notes', 'settings'] as Tab[]).map(k => (
          <TabItem
            key={k}
            icon={TAB_META[k].icon}
            label={TAB_META[k].title}
            active={tab === k}
            onPress={() => switchTab(k)}
          />
        ))}
      </View>
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
  return (
    <TouchableOpacity
      style={ts.item}
      onPress={onPress}
      activeOpacity={0.7}
      accessibilityRole="tab"
      accessibilityState={{ selected: active }}
    >
      {active && <View style={ts.tick} />}
      <Icon name={icon} size={rs(22)} color={active ? c.accent : c.textTer} stroke={active ? 2 : 1.7} />
      <Text style={[ts.label, active && ts.labelActive]}>{label.toUpperCase()}</Text>
    </TouchableOpacity>
  );
}

// ─────────────────────────────── Styles ───────────────────────────────

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: c.bg },

  header: {
    paddingTop: SAFE_TOP,
    backgroundColor: c.bg,
    borderBottomWidth: 1,
    borderBottomColor: c.border,
  },
  secBanner: {
    paddingVertical: rs(4),
    alignItems: 'center',
  },
  secTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(10),
    letterSpacing: rs(1),
    textTransform: 'uppercase',
    color: '#0A0A0C',
  },
  brandRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(10),
    paddingHorizontal: rs(16),
    paddingTop: rs(8),
    paddingBottom: rs(8),
  },
  wordmark: {
    fontFamily: font.monoBold,
    fontSize: rs(14),
    letterSpacing: rs(2.5),
    color: c.text,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(6),
    marginTop: rs(4),
  },
  statusDot: { width: rs(5), height: rs(5), backgroundColor: c.accent },
  statusTxt: {
    fontFamily: font.mono,
    fontSize: rs(9.5),
    letterSpacing: rs(2),
    color: c.accent,
  },
  iconBtn: {
    width: rs(34),
    height: rs(34),
    alignItems: 'center',
    justifyContent: 'center',
  },
  titleRow: {
    paddingHorizontal: rs(18),
    paddingTop: rs(2),
    paddingBottom: rs(10),
  },
  title: {
    fontFamily: font.displayBold,
    fontSize: rs(26),
    color: c.text,
    letterSpacing: -0.5,
  },
  subRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(7),
    marginTop: rs(6),
  },
  subTick: { width: rs(10), height: 2, backgroundColor: c.accent },
  subTxt: {
    fontFamily: font.mono,
    fontSize: rs(10.5),
    letterSpacing: rs(0.5),
    color: c.textTer,
  },

  content: { flex: 1 },

  tabBar: {
    flexDirection: 'row',
    height: TAB_BAR_HEIGHT,
    backgroundColor: c.bg,
    borderTopWidth: 1,
    borderTopColor: c.border2,
    paddingBottom: SAFE_BOTTOM,
    paddingTop: rs(9),
  },
});

const ts = StyleSheet.create({
  item: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'flex-start',
    gap: rs(5),
    position: 'relative',
    paddingTop: rs(4),
  },
  tick: {
    position: 'absolute',
    top: rs(-9),
    width: rs(18),
    height: 2,
    backgroundColor: c.accent,
  },
  label: {
    fontFamily: font.monoBold,
    fontSize: rs(9.5),
    letterSpacing: rs(1.2),
    color: c.textTer,
  },
  labelActive: { color: c.accent },
});
