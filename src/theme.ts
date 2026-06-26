import { Dimensions, Platform, StatusBar } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

const { width: W } = Dimensions.get('window');

// Responsive font/size scaling (phone-width-aware)
export const rs = (n: number): number => {
  if (W <= 360) return Math.round(n * 0.91);
  if (W >= 430) return Math.round(n * 1.06);
  return n;
};

// Safe area constants (edge-to-edge compatible)
export const SAFE_TOP =
  Platform.OS === 'ios' ? 54 : (StatusBar.currentHeight ?? 24);
export const SAFE_BOTTOM = Platform.OS === 'ios' ? 34 : 12;
export const TAB_BAR_HEIGHT = rs(56) + SAFE_BOTTOM;

// Hook: returns actual bottom inset from OS (gesture nav, home indicator, button nav).
// Falls back to SAFE_BOTTOM when SafeAreaProvider is not in tree.
export function useBottomInset(): number {
  const insets = useSafeAreaInsets();
  return Math.max(SAFE_BOTTOM, insets.bottom);
}

/**
 * OBSCURA — "Optical Instrument" design tokens (ported from obscura/theme.css).
 * Matte near-black body, a single amber signal, red only for destructive actions.
 *
 * NOTE: the historic `c.*` keys are preserved (lots of screens import them) but
 * remapped to the Obscura palette so the whole app adopts the new look at once.
 */
export const c = {
  // Backgrounds / surfaces
  bg:      '#0A0A0C',
  surface: '#121316',
  surface2:'#1A1B20',
  inset:   '#050506',
  card:    '#121316',
  cardEl:  '#1A1B20',

  // Borders / separators
  border:  '#232429',
  border2: '#34363D',
  sep:     '#232429',

  // amber signal
  accent:       '#E9A23B',
  accentBright: '#F6B557',
  accentDim:    'rgba(233,162,59,0.15)',
  accentBorder: 'rgba(233,162,59,0.38)',
  accentFg:     '#160F03',

  success:     '#2FB46F',
  successDim:  'rgba(47,180,111,0.14)',

  danger:      '#E5484D',
  dangerBright:'#F05A5F',
  dangerDim:   'rgba(229,72,77,0.13)',
  dangerBorder:'rgba(229,72,77,0.42)',

  // warn channel == amber signal (per design)
  warning:     '#E9A23B',
  warningDim:  'rgba(233,162,59,0.12)',

  purple:      '#BF5AF2',
  purpleDim:   'rgba(191,90,242,0.14)',

  teal:        '#5AC8FA',
  tealDim:     'rgba(90,200,250,0.14)',

  // Text hierarchy
  text:    '#ECECEF',
  textSec: '#B4B6BD',
  textTer: '#51535A',
  textFaint: '#51535A',

  // Overlays
  overlay: 'rgba(3,3,4,0.7)',
  overlayMid: 'rgba(3,3,4,0.55)',
} as const;

/**
 * Font families. Names match the @expo-google-fonts keys loaded in App.tsx.
 * mono = Space Mono (wordmark, labels, data, buttons)
 * display = Space Grotesk (headings)
 * sans = IBM Plex Sans (reading)
 */
export const font = {
  mono:        'SpaceMono_400Regular',
  monoBold:    'SpaceMono_700Bold',
  display:     'SpaceGrotesk_500Medium',
  displaySemi: 'SpaceGrotesk_600SemiBold',
  displayBold: 'SpaceGrotesk_700Bold',
  sans:        'IBMPlexSans_400Regular',
  sansMed:     'IBMPlexSans_500Medium',
  sansSemi:    'IBMPlexSans_600SemiBold',
} as const;

// square-ish geometry (the design uses 2-3px radii)
export const radius = { card: 3, input: 2, btn: 2 } as const;

// Per-file-type accent — the Obscura identity uses one amber signal, so all
// types share the accent (distinguished by the mono extension label instead).
export const fileColor = {
  image:    { accent: c.accent, dim: c.accentDim },
  video:    { accent: c.accent, dim: c.accentDim },
  document: { accent: c.accent, dim: c.accentDim },
} as const;
