import { Dimensions, Platform, StatusBar } from 'react-native';

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
export const TAB_BAR_HEIGHT = rs(52) + SAFE_BOTTOM;

// Design tokens
export const c = {
  // Backgrounds
  bg:      '#090909',
  surface: '#111113',
  card:    '#161618',
  cardEl:  '#1C1C1E',

  // Borders / separators
  border:  '#222224',
  sep:     '#1E1E20',

  // iOS system colors — dark mode variants
  accent:      '#0A84FF',
  accentDim:   'rgba(10,132,255,0.14)',
  accentBorder:'rgba(10,132,255,0.30)',

  success:     '#30D158',
  successDim:  'rgba(48,209,88,0.14)',

  danger:      '#FF453A',
  dangerDim:   'rgba(255,69,58,0.14)',

  warning:     '#FF9F0A',
  warningDim:  'rgba(255,159,10,0.14)',

  purple:      '#BF5AF2',
  purpleDim:   'rgba(191,90,242,0.14)',

  teal:        '#5AC8FA',
  tealDim:     'rgba(90,200,250,0.14)',

  // Text hierarchy
  text:    '#FFFFFF',
  textSec: '#8E8E93',
  textTer: '#3A3A3C',

  // Overlays
  overlay: 'rgba(0,0,0,0.75)',
  overlayMid: 'rgba(0,0,0,0.55)',
} as const;

// Per-file-type accent colors
export const fileColor = {
  image:    { accent: '#30D158', dim: 'rgba(48,209,88,0.14)'    },
  video:    { accent: '#BF5AF2', dim: 'rgba(191,90,242,0.14)'   },
  document: { accent: '#0A84FF', dim: 'rgba(10,132,255,0.14)'   },
} as const;
