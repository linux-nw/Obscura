import React, { ReactElement } from 'react';
import { View } from 'react-native';
import Svg, { Path, Circle, Rect } from 'react-native-svg';

type IconType = 'edit' | 'delete' | 'check' | 'close' | 'plus' | 'chevron-right' | 'lock';

interface ActionIconProps {
  type: IconType;
  size?: number;
  color?: string;
}

export default function ActionIcon({ type, size = 28, color }: ActionIconProps) {
  const defaultColors: Record<IconType, string> = {
    'edit':          '#FF9F0A',
    'delete':        '#FF453A',
    'check':         '#30D158',
    'close':         '#8E8E93',
    'plus':          '#0A84FF',
    'chevron-right': '#8E8E93',
    'lock':          '#8E8E93',
  };

  const stroke = color ?? defaultColors[type];
  const sw     = Math.max(1.2, size / 15);

  const icon: Record<IconType, ReactElement> = {
    'edit': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
        />
        <Path
          d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
        />
      </Svg>
    ),
    'delete': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
        />
        <Path
          d="M10 11v6M14 11v6"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round"
        />
      </Svg>
    ),
    'check': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M20 6L9 17l-5-5"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
        />
      </Svg>
    ),
    'close': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M18 6L6 18M6 6l12 12"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round"
        />
      </Svg>
    ),
    'plus': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M12 5v14M5 12h14"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round"
        />
      </Svg>
    ),
    'chevron-right': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Path
          d="M9 18l6-6-6-6"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
        />
      </Svg>
    ),
    'lock': (
      <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
        <Rect x="5" y="11" width="14" height="11" rx="2"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round"
        />
        <Path
          d="M8 11V7a4 4 0 0 1 8 0v4"
          stroke={stroke} strokeWidth={sw} strokeLinecap="round"
        />
        <Circle cx="12" cy="16" r="1.2" fill={stroke} />
      </Svg>
    ),
  };

  return (
    <View style={{ width: size, height: size, alignItems: 'center', justifyContent: 'center' }}>
      {icon[type]}
    </View>
  );
}
