import React from 'react';
import { View } from 'react-native';
import Svg, { Path, Circle, Rect } from 'react-native-svg';

interface FileIconProps {
  type: 'image' | 'video' | 'document';
  size?: number;
  color?: string;
}

export default function FileIcon({ type, size = 28, color = '#0A84FF' }: FileIconProps) {
  return (
    <View style={{ width: size, height: size, alignItems: 'center', justifyContent: 'center' }}>
      {type === 'image'    && <ImageIcon    size={size} color={color} />}
      {type === 'video'    && <VideoIcon    size={size} color={color} />}
      {type === 'document' && <DocumentIcon size={size} color={color} />}
    </View>
  );
}

// ─────────────────────────────── Icon shapes ───────────────────────────────

function ImageIcon({ size, color }: { size: number; color: string }) {
  const sw = size / 13;
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <Rect x="2" y="2" width="20" height="20" rx="3"
        stroke={color} strokeWidth={sw} strokeLinecap="round" />
      <Circle cx="8.5" cy="8.5" r="1.8"
        stroke={color} strokeWidth={sw} />
      <Path d="M2 16l5-5 4 4 3-3 5 5"
        stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

function VideoIcon({ size, color }: { size: number; color: string }) {
  const sw = size / 13;
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <Rect x="2" y="4" width="14" height="16" rx="2"
        stroke={color} strokeWidth={sw} strokeLinecap="round" />
      <Path d="M16 8.5l6-3v13l-6-3"
        stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

function DocumentIcon({ size, color }: { size: number; color: string }) {
  const sw = size / 13;
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <Path d="M14 2H6C4.9 2 4 2.9 4 4v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z"
        stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
      <Path d="M14 2v6h6"
        stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
      <Path d="M8 13h8M8 17h5"
        stroke={color} strokeWidth={sw} strokeLinecap="round" />
    </Svg>
  );
}
