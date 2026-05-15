import React, { useEffect, useRef } from 'react';
import { View, Animated, StyleSheet } from 'react-native';
import Svg, { Path, Rect, Circle } from 'react-native-svg';

interface LockIconProps {
  locked: boolean;
  size?: number;
  animating?: boolean;
  onAnimationComplete?: () => void;
}

export default function LockIcon({ locked, size = 60, animating = false, onAnimationComplete }: LockIconProps) {
  const progress = useRef(new Animated.Value(locked ? 0 : 1)).current;

  useEffect(() => {
    if (!animating) return;
    Animated.timing(progress, {
      toValue: 1,
      duration: 480,
      useNativeDriver: true,
    }).start(() => {
      onAnimationComplete?.();
    });
  }, [animating]);

  const lockedOpacity = progress.interpolate({ inputRange: [0, 1], outputRange: [1, 0] });
  const unlockedOpacity = progress.interpolate({ inputRange: [0, 1], outputRange: [0, 1] });
  const scale = progress.interpolate({
    inputRange: [0, 0.45, 0.75, 1],
    outputRange: [1, 0.88, 1.1, 1],
  });

  return (
    <Animated.View style={{ width: size, height: size, transform: [{ scale }] }}>
      {/* Geschlossen – rot */}
      <Animated.View style={[StyleSheet.absoluteFill, { opacity: lockedOpacity }]}>
        <Svg width={size} height={size} viewBox="0 0 100 110" fill="none">
          <Rect x="12" y="50" width="76" height="56" rx="11" fill="#FF3B30" />
          <Path
            d="M 30 52 L 30 30 Q 50 11 70 30 L 70 52"
            stroke="#FF3B30"
            strokeWidth="11"
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <Circle cx="50" cy="75" r="7" fill="rgba(0,0,0,0.22)" />
          <Rect x="47" y="75" width="6" height="10" rx="3" fill="rgba(0,0,0,0.22)" />
        </Svg>
      </Animated.View>

      {/* Offen – grün */}
      <Animated.View style={[StyleSheet.absoluteFill, { opacity: unlockedOpacity }]}>
        <Svg width={size} height={size} viewBox="0 0 100 110" fill="none">
          <Rect x="12" y="50" width="76" height="56" rx="11" fill="#34C759" />
          <Path
            d="M 30 52 L 30 30 Q 50 11 70 30 L 70 16"
            stroke="#34C759"
            strokeWidth="11"
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <Circle cx="50" cy="75" r="7" fill="rgba(0,0,0,0.22)" />
        </Svg>
      </Animated.View>
    </Animated.View>
  );
}
