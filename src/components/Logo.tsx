/**
 * Obscura brand mark — three concentric circles (iris/aperture motif).
 *
 * Two usage modes:
 *  1. Static (header): <Logo size={28} />
 *  2. Auth lock:       <Logo size={88} locked animating={unlocking} onAnimationComplete={...} />
 *
 * In auth mode the mark starts red (locked) and cross-fades to green (unlocked)
 * with a scale bounce, matching the existing LockIcon behaviour.
 */

import React, { useEffect, useRef } from 'react';
import { Animated, StyleSheet } from 'react-native';
import Svg, { Circle, G, Defs, RadialGradient, Stop } from 'react-native-svg';
import { c } from '../theme';

interface LogoProps {
  size?: number;
  /** Override ring colour for static (non-auth) usage */
  color?: string;
  /** Show the locked/red initial state; required for auth screen */
  locked?: boolean;
  /** Triggers the locked → unlocked animation */
  animating?: boolean;
  onAnimationComplete?: () => void;
}

export default function Logo({
  size = 60,
  color = c.accent,
  locked = false,
  animating = false,
  onAnimationComplete,
}: LogoProps) {
  const progress = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    if (!animating) return;
    Animated.timing(progress, {
      toValue: 1,
      duration: 520,
      useNativeDriver: true,
    }).start(() => onAnimationComplete?.());
  }, [animating]);

  // ── Static header mark ──────────────────────────────────────────────
  if (!locked && !animating) {
    return <Mark size={size} color={color} />;
  }

  // ── Animated auth mark (locked → unlocked cross-fade + bounce) ──────
  const lockedOp   = progress.interpolate({ inputRange: [0, 1], outputRange: [1, 0] });
  const unlockedOp = progress.interpolate({ inputRange: [0, 1], outputRange: [0, 1] });
  const scale      = progress.interpolate({
    inputRange:  [0,    0.42, 0.72, 1],
    outputRange: [1, 0.87,  1.09, 1],
  });

  return (
    <Animated.View style={{ width: size, height: size, transform: [{ scale }] }}>
      <Animated.View style={[StyleSheet.absoluteFill, { opacity: lockedOp }]}>
        <Mark size={size} color={c.danger} />
      </Animated.View>
      <Animated.View style={[StyleSheet.absoluteFill, { opacity: unlockedOp }]}>
        <Mark size={size} color={c.success} />
      </Animated.View>
    </Animated.View>
  );
}

// ─────────────────────────────── Mark SVG ───────────────────────────────
// Three concentric circles — identical geometry to the app icon asset.
// Outer ring:  faint (opacity 0.28)
// Middle ring: medium (opacity 0.58)
// Inner dot:   solid  (opacity 1.00)

function Mark({ size, color }: { size: number; color: string }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      {/* Outer ring */}
      <Circle
        cx="50" cy="50" r="43"
        stroke={color}
        strokeWidth="3.2"
        opacity={0.28}
      />
      {/* Middle ring */}
      <Circle
        cx="50" cy="50" r="30"
        stroke={color}
        strokeWidth="3.2"
        opacity={0.58}
      />
      {/* Inner filled dot */}
      <Circle
        cx="50" cy="50" r="13"
        fill={color}
        opacity={0.95}
      />
    </Svg>
  );
}
