import React, { useEffect, useRef } from 'react';
import { View, Animated, Easing, StyleSheet } from 'react-native';
import Svg, { Line, Circle, Path } from 'react-native-svg';
import { c } from '../theme';

/**
 * Obscura brand mark — an aperture / iris diaphragm with a keyhole.
 * Ported from obscura/components.jsx (VaultMark). 48×48 viewBox.
 */
interface Props {
  size?: number;
  locked?: boolean;
  accent?: string;
  spinning?: boolean;
}

export default function VaultMark({ size = 40, locked = true, accent, spinning }: Props) {
  const a = accent || c.accent;
  const center = 24;
  const rOut = 24 * 0.43;
  const rIn = 24 * 0.14;

  const blades = [];
  for (let i = 0; i < 6; i++) {
    const ang = ((i * 60 + 25) * Math.PI) / 180;
    const tx = center + rIn * Math.cos(ang);
    const ty = center + rIn * Math.sin(ang);
    const L = Math.sqrt(Math.max(0, rOut * rOut - rIn * rIn));
    const dx = -Math.sin(ang);
    const dy = Math.cos(ang);
    blades.push(
      <Line
        key={i}
        x1={(tx + L * dx).toFixed(2)}
        y1={(ty + L * dy).toFixed(2)}
        x2={(tx - L * dx).toFixed(2)}
        y2={(ty - L * dy).toFixed(2)}
        stroke={a}
        strokeWidth={24 * 0.04}
        strokeLinecap="round"
      />
    );
  }

  const spin = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    if (!spinning) return;
    const loop = Animated.loop(
      Animated.timing(spin, { toValue: 1, duration: 2600, easing: Easing.linear, useNativeDriver: true })
    );
    loop.start();
    return () => loop.stop();
  }, [spinning]);
  const rotate = spin.interpolate({ inputRange: [0, 1], outputRange: ['0deg', '360deg'] });

  return (
    <Animated.View style={[styles.wrap, { width: size, height: size }, spinning && { transform: [{ rotate }] }]}>
      <Svg width={size} height={size} viewBox="0 0 48 48">
        {blades}
        {locked ? (
          <>
            <Circle cx={center} cy={center - 0.3} r={24 * 0.05} fill={a} />
            <Path
              d={`M${center} ${center + 0.4} L${(center - 24 * 0.04).toFixed(2)} ${(center + 24 * 0.092).toFixed(2)} H${(center + 24 * 0.04).toFixed(2)} Z`}
              fill={a}
            />
          </>
        ) : (
          <Circle cx={center} cy={center} r={24 * 0.05} fill="none" stroke={a} strokeWidth={1.3} />
        )}
      </Svg>
    </Animated.View>
  );
}

/** Registration-tick frame (instrument motif) drawn around a hero mark. */
export function CornerFrame({ size = 116, tick = 11, color = c.border2 }: { size?: number; tick?: number; color?: string }) {
  const b = 1.5;
  return (
    <View pointerEvents="none" style={[StyleSheet.absoluteFill, { width: size, height: size }]}>
      <View style={[corner.base, { top: 0, left: 0, width: tick, height: tick, borderColor: color, borderTopWidth: b, borderLeftWidth: b }]} />
      <View style={[corner.base, { top: 0, right: 0, width: tick, height: tick, borderColor: color, borderTopWidth: b, borderRightWidth: b }]} />
      <View style={[corner.base, { bottom: 0, left: 0, width: tick, height: tick, borderColor: color, borderBottomWidth: b, borderLeftWidth: b }]} />
      <View style={[corner.base, { bottom: 0, right: 0, width: tick, height: tick, borderColor: color, borderBottomWidth: b, borderRightWidth: b }]} />
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { alignItems: 'center', justifyContent: 'center' },
});
const corner = StyleSheet.create({
  base: { position: 'absolute' },
});
