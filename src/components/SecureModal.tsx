import React, { useEffect } from 'react';
import { BackHandler, StyleSheet, View } from 'react-native';

interface Props {
  visible: boolean;
  onRequestClose?: () => void;
  children?: React.ReactNode;
  [key: string]: unknown;
}

/**
 * Drop-in replacement for react-native `Modal` that renders in the activity's own window.
 * RN's Modal on Android opens a separate Dialog window that does NOT inherit the activity's
 * FLAG_SECURE, so decrypted content or passphrase fields inside it can be screenshotted /
 * screen-recorded. This overlay stays inside the protected window.
 */
export default function SecureModal({ visible, onRequestClose, children }: Props) {
  useEffect(() => {
    if (!visible || !onRequestClose) return;
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      onRequestClose();
      return true;
    });
    return () => sub.remove();
  }, [visible, onRequestClose]);

  if (!visible) return null;
  return (
    <View style={styles.overlay} pointerEvents="auto">
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  overlay: { ...StyleSheet.absoluteFillObject, zIndex: 1000, elevation: 1000 },
});
