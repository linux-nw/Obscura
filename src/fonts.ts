import * as Font from 'expo-font';

/**
 * Loads the Obscura type identity from bundled static TTFs (assets/fonts).
 * License-free: Space Mono + IBM Plex Sans (OFL), Space Grotesk (OFL).
 *
 * The registered family names match the `font` tokens in theme.ts. Best-effort:
 * if loading fails (e.g. native expo-font module absent), the app keeps running
 * with system-font fallback rather than crashing.
 */
export async function loadObscuraFonts(): Promise<void> {
  try {
    await Font.loadAsync({
      SpaceMono_400Regular: require('../assets/fonts/SpaceMono-Regular.ttf'),
      SpaceMono_700Bold: require('../assets/fonts/SpaceMono-Bold.ttf'),
      SpaceGrotesk_500Medium: require('../assets/fonts/SpaceGrotesk-Medium.ttf'),
      SpaceGrotesk_600SemiBold: require('../assets/fonts/SpaceGrotesk-SemiBold.ttf'),
      SpaceGrotesk_700Bold: require('../assets/fonts/SpaceGrotesk-Bold.ttf'),
      IBMPlexSans_400Regular: require('../assets/fonts/IBMPlexSans-Regular.ttf'),
      IBMPlexSans_500Medium: require('../assets/fonts/IBMPlexSans-Medium.ttf'),
      IBMPlexSans_600SemiBold: require('../assets/fonts/IBMPlexSans-SemiBold.ttf'),
    });
  } catch (e) {
    console.warn('[fonts] Obscura fonts failed to load — using system fallback.', e);
  }
}
