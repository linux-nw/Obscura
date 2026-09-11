const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Strip console.* calls from production bundles. Every native-bridge rejection on
// Android carries a `nativeStackAndroid` field (React Native attaches the native
// Kotlin/Java stack trace to the JS Error automatically); this codebase's many
// `catch (error) { console.error(...) }` blocks would otherwise print that - plus
// panic/decoy configuration state, key-rotation progress, etc. - straight into
// `adb logcat` on a shipped release build, readable by anyone with device access.
if (process.env.NODE_ENV === 'production') {
  config.transformer.minifierConfig = {
    ...config.transformer.minifierConfig,
    compress: {
      ...(config.transformer.minifierConfig && config.transformer.minifierConfig.compress),
      drop_console: true,
    },
  };
}

module.exports = config;
