// Obscura FileVault: exclude vault data from Android Auto Backup / device-to-device transfer.
//
// Why this exists: nothing in app.json's `android` block, and no Android config plugin,
// previously set `android:allowBackup`. Expo's generated AndroidManifest.xml then keeps the
// Android platform default (true). FileSystem.documentDirectory (where vault/, notes/ and
// backups/ live) maps to Context.getFilesDir(), which IS included in Android Auto Backup by
// default when allowBackup is true or unset - only cacheDirectory is excluded by the OS.
// That means the encrypted vault could be copied into the user's Google Account cloud backup
// (or a device-to-device transfer) without any code in this repo ever deciding that should
// happen. The ciphertext itself stays protected by the PIN/biometric-derived master key, but
// it hands an attacker with access to that Google account (or backup) an offline copy of the
// entire vault to brute-force at their leisure, with no on-device rate limiting.
//
// Setting allowBackup="false" disables both Android's classic cloud backup AND (per Android's
// own docs) device-to-device migration for this app, for every Android version - the simplest
// correct fix, since a vault app has no legitimate reason to want any of its files backed up.
//
// NOT verified against a real `expo prebuild`/build in this environment (no Android SDK/
// Gradle toolchain available) - verified only by reading the @expo/config-plugins source this
// plugin calls against (getMainApplicationOrThrow, withAndroidManifest) to confirm the shape
// of the manifest object being mutated.

const { withAndroidManifest, AndroidConfig } = require('@expo/config-plugins');

function withDisableAndroidBackup(config) {
  return withAndroidManifest(config, (config) => {
    const mainApplication = AndroidConfig.Manifest.getMainApplicationOrThrow(config.modResults);
    mainApplication.$['android:allowBackup'] = 'false';
    return config;
  });
}

module.exports = withDisableAndroidBackup;
