const { withAndroidManifest } = require('@expo/config-plugins');

/**
 * Obscura is documented (README.md, SECURITY.md) as an offline, zero-knowledge app with no
 * network-adjacent permissions. `expo prebuild` regenerates AndroidManifest.xml from scratch
 * every time, and several dependencies inject permissions this app doesn't need or want:
 * INTERNET is hardcoded by @expo/config-plugins' own base manifest template and separately
 * re-declared by expo-file-system's and expo-video's own library manifests; SYSTEM_ALERT_WINDOW
 * comes from the same base template. Neither is requested in app.json's explicit
 * android.permissions list, and no code in src/ makes a network call.
 *
 * A plain removal from the app's own manifest is not enough: Gradle's manifest merger re-adds
 * a permission a dependency's own library manifest declares, unless the app manifest explicitly
 * marks it `tools:node="remove"` to override the merge. That's what this plugin adds, so the
 * strip survives every future `expo prebuild` run instead of needing to be manually reapplied
 * (which is exactly what went unnoticed the first time — see AUDIT_2026-09-15-v2.md, B.2).
 */
const STRIPPED_PERMISSIONS = [
  'android.permission.INTERNET',
  'android.permission.SYSTEM_ALERT_WINDOW',
];

/** Pure mutation, kept separate from the withAndroidManifest wrapper so it's unit-testable
 * without going through Expo's async mod-compilation pipeline. */
function markPermissionsForRemoval(androidManifest) {
  if (!Array.isArray(androidManifest['uses-permission'])) {
    androidManifest['uses-permission'] = [];
  }

  for (const permissionName of STRIPPED_PERMISSIONS) {
    const existing = androidManifest['uses-permission'].find(
      (entry) => entry.$ && entry.$['android:name'] === permissionName
    );
    if (existing) {
      existing.$['tools:node'] = 'remove';
    } else {
      androidManifest['uses-permission'].push({
        $: { 'android:name': permissionName, 'tools:node': 'remove' },
      });
    }
  }

  return androidManifest;
}

function withStrippedAndroidPermissions(config) {
  return withAndroidManifest(config, (config) => {
    markPermissionsForRemoval(config.modResults.manifest);
    return config;
  });
}

module.exports = withStrippedAndroidPermissions;
module.exports.STRIPPED_PERMISSIONS = STRIPPED_PERMISSIONS;
module.exports.markPermissionsForRemoval = markPermissionsForRemoval;
