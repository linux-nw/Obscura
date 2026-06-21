/**
 * Patches react-native/Libraries/Utilities/createPerformanceLogger.js to
 * use optional chaining when accessing global.performance.now().
 *
 * In Hermes + New Architecture (Bridgeless Mode), global.performance may be
 * undefined at the time PerformanceLogger.startTimespan() is called during
 * renderApplication, causing:
 *   TypeError: Cannot read property 'now' of undefined
 *
 * The fix uses optional chaining + Date.now() fallback so the logger never
 * crashes regardless of whether the C++ performance module is ready.
 */
const fs = require('fs');
const path = require('path');

const target = path.join(
  __dirname,
  '../node_modules/react-native/Libraries/Utilities/createPerformanceLogger.js'
);

if (!fs.existsSync(target)) {
  console.warn('[fix-perf-logger] File not found, skipping:', target);
  process.exit(0);
}

const original = fs.readFileSync(target, 'utf8');
const BEFORE = 'global.nativeQPLTimestamp ?? (() => global.performance.now());';
const AFTER  = 'global.nativeQPLTimestamp ??\n  (() => global.performance?.now?.() ?? Date.now());';

if (original.includes(AFTER)) {
  console.log('[fix-perf-logger] Already patched.');
  process.exit(0);
}

if (!original.includes(BEFORE)) {
  console.warn('[fix-perf-logger] Target line not found — react-native version may have changed.');
  process.exit(0);
}

fs.writeFileSync(target, original.replace(BEFORE, AFTER), 'utf8');
console.log('[fix-perf-logger] Patched createPerformanceLogger.js');
