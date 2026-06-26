/**
 * Patches expo/src/winter/runtime.native.ts to guard the top-level
 * installFormDataPatch(FormData) call with a typeof check.
 *
 * In Hermes + New Architecture (Bridgeless Mode), FormData is not yet
 * defined on the global object when this module evaluates as a Metro
 * preModule, causing:
 *   [runtime not ready]: ReferenceError: Property 'FormData' doesn't exist
 *
 * The guard skips the patch when FormData is unavailable; the stock RN
 * FormData class is used instead (no WinterCG extension methods), which
 * is fine for this app.
 */
const fs = require('fs');
const path = require('path');

const target = path.join(
  __dirname,
  '../node_modules/expo/src/winter/runtime.native.ts'
);

if (!fs.existsSync(target)) {
  console.warn('[fix-expo-formdata] File not found, skipping patch:', target);
  process.exit(0);
}

const original = fs.readFileSync(target, 'utf8');
const BEFORE = 'installFormDataPatch(FormData);';
const AFTER = 'if (typeof FormData !== \'undefined\') {\n  installFormDataPatch(FormData);\n}';

if (original.includes(AFTER)) {
  console.log('[fix-expo-formdata] Already patched.');
  process.exit(0);
}

if (!original.includes(BEFORE)) {
  console.warn('[fix-expo-formdata] Target line not found — expo version may have changed.');
  process.exit(0);
}

fs.writeFileSync(target, original.replace(BEFORE, AFTER), 'utf8');
console.log('[fix-expo-formdata] Patched expo/src/winter/runtime.native.ts');
