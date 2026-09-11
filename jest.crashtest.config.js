// Dedicated Jest config for the real-process kill-9 rotation crash test
// (scripts/crash-test/). NOT used by `npm test` (package.json's own "jest" key is the
// default config) - this one is only ever invoked explicitly, via
// `node scripts/crash-test/orchestrate.js`, because phase1 deliberately hangs forever
// and would otherwise block the normal test suite.
module.exports = {
  preset: 'jest-expo',
  rootDir: __dirname,
  testMatch: ['<rootDir>/scripts/crash-test/phase*.ts'],
  transformIgnorePatterns: [
    'node_modules/(?!((jest-)?react-native|@react-native(-community)?)|expo(nent)?|@expo(nent)?/.*|@expo-google-fonts/.*|react-navigation|@react-navigation/.*|@unimodules/.*|unimodules|sentry-expo|native-base|react-native-svg|crypto-js|@noble/.*)',
  ],
  moduleNameMapper: {
    '^@noble/hashes/argon2.js$': '<rootDir>/__mocks__/noble-argon2.js',
    '^expo-crypto$': '<rootDir>/__mocks__/expo-crypto.js',
    '^react-native$': '<rootDir>/__mocks__/react-native.js',
    '^hash-wasm$': '<rootDir>/__mocks__/hash-wasm.js',
  },
};
