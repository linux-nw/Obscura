// Polyfill global.performance for React Native's PerformanceLogger in
// Hermes + New Architecture (Bridgeless Mode). The C++ JSI performance
// module may not be installed yet when createPerformanceLogger evaluates,
// causing: TypeError: Cannot read property 'now' of undefined
if (typeof global !== 'undefined' && !global.performance) {
  (global as any).performance = { now: () => Date.now() };
} else if (typeof global !== 'undefined' && typeof global.performance?.now !== 'function') {
  (global as any).performance = { ...global.performance, now: () => Date.now() };
}

import { registerRootComponent } from 'expo';

import App from './App';

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
