// Minimal React Native mock for unit tests.
//
// AppState is a real, controllable implementation rather than a stub: AutoLockService registers
// the background-lock listener through it, and with AppState missing entirely
// setupAppStateListener() threw into initialize()'s catch — so the whole background-lock path
// was silently unexercised by the host suite. `__emit(state)` lets a test drive a transition.
const appStateListeners = new Set();

const AppState = {
  currentState: 'active',
  addEventListener: jest.fn((type, handler) => {
    if (type !== 'change') return { remove: () => {} };
    appStateListeners.add(handler);
    return { remove: () => appStateListeners.delete(handler) };
  }),
  /** Test helper: drive an app-state transition through every live listener. */
  __emit: (state) => {
    AppState.currentState = state;
    for (const h of [...appStateListeners]) h(state);
  },
  /** Test helper: how many listeners are currently registered. */
  __listenerCount: () => appStateListeners.size,
  __reset: () => appStateListeners.clear(),
};

// NativeModules is anchored on globalThis so it survives jest.isolateModules(). The native
// bridges (src/native/*.ts) snapshot `NativeModules.X` into a module-level const at import time,
// so a test that needs a module present must install it and then re-require the service in a
// fresh registry — which re-evaluates THIS mock too. Without the global anchor the isolated
// registry would get a brand-new empty object and the installed module would be invisible.
globalThis.__rnNativeModules = globalThis.__rnNativeModules || {};

function createNativeKeyCustodyMock(opts = {}) {
  const store = new Map();
  const registerGate = opts.registerGate || Promise.resolve();

  function requireHandle(handle) {
    if (!store.has(handle)) throw new Error(`NativeKeyCustody mock: unknown handle ${handle}`);
  }

  return {
    __store: store,
    registerRawKey: jest.fn(async ({ handle, keyHex }) => {
      await registerGate;
      store.set(handle, keyHex);
      return handle;
    }),
    openVault: jest.fn(async () => {
      throw new Error('NativeKeyCustody mock: openVault not implemented');
    }),
    unwrapVaultWithKek: jest.fn(async () => {
      throw new Error('NativeKeyCustody mock: unwrapVaultWithKek not implemented');
    }),
    rewrapVault: jest.fn(async ({ handle }) => {
      requireHandle(handle);
      return { ivHex: '00'.repeat(16), ctHex: '00'.repeat(48), macHex: '00'.repeat(16) };
    }),
    encryptContent: jest.fn(async ({ handle, dataB64 }) => {
      requireHandle(handle);
      return { cipherHex: Buffer.from(dataB64, 'base64').toString('hex'), tagHex: '00'.repeat(16) };
    }),
    decryptContent: jest.fn(async ({ handle, cipherHex }) => {
      requireHandle(handle);
      return Buffer.from(cipherHex, 'hex').toString('base64');
    }),
    wrapKey: jest.fn(async ({ handle, plaintextHex }) => {
      requireHandle(handle);
      return { ctHex: plaintextHex, macHex: '00'.repeat(16) };
    }),
    unwrapKey: jest.fn(async ({ handle, ctHex }) => {
      requireHandle(handle);
      return Buffer.from(ctHex, 'hex').toString('utf8');
    }),
    hasHandle: jest.fn(async ({ handle }) => store.has(handle)),
    closeVault: jest.fn(async ({ handle }) => store.delete(handle)),
    closeAll: jest.fn(async () => {
      store.clear();
    }),
  };
}

module.exports = {
  NativeModules: globalThis.__rnNativeModules,
  Platform: { OS: 'android', select: (obj) => obj.android ?? obj.default },
  Alert: { alert: jest.fn() },
  Vibration: { vibrate: jest.fn() },
  AppState,
  createNativeKeyCustodyMock,
};
