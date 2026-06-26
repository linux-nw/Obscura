// In-memory mock for @react-native-async-storage/async-storage (default export).
// SettingsService uses getItem/setItem; the rest are provided for completeness.
const store = new Map();

const AsyncStorage = {
  getItem: jest.fn(async (k) => (store.has(k) ? store.get(k) : null)),
  setItem: jest.fn(async (k, v) => { store.set(k, String(v)); }),
  removeItem: jest.fn(async (k) => { store.delete(k); }),
  clear: jest.fn(async () => { store.clear(); }),
  getAllKeys: jest.fn(async () => [...store.keys()]),
  _reset: () => store.clear(),
};

module.exports = { __esModule: true, default: AsyncStorage };
