// Mock for expo-secure-store: in-memory key-value store.
const store = new Map();

module.exports = {
  getItemAsync: jest.fn(async (key) => store.get(key) ?? null),
  setItemAsync: jest.fn(async (key, value) => { store.set(key, value); }),
  deleteItemAsync: jest.fn(async (key) => { store.delete(key); }),
  _reset: () => store.clear(),
  _store: store,
};
