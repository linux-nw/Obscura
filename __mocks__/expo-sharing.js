// Mock for expo-sharing — avoids the native ExpoSharing module require under Jest.
module.exports = {
  shareAsync: jest.fn(async () => {}),
  isAvailableAsync: jest.fn(async () => true),
};
