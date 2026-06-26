// Minimal React Native mock for unit tests.
module.exports = {
  NativeModules: {},
  Platform: { OS: 'android', select: (obj) => obj.android ?? obj.default },
  Alert: { alert: jest.fn() },
  Vibration: { vibrate: jest.fn() },
};
