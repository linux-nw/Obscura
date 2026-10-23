import { AutoLockService } from '../src/services/AutoLockService';

describe('Sec_App: auto-lock fail-safe', () => {
  afterEach(() => {
    AutoLockService.endPickerSession();
    AutoLockService.setLockCallback(() => {});
    jest.restoreAllMocks();
  });

  test('UI lock callback fires even if persisting the lock flag fails', async () => {
    const SecureStore = require('expo-secure-store');
    SecureStore.setItemAsync.mockRejectedValueOnce(new Error('keystore down'));
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test('a hung picker session expires and no longer suppresses locking', async () => {
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);
    const now = Date.now();
    AutoLockService.beginPickerSession();
    expect(AutoLockService.isPickerActive()).toBe(true);
    jest.spyOn(Date, 'now').mockReturnValue(now + 6 * 60 * 1000);
    expect(AutoLockService.isPickerActive()).toBe(false);
    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
