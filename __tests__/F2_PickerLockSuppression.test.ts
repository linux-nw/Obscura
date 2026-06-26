/**
 * F2_PickerLockSuppression.test.ts
 *
 * Guards the picker-vs-autolock fix: while a system picker is open the app
 * goes to background, but the master key MUST survive (triggerLock suppressed)
 * so the picked file can be encrypted. Without this, file import is impossible
 * on device — proven by the device test that surfaced "Kein
 * Verschlüsselungsschlüssel gefunden".
 */

import { AutoLockService } from '../src/services/AutoLockService';

beforeEach(() => {
  // ensure clean flag state
  AutoLockService.endPickerSession();
});

describe('F2: AutoLock suppression during picker session', () => {
  test('triggerLock does NOT fire the callback while picker is active', async () => {
    const cb = jest.fn();
    AutoLockService.setLockCallback(cb);

    AutoLockService.beginPickerSession();
    expect(AutoLockService.isPickerActive()).toBe(true);

    await AutoLockService.triggerLock();
    expect(cb).not.toHaveBeenCalled(); // suppressed during picker

    AutoLockService.endPickerSession();
    expect(AutoLockService.isPickerActive()).toBe(false);

    await AutoLockService.triggerLock();
    expect(cb).toHaveBeenCalledTimes(1); // fires again once picker is done

    AutoLockService.setLockCallback(() => {});
  });

  test('endPickerSession always clears the flag (finally-safety)', () => {
    AutoLockService.beginPickerSession();
    expect(AutoLockService.isPickerActive()).toBe(true);
    AutoLockService.endPickerSession();
    expect(AutoLockService.isPickerActive()).toBe(false);
  });

  test('default state is not-active (no accidental permanent suppression)', () => {
    expect(AutoLockService.isPickerActive()).toBe(false);
  });
});
