/**
 * A3-AUTH: AuthScreen probes all three credentials (real / panic / decoy) in parallel so the
 * three paths are indistinguishable by timing. Two of the three necessarily fail on every
 * login, so calling SecureCryptoService.unlock() unwrapped charged a failed attempt against
 * the REAL vault on every successful decoy or panic login — five decoy logins locked the real
 * vault for 5 minutes, and the lockout message told an observer a second, real credential
 * exists (a deniability leak).
 *
 * AuthScreen.checkLoginPass now wraps the parallel probe in
 * SecureCryptoService.withAttemptCountSuppressed() and calls registerFailedUnlock() only in
 * the branch where none of the three matched. This test exercises that exact pattern at the
 * service layer (the same sequence AuthScreen.tsx runs) and proves the real security property:
 * a successful decoy/panic login never touches the real vault's failed-attempt counter, while
 * a genuine wrong password still charges exactly one attempt.
 */

const secureStore = require('../__mocks__/expo-secure-store');

beforeEach(async () => {
  secureStore._reset();
  SecureCryptoService.clearAllCaches();
});

import { SecureCryptoService } from '../src/services/CryptoService';
import { PanicService } from '../src/services/PanicService';
import { DecoyVaultService } from '../src/services/DecoyVaultService';

const REAL_PASSPHRASE = 'RealVaultPass123!';
const DECOY_PIN = 'decoy-pin-456!';
const PANIC_PIN = 'panic-pin-789!';
const FAILED_ATTEMPTS_KEY = 'filevault_failed_attempts';

/** The exact pattern AuthScreen.checkLoginPass runs. */
async function simulateAuthScreenLogin(entered: string) {
  const [panicMatch, realMatch, decoyMatch] = await SecureCryptoService.withAttemptCountSuppressed(() =>
    Promise.all([
      PanicService.verifyPanicPin(entered),
      SecureCryptoService.unlock(entered),
      DecoyVaultService.verifyDecoyPin(entered),
    ])
  );
  if (!panicMatch && !realMatch && !decoyMatch) {
    await SecureCryptoService.registerFailedUnlock();
  }
  return { panicMatch, realMatch, decoyMatch };
}

test('A3-AUTH: a successful decoy login does not increment the real vault failed-attempt counter', async () => {
  await SecureCryptoService.setupMasterKey(REAL_PASSPHRASE);
  await DecoyVaultService.setDecoyPin(DECOY_PIN);

  const { panicMatch, realMatch, decoyMatch } = await simulateAuthScreenLogin(DECOY_PIN);
  expect(decoyMatch).toBe(true);
  expect(realMatch).toBe(false);
  expect(panicMatch).toBe(false);

  expect(await secureStore.getItemAsync(FAILED_ATTEMPTS_KEY)).toBeNull();
});

test('A3-AUTH: a successful panic login does not increment the real vault failed-attempt counter', async () => {
  await SecureCryptoService.setupMasterKey(REAL_PASSPHRASE);
  await PanicService.setPanicPin(PANIC_PIN);

  const { panicMatch, realMatch, decoyMatch } = await simulateAuthScreenLogin(PANIC_PIN);
  expect(panicMatch).toBe(true);
  expect(realMatch).toBe(false);
  expect(decoyMatch).toBe(false);

  expect(await secureStore.getItemAsync(FAILED_ATTEMPTS_KEY)).toBeNull();
});

test('A3-AUTH: a successful real-passphrase login does not increment the failed-attempt counter', async () => {
  await SecureCryptoService.setupMasterKey(REAL_PASSPHRASE);
  await DecoyVaultService.setDecoyPin(DECOY_PIN);

  const { realMatch } = await simulateAuthScreenLogin(REAL_PASSPHRASE);
  expect(realMatch).toBe(true);

  expect(await secureStore.getItemAsync(FAILED_ATTEMPTS_KEY)).toBeNull();
});

test('A3-AUTH: a genuine wrong password (none of the three match) charges exactly one failed attempt', async () => {
  await SecureCryptoService.setupMasterKey(REAL_PASSPHRASE);
  await DecoyVaultService.setDecoyPin(DECOY_PIN);
  await PanicService.setPanicPin(PANIC_PIN);

  const { panicMatch, realMatch, decoyMatch } = await simulateAuthScreenLogin('totally-wrong-password');
  expect(panicMatch).toBe(false);
  expect(realMatch).toBe(false);
  expect(decoyMatch).toBe(false);

  expect(await secureStore.getItemAsync(FAILED_ATTEMPTS_KEY)).toBe('1');
});

test('A3-AUTH: repeated decoy logins never accumulate failed attempts (the original bug scenario)', async () => {
  await SecureCryptoService.setupMasterKey(REAL_PASSPHRASE);
  await DecoyVaultService.setDecoyPin(DECOY_PIN);

  for (let i = 0; i < 5; i++) {
    const { decoyMatch } = await simulateAuthScreenLogin(DECOY_PIN);
    expect(decoyMatch).toBe(true);
  }

  // Before the fix, 5 decoy logins would have locked the real vault (maxFailedAttempts default).
  expect(await secureStore.getItemAsync(FAILED_ATTEMPTS_KEY)).toBeNull();
  expect((await SecureCryptoService.getLockStatus()).locked).toBe(false);
});
