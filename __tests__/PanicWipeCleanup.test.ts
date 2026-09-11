/**
 * PanicWipeCleanup.test.ts
 *
 * Regression found by an independent review of this session's fixes: making
 * SecureDeleteService.secureWipeAll() fail closed (throw on incomplete deletion) broke
 * PanicService.wipeAllData(), because secureWipeAll() wasn't wrapped in its own
 * try/catch - a throw there skipped clearPanicPin() and destroyDecoyVault() entirely,
 * leaving the panic PIN configured and the decoy vault's data recoverable after a
 * panic wipe that hit a real file-deletion failure. Fixed by giving secureWipeAll()
 * its own try/catch (matching the pattern already used for the two steps after it),
 * so a vault-wipe failure can never skip the independent panic-PIN/decoy-vault cleanup.
 */

jest.mock('../src/services/SecureDeleteService', () => ({
  SecureDeleteService: {
    secureWipeAll: jest.fn(),
  },
}));
jest.mock('../src/services/DecoyVaultService', () => ({
  DecoyVaultService: {
    destroyDecoyVault: jest.fn(async () => {}),
  },
}));

const secureStore = require('../__mocks__/expo-secure-store');
const { SecureCryptoService } = require('../src/services/CryptoService');
const { SecureDeleteService } = require('../src/services/SecureDeleteService');
const { DecoyVaultService } = require('../src/services/DecoyVaultService');
const { PanicService } = require('../src/services/PanicService');

beforeEach(() => {
  secureStore._reset();
  jest.clearAllMocks();
  jest.spyOn(SecureCryptoService, 'deleteEncryptionKey').mockResolvedValue(undefined);
  jest.spyOn(SecureCryptoService, 'deletePinData').mockResolvedValue(undefined);
  jest.spyOn(SecureCryptoService, 'setAppInitialized').mockResolvedValue(undefined);
});

describe('PanicService panic-wipe: secureWipeAll failure must not skip cleanup', () => {
  test('secureWipeAll() rejects → clearPanicPin/destroyDecoyVault/setAppInitialized still run', async () => {
    await PanicService.setPanicPin('somepanicpin1');
    await PanicService.setTriggerAction('wipe');

    SecureDeleteService.secureWipeAll.mockRejectedValue(new Error('disk error mid-wipe'));

    await PanicService.triggerPanicAction();

    expect(SecureDeleteService.secureWipeAll).toHaveBeenCalled();
    expect(DecoyVaultService.destroyDecoyVault).toHaveBeenCalled();
    expect(SecureCryptoService.setAppInitialized).toHaveBeenCalledWith(false);

    // clearPanicPin itself isn't mocked (real implementation) - verify its actual effect:
    // the panic PIN hash is gone from SecureStore despite secureWipeAll having failed.
    expect(await secureStore.getItemAsync('filevault_panic_pin_hash')).toBeNull();
  }, 60000);

  test('secureWipeAll() succeeds → same cleanup still runs (no regression on the happy path)', async () => {
    await PanicService.setPanicPin('somepanicpin1');
    await PanicService.setTriggerAction('wipe');
    SecureDeleteService.secureWipeAll.mockResolvedValue(undefined);

    await PanicService.triggerPanicAction();

    expect(DecoyVaultService.destroyDecoyVault).toHaveBeenCalled();
    expect(SecureCryptoService.setAppInitialized).toHaveBeenCalledWith(false);
    expect(await secureStore.getItemAsync('filevault_panic_pin_hash')).toBeNull();
  }, 60000);
});
