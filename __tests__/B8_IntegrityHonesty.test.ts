/**
 * B8_IntegrityHonesty.test.ts
 *
 * B.8 (AUDIT_2026-09-15-v2.md): checkAppFiles()/checkDebugger()/checkIntegrityService() in
 * IntegrityService.ts are hardcoded-true placeholders, not real checks — only checkSignature()
 * does genuine work. checkIntegrity()'s aggregate score blends all four together, so a future
 * "checksPassed/4" UI could misread this as four independent signals.
 *
 * This locks in the honesty property as a regression guard: the three stub checks return
 * true unconditionally, independent of the one real signal — so nobody can mistake the
 * aggregate for four real, independent checks.
 */

jest.mock('../src/native/IntegrityNative', () => ({
  verifyPinnedSignature: jest.fn(),
}));

import { IntegrityService } from '../src/services/IntegrityService';
import { verifyPinnedSignature } from '../src/native/IntegrityNative';

const mockedVerify = verifyPinnedSignature as jest.Mock;

describe('B.8: only the signature check is real — the other three are unconditional stubs', () => {
  test('the 3 stub checks stay true even when the one real check fails', async () => {
    mockedVerify.mockResolvedValue('invalid'); // real tamper signal

    const stubResults = await Promise.all([
      (IntegrityService as any).checkAppFiles(),
      (IntegrityService as any).checkDebugger(),
      (IntegrityService as any).checkIntegrityService(),
    ]);
    expect(stubResults).toEqual([true, true, true]);

    const status = await IntegrityService.checkIntegrity();
    // Only the real check (signature) reflects the 'invalid' verdict — 3/4 pass regardless.
    expect(status.checksPassed).toBe(3);
    expect(status.checksFailed).toBe(1);
    expect(status.isIntact).toBe(false);
  });

  test('the 3 stub checks stay true when the real check passes too (the misleading 4/4 case)', async () => {
    mockedVerify.mockResolvedValue('valid');

    const status = await IntegrityService.checkIntegrity();
    expect(status.checksPassed).toBe(4);
    expect(status.checksFailed).toBe(0);
    expect(status.isIntact).toBe(true);

    // The honesty property: of those 4, only 1 (signature) is real — the other 3 pass
    // unconditionally regardless of verdict, as proven above. A "4/4" reading of this
    // status without that context is exactly what B.8 flags as misleading.
  });
});
