/**
 * SafeBufferZeroize.test.ts
 *
 * SafeBuffer.zeroize() ran 4 overwrite passes: 0x00, 0xFF, 0x00, then XOR every byte
 * with the constant 0xFF. Since pattern 3 already left the buffer at 0x00, the XOR
 * pass simply flipped it to 0xFF and left it there — a method named zeroize() that
 * actually left the buffer full of 0xFF, the opposite of its contract. (SafeBuffer
 * itself is unused dead code in the app today, but the bug is real regardless.)
 */

import { SafeBuffer, ZeroingArrayBuffer } from '../src/services/MemorySafetyService';

describe('SafeBuffer.zeroize()', () => {
  test('leaves every byte at 0x00, not 0xFF', () => {
    const buf = new SafeBuffer(16);
    buf.write('sensitive-data!!');
    buf.zeroize();

    // read() returns a fresh zero-filled array once zeroized (by design), so inspect
    // the underlying bytes directly to prove the buffer itself was actually zeroed,
    // not just that read() masks it.
    const raw = (buf as any).buffer as Uint8Array;
    expect(Array.from(raw)).toEqual(new Array(16).fill(0));
  });

  test('isZeroized() reports true and read() returns zeros after zeroize()', () => {
    const buf = new SafeBuffer(8);
    buf.write('secretpw');
    buf.zeroize();
    expect(buf.isZeroized()).toBe(true);
    expect(Array.from(buf.read())).toEqual(new Array(8).fill(0));
  });
});

describe('ZeroingArrayBuffer.zeroize() (regression guard - already correct)', () => {
  test('leaves every byte at 0x00', () => {
    const buf = new ZeroingArrayBuffer(8);
    buf.write(new Uint8Array(8).fill(0x42));
    buf.zeroize();
    const raw = new Uint8Array((buf as any).arrayBuffer);
    expect(Array.from(raw)).toEqual(new Array(8).fill(0));
  });
});
