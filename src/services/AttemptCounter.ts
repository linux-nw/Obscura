/**
 * Parse the persisted failed-attempt counter. A missing value is 0; a PRESENT but corrupt
 * value (non-numeric, negative, fractional, absurd) is tampering and must not reset the count
 * to zero — it is treated as one-below-max so the next failure trips lockout/wipe.
 */
export function parseAttemptCounter(raw: string | null | undefined, maxAttempts: number): number {
  if (raw === null || raw === undefined || raw === '') return 0;
  if (!/^\d{1,6}$/.test(raw)) return Math.max(0, maxAttempts - 1);
  return parseInt(raw, 10);
}
