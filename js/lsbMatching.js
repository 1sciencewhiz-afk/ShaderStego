// LSB matching (±1 embedding): instead of directly overwriting a channel's
// low bits (LSB replacement), nudge the channel value up or down by the
// smallest amount that makes its low bits equal the target pattern.
//
// Plain LSB replacement creates a specific, well-known statistical artifact:
// it only ever turns an even value into itself-or-odd-plus-one, so values end
// up "paired" (2k stays 2k or becomes 2k+1, never 2k-1) — this is exactly
// what the classic chi-square steganalysis attack tests for. LSB matching
// breaks that pairing by choosing the direction (+1 or -1) at random
// whenever either direction reaches the target equally well, so a changed
// pixel is no more likely to have increased than decreased.
//
// This generalizes past 1-bit LSB matching to the 2-bit case (a "high
// detail" pixel's blue channel LSB and LSB+1 together): the target is a
// value's bottom `numBits` bits, and we pick whichever of the two shifts
// congruent to the required change (mod 2^numBits) has the smaller
// magnitude, breaking ties randomly.

/**
 * Return a new channel value in [0, 255] whose low `numBits` bits equal
 * `targetBits`, changing `value` by the smallest possible amount. When two
 * shifts of equal magnitude both work (e.g. +1 vs -1 for a 1-bit target, or
 * +2 vs -2 for a 2-bit target), `preferPositive` picks which one — pass a
 * fresh random boolean per call so the direction isn't predictable.
 *
 * @param {number} value - current channel value, 0-255
 * @param {number} targetBits - desired low bits, 0..(2^numBits - 1)
 * @param {number} numBits - 1 or 2
 * @param {boolean} preferPositive - tie-break direction for equal-magnitude shifts
 * @returns {number} new channel value, 0-255, with (value & ((1<<numBits)-1)) === targetBits
 */
export function matchValueToBits(value, targetBits, numBits, preferPositive) {
  const period = 1 << numBits;
  const current = value & (period - 1);
  if (current === targetBits) return value;

  // `base` is the smallest non-negative shift that reaches the target;
  // `base - period` is its negative-direction counterpart. Exactly one of
  // the two (or, on a tie, whichever `preferPositive` picks) is used.
  const base = (((targetBits - current) % period) + period) % period;
  const altShift = base - period;

  let candidates;
  if (Math.abs(base) < Math.abs(altShift)) candidates = [base, altShift];
  else if (Math.abs(base) > Math.abs(altShift)) candidates = [altShift, base];
  else candidates = preferPositive ? [base, altShift] : [altShift, base];

  for (const shift of candidates) {
    const candidate = value + shift;
    if (candidate >= 0 && candidate <= 255) return candidate;
  }

  // Both directions would leave [0, 255] — only possible right at the
  // extremes (e.g. value 0 or 1 needing a -2 shift). Clamp best-effort;
  // still guaranteed correct since `value` is always within `period` of a
  // boundary in that case, so the in-range candidate above already fired
  // for any real target/period combination this module is used with.
  return Math.min(255, Math.max(0, value + base));
}

/** Extract the low `numBits` bits currently stored in `value`. */
export function readBits(value, numBits) {
  return value & ((1 << numBits) - 1);
}
