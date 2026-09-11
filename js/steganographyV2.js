// V2 adaptive steganography: orchestrates the variance cost map
// (complexity.js), passphrase-seeded permutation (prng.js), and LSB
// matching (lsbMatching.js) around the same AES-GCM(+deflate) payload
// crypto.js already provides.
//
// Layout inside the image:
//   1. A "header region" — the first N pixels in raster order — holds the
//      fixed header fields via plain sequential blue-channel LSB matching.
//      This must be readable without knowing anything else about the
//      image, so it never depends on variance analysis or the
//      passphrase-derived permutation.
//   2. The ciphertext is embedded into the blue channel of every pixel the
//      variance cost map allocates capacity to — outside the header
//      region — in an order scattered by a Fisher-Yates shuffle seeded
//      from the passphrase and salt. Without the correct passphrase, the
//      scatter order (and hence which bits are the payload) is
//      unrecoverable even if the variance map itself is re-derived.
//
// Every write (header and payload alike) goes through LSB matching
// (±1 embedding) rather than direct bit replacement: a pixel whose low
// bits already match the target is left untouched, and one that doesn't
// is nudged up or down by the smallest amount that fixes it, picking the
// direction at random on ties. Direct bit replacement always turns an even
// channel value into itself-or-odd+1, never odd-1 — a asymmetry the classic
// chi-square steganalysis attack specifically tests for. LSB matching
// removes that asymmetry.
//
// A 2-bit ("high detail") pixel's two bits are always written and read
// together as a single 2-bit target, not as two independent bit slots:
// LSB matching can carry a value across a bit boundary (e.g. 0b011 -> 0b100
// to flip just the low bit), so writing a pixel's two bits at unrelated
// times during the scatter could let a later write clobber an earlier one.
// Capacity is therefore scattered per *pixel*, each contributing 1 or 2
// bits of payload consumed atomically.
//
// No magic bytes: a literal ASCII signature at a fixed, fully predictable
// location is trivial for a signature-scanning steganalysis tool to flag,
// independent of the passphrase — see steganography.js (V1) for the same
// reasoning. Header validity is instead a bounds/plausibility check on the
// fields themselves (window radius, percentiles, declared length), and the
// real gate is AES-GCM's authentication tag: it either verifies or it
// doesn't, so "wrong passphrase" and "not a stego image" look the same.
//
// Header fields (big-endian):
//   [0:16]  Salt (16 bytes)
//   [16:28] IV (12 bytes)
//   [28:29] Variance window radius in pixels (1 byte)
//   [29:30] Low variance percentile (1 byte, 0-100)
//   [30:31] High variance percentile (1 byte, 0-100)
//   [31:35] Ciphertext length in bytes (uint32)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';
import { computeReservedPixelCount, computeVarianceMap, classifyTiers } from './complexity.js';
import { deriveSeed, shuffleWithSeed } from './prng.js';
import { matchValueToBits, readBits } from './lsbMatching.js';

const FIXED_HEADER_SIZE = SALT_LENGTH + IV_LENGTH + 1 + 1 + 1 + 4; // 35

const BLUE_OFFSET = 2;

// Below roughly this many pixels per side, a progressive chi-square scan
// gets too few samples per histogram bin to be a stable statistic — the
// instability is a property of the *detector* reading any channel of a
// small image, not of what (if anything) was embedded into it (confirmed
// empirically: even a completely unembedded carrier this small can read
// as suspicious purely from sampling noise). V1 (steganography.js) uses a
// 320px floor, but that was verified against carriers it generates
// itself, which have more varied local texture than a plain low-frequency
// carrier can. Since V2 also accepts arbitrary user-uploaded carriers —
// including flat or smoothly-varying images that give this noise mode
// more room — 512px (matching this app's own procedural default) is the
// smallest floor that tested reliably clean here.
const MIN_SIDE = 512;

// Even with LSB matching removing the classic even/odd replacement
// asymmetry, saturating a large fraction of the variance-selected "high
// detail" pixels still measurably disturbs the blue channel's value
// distribution — verified empirically: touching a payload near the raw
// tier capacity (>~75-80%) on an otherwise-clean 512x512 carrier reads as
// suspicious, while the same carrier stays clean well under that. Unlike
// V1 (which controls its own generated carrier size and can dilute touch
// density by inflating it), V2's carrier is frequently user-supplied, so
// the margin here is enforced as a hard cap on usable capacity rather
// than by resizing anything: at most 1/CAPACITY_MARGIN of the
// variance-identified capacity may actually be used per embed.
const CAPACITY_MARGIN = 4;

function randomBool() {
  return Math.random() < 0.5;
}

function bytesToBits(bytes) {
  const bits = new Array(bytes.length * 8);
  let k = 0;
  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 7; bit >= 0; bit--) {
      bits[k++] = (bytes[i] >> bit) & 1;
    }
  }
  return bits;
}

function bitsToBytes(bits) {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      out[i >> 3] |= 0x80 >> (i & 7);
    }
  }
  return out;
}

/** Write `bytes` one bit per pixel (blue channel) via LSB matching, starting at pixel 0. */
function writeHeaderBytes(data, bytes) {
  const bits = bytesToBits(bytes);
  for (let i = 0; i < bits.length; i++) {
    const byteIdx = i * 4 + BLUE_OFFSET;
    data[byteIdx] = matchValueToBits(data[byteIdx], bits[i], 1, randomBool());
  }
}

function readHeaderBytes(data, numBytes) {
  const numBits = numBytes * 8;
  const bits = new Array(numBits);
  for (let i = 0; i < numBits; i++) {
    const byteIdx = i * 4 + BLUE_OFFSET;
    bits[i] = readBits(data[byteIdx], 1);
  }
  return bitsToBytes(bits);
}

function buildFixedHeader(salt, iv, windowRadius, lowPercentile, highPercentile, ciphertextLength) {
  const header = new Uint8Array(FIXED_HEADER_SIZE);
  header.set(salt, 0);
  header.set(iv, SALT_LENGTH);

  let offset = SALT_LENGTH + IV_LENGTH;
  header[offset] = windowRadius;
  header[offset + 1] = lowPercentile;
  header[offset + 2] = highPercentile;
  offset += 3;

  new DataView(header.buffer).setUint32(offset, ciphertextLength, false);

  return header;
}

/** Generic message for any header that doesn't look plausible — deliberately not more specific. */
const NO_DATA_ERROR = 'No adaptive hidden data found in this image, or the file is corrupted.';

function parseFixedHeader(bytes) {
  const salt = bytes.slice(0, SALT_LENGTH);
  const iv = bytes.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);

  let offset = SALT_LENGTH + IV_LENGTH;
  const windowRadius = bytes[offset];
  const lowPercentile = bytes[offset + 1];
  const highPercentile = bytes[offset + 2];
  offset += 3;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ciphertextLength = view.getUint32(offset, false);

  // Plausibility bounds in place of a magic-byte signature: these are the
  // only values this app ever writes, so anything outside them means this
  // isn't (or is no longer) a valid adaptive stego image.
  if (
    (windowRadius !== 1 && windowRadius !== 2) ||
    lowPercentile > 100 ||
    highPercentile > 100 ||
    lowPercentile > highPercentile
  ) {
    throw new Error(NO_DATA_ERROR);
  }

  return { salt, iv, windowRadius, lowPercentile, highPercentile, ciphertextLength };
}

/** Ordered (pre-shuffle) list of pixel indices with capacity (tier >= 1), in raster order. */
function buildPixelSlots(tiers) {
  const slots = [];
  for (let p = 0; p < tiers.length; p++) {
    if (tiers[p] >= 1) slots.push(p);
  }
  return slots;
}

/**
 * Run the expensive part of carrier analysis (local variance) once for a
 * given carrier + window radius. The result can be re-used across many
 * threshold changes via `buildAnalysis` below, so a UI slider doesn't
 * re-run the variance pass on every tick.
 */
export function scoreCarrier(imageData, windowRadius) {
  const { width, height } = imageData;
  const reservedPixelCount = computeReservedPixelCount(width, height, FIXED_HEADER_SIZE);
  const { variance } = computeVarianceMap(imageData, windowRadius);
  return { variance, width, height, windowRadius, reservedPixelCount };
}

/**
 * Cheaply derive the tier map, capacity, and stats for a pair of
 * percentile thresholds from a pre-computed `scoreCarrier` result. Used to
 * drive the Complexity Visualizer and Capacity Meter in the UI.
 */
export function buildAnalysis(scored, lowPercentile, highPercentile) {
  const { variance, width, height, windowRadius, reservedPixelCount } = scored;
  const { tiers, lowThreshold, highThreshold, tierCounts } = classifyTiers(
    variance,
    width,
    height,
    reservedPixelCount,
    lowPercentile,
    highPercentile
  );

  const capacityBits = tierCounts[1] * 1 + tierCounts[2] * 2;
  const sequentialCapacityBits = width * height * 3; // reference: plain 1-bit R/G/B LSB
  // The capacity a payload may actually use (see CAPACITY_MARGIN above) —
  // distinct from capacityBits, which is the raw, undiluted tier-map total
  // and is still reported for the visualizer/meter's "theoretical" figures.
  const safeCapacityBits = Math.floor(capacityBits / CAPACITY_MARGIN);

  return {
    width,
    height,
    windowRadius,
    reservedPixelCount,
    lowPercentile,
    highPercentile,
    lowThreshold,
    highThreshold,
    tiers,
    tierCounts,
    totalPixels: width * height,
    capacityBits,
    safeCapacityBits,
    sequentialCapacityBits,
  };
}

/** Convenience: score + build analysis in one call (used by tests / one-off calls). */
export function analyzeCarrier(imageData, windowRadius, lowPercentile, highPercentile) {
  return buildAnalysis(scoreCarrier(imageData, windowRadius), lowPercentile, highPercentile);
}

/**
 * Embed `ciphertext` (already compressed + AES-GCM encrypted) into
 * `imageData` in place, using a previously computed `analysis` (from
 * buildAnalysis/analyzeCarrier) so the tier map actually embedded matches
 * whatever the UI last showed the user.
 */
export async function embedAdaptive(imageData, salt, iv, ciphertext, passphrase, analysis) {
  const { width, height, windowRadius, lowPercentile, highPercentile, tiers, capacityBits, safeCapacityBits } =
    analysis;

  if (width < MIN_SIDE || height < MIN_SIDE) {
    throw new Error(
      `Carrier image is ${width}x${height}, below the ${MIN_SIDE}x${MIN_SIDE} minimum this app enforces — ` +
        `smaller images give a steganalysis chi-square scan too few samples per histogram bin to be reliable, ` +
        `which can flag even a hidden payload as suspicious purely from that noise. Use a larger carrier.`
    );
  }

  const payloadBits = ciphertext.length * 8;
  if (payloadBits > safeCapacityBits) {
    throw new Error(
      `Payload needs ${payloadBits} bits but only ${safeCapacityBits} bits can safely be used ` +
        `(of ${capacityBits} bits identified) at the current variance thresholds — using more risks a ` +
        `detectable statistical signature. Lower the thresholds, use a larger/more textured image, or a smaller file.`
    );
  }

  const fixedHeader = buildFixedHeader(salt, iv, windowRadius, lowPercentile, highPercentile, ciphertext.length);

  const data = imageData.data;
  writeHeaderBytes(data, fixedHeader);

  const pixelSlots = buildPixelSlots(tiers);
  const seed = await deriveSeed(passphrase, salt);
  shuffleWithSeed(pixelSlots, seed);

  const bits = bytesToBits(ciphertext);
  let bitPos = 0;
  for (let i = 0; i < pixelSlots.length && bitPos < bits.length; i++) {
    const p = pixelSlots[i];
    const numBits = tiers[p]; // 1 or 2

    let target = 0;
    for (let b = 0; b < numBits; b++) {
      // The last pixel touched may need fewer real bits than its tier
      // allows; pad the remainder with a random bit so the write is still
      // a single atomic numBits-wide match. The decoder stops reading
      // once it has the exact ciphertext length, so padding is never seen.
      const bit = bitPos < bits.length ? bits[bitPos] : Math.random() < 0.5 ? 1 : 0;
      target = (target << 1) | bit;
      bitPos++;
    }

    const byteIdx = p * 4 + BLUE_OFFSET;
    data[byteIdx] = matchValueToBits(data[byteIdx], target, numBits, randomBool());
  }

  return analysis;
}

/**
 * Extract and decrypt-ready material from a stego image produced by
 * embedAdaptive. Returns { salt, iv, ciphertext, tiers, tierCounts,
 * reservedPixelCount, width, height } — the caller decrypts+decompresses
 * ciphertext with crypto.js.
 */
export async function extractAdaptive(imageData, passphrase) {
  const data = imageData.data;
  const { width, height } = imageData;
  const totalPixels = width * height;

  if (totalPixels < FIXED_HEADER_SIZE * 8) {
    throw new Error('Image is too small to contain an adaptive header.');
  }

  const fixedHeaderBytes = readHeaderBytes(data, FIXED_HEADER_SIZE);
  const { salt, iv, windowRadius, lowPercentile, highPercentile, ciphertextLength } =
    parseFixedHeader(fixedHeaderBytes);

  const reservedPixelCount = computeReservedPixelCount(width, height, FIXED_HEADER_SIZE);
  const { variance } = computeVarianceMap(imageData, windowRadius);
  const { tiers, tierCounts } = classifyTiers(
    variance,
    width,
    height,
    reservedPixelCount,
    lowPercentile,
    highPercentile
  );

  const pixelSlots = buildPixelSlots(tiers);
  const seed = await deriveSeed(passphrase, salt);
  shuffleWithSeed(pixelSlots, seed);

  const neededBits = ciphertextLength * 8;
  const bits = [];
  for (let i = 0; i < pixelSlots.length && bits.length < neededBits; i++) {
    const p = pixelSlots[i];
    const numBits = tiers[p];
    const byteIdx = p * 4 + BLUE_OFFSET;
    const value = readBits(data[byteIdx], numBits);

    for (let b = numBits - 1; b >= 0 && bits.length < neededBits; b--) {
      bits.push((value >> b) & 1);
    }
  }

  if (bits.length < neededBits) {
    throw new Error('Hidden payload appears truncated or corrupted.');
  }
  const ciphertext = bitsToBytes(bits);

  return { salt, iv, ciphertext, tiers, tierCounts, reservedPixelCount, width, height };
}
