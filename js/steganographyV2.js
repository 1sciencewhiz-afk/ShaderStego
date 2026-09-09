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
// Header fields (big-endian):
//   [0:6]   Magic 'STEGV4'
//   [6:22]  Salt (16 bytes)
//   [22:34] IV (12 bytes)
//   [34:35] Variance window radius in pixels (1 byte)
//   [35:36] Low variance percentile (1 byte, 0-100)
//   [36:37] High variance percentile (1 byte, 0-100)
//   [37:41] Ciphertext length in bytes (uint32)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';
import { computeReservedPixelCount, computeVarianceMap, classifyTiers } from './complexity.js';
import { deriveSeed, shuffleWithSeed } from './prng.js';
import { matchValueToBits, readBits } from './lsbMatching.js';

const MAGIC = [0x53, 0x54, 0x45, 0x47, 0x56, 0x34]; // 'STEGV4'
const FIXED_HEADER_SIZE = MAGIC.length + SALT_LENGTH + IV_LENGTH + 1 + 1 + 1 + 4; // 41

const BLUE_OFFSET = 2;

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
  header.set(MAGIC, 0);
  header.set(salt, MAGIC.length);
  header.set(iv, MAGIC.length + SALT_LENGTH);

  let offset = MAGIC.length + SALT_LENGTH + IV_LENGTH;
  header[offset] = windowRadius;
  header[offset + 1] = lowPercentile;
  header[offset + 2] = highPercentile;
  offset += 3;

  new DataView(header.buffer).setUint32(offset, ciphertextLength, false);

  return header;
}

function parseFixedHeader(bytes) {
  const magicOk = MAGIC.every((b, i) => bytes[i] === b);
  if (!magicOk) {
    throw new Error('No adaptive hidden data found in this image (magic bytes mismatch).');
  }
  const salt = bytes.slice(MAGIC.length, MAGIC.length + SALT_LENGTH);
  const iv = bytes.slice(MAGIC.length + SALT_LENGTH, MAGIC.length + SALT_LENGTH + IV_LENGTH);

  let offset = MAGIC.length + SALT_LENGTH + IV_LENGTH;
  const windowRadius = bytes[offset];
  const lowPercentile = bytes[offset + 1];
  const highPercentile = bytes[offset + 2];
  offset += 3;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ciphertextLength = view.getUint32(offset, false);

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
  const { windowRadius, lowPercentile, highPercentile, tiers, capacityBits } = analysis;

  const payloadBits = ciphertext.length * 8;
  if (payloadBits > capacityBits) {
    throw new Error(
      `Payload needs ${payloadBits} bits but only ${capacityBits} bits are available ` +
        `at the current variance thresholds. Lower the thresholds or use a larger/more textured image.`
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
