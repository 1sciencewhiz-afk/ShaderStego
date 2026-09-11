// LSB steganography: header framing and bit-level embed/extract over RGBA image data.
// Only the R, G, B channel LSBs are used (see CHANNELS_PER_PIXEL below); alpha
// is left untouched to avoid premultiplied-alpha rounding on redraw.
//
// No magic bytes: an earlier version of this format led with a literal
// ASCII 'STEG' signature at a fixed, fully predictable location (pixel 0
// onward) — trivial for a signature-scanning steganalysis tool to flag,
// independent of the passphrase. Validity is now established the only way
// that doesn't leak anything: AES-GCM's own authentication tag either
// verifies or it doesn't. A bounds check on the declared ciphertext length
// still guards against reading garbage off a non-stego image; beyond that,
// "wrong passphrase" and "not a stego image at all" are deliberately
// indistinguishable to the caller.
//
// Every bit is written via LSB matching (±1), not direct bit replacement:
// replacement always turns an even channel value into itself-or-odd+1,
// never odd-1, which is exactly the asymmetry the classic chi-square
// steganalysis attack tests for. Each R/G/B channel byte carries at most
// one independently-matched bit, so — unlike the adaptive (V2) scheme's
// 2-bit pixels — there's no carry-coordination concern between slots.
//
// Matching alone isn't enough, though: a progressive/windowed scanner
// doesn't need to detect *how* a bit was written to notice that a
// contiguous block of pixels statistically differs from its surroundings
// — and embedding the whole payload sequentially starting at pixel 0 is
// exactly that block. So only the small fixed header (length, salt, IV —
// needed to derive the passphrase-based scatter seed in the first place)
// is written sequentially; the ciphertext itself is scattered across the
// *entire* remaining canvas via the same passphrase/salt-seeded
// Fisher-Yates shuffle the adaptive (V2) scheme uses, so touched pixels
// are spread uniformly across the whole image rather than clustered at
// the start.
//
// Header layout (sequential, fixed location, all multi-byte fields
// big-endian):
//   [0:4]   uint32 ciphertext length (bytes)
//   [4:20]  Salt (16 bytes)
//   [20:32] IV (12 bytes)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';
import { matchValueToBits, readBits } from './lsbMatching.js';
import { deriveSeed, shuffleWithSeed } from './prng.js';

const LENGTH_FIELD_SIZE = 4;
export const HEADER_SIZE = LENGTH_FIELD_SIZE + SALT_LENGTH + IV_LENGTH; // 32 bytes

/** Build the fixed header (length + salt + IV) written sequentially ahead of the scattered ciphertext. */
export function buildHeader(salt, iv, ciphertextLength) {
  const header = new Uint8Array(HEADER_SIZE);

  const view = new DataView(header.buffer);
  view.setUint32(0, ciphertextLength, false);

  header.set(salt, LENGTH_FIELD_SIZE);
  header.set(iv, LENGTH_FIELD_SIZE + SALT_LENGTH);

  return header;
}

// Bits are packed only into the R, G, B channels (3 per pixel). The alpha
// channel is left untouched at 255: browsers premultiply RGB by alpha when
// compositing a drawn image, so an alpha LSB flip (255 -> 254) silently
// rescales the RGB channels on redraw and corrupts the hidden bits.
const CHANNELS_PER_PIXEL = 3;

/** Map a sequential (header) bit index to its R/G/B channel byte offset in the pixel buffer. */
function channelDataIndex(bitIndex) {
  const pixel = Math.floor(bitIndex / CHANNELS_PER_PIXEL);
  const channel = bitIndex % CHANNELS_PER_PIXEL; // 0=R, 1=G, 2=B
  return pixel * 4 + channel;
}

function randomBool() {
  return Math.random() < 0.5;
}

// Even with LSB matching, touching *every* available channel slot still
// leaves a measurable Westfeld pairs-of-values chi-square signal: a
// mismatched pixel moves to either neighboring value with equal
// probability, so roughly a quarter of a pair's "wrong-parity" population
// leaks into the *adjacent* pair rather than staying put — under full
// touch density this shrinks each pair's natural (n_2k - n_2k+1) count
// difference to about 25% of a clean image's, not to zero, but still
// squarely inside detectable territory once it feeds back into the
// difference-squared chi-square statistic. Sizing the carrier with real
// slack — so most of any progressive window is genuinely untouched —
// dilutes that residual far below it: touching only ~1/CAPACITY_MARGIN of
// available slots means roughly that same fraction of the aggregate
// histogram carries any artifact at all, the rest being pristine original
// data. CAPACITY_MARGIN=8 targets ~12.5% touch density, a comfortable
// margin under the ~20% ceiling a back-of-envelope pairs-of-values
// analysis suggests keeps most of a natural image's pair inequality intact.
const CAPACITY_MARGIN = 8;

// Below roughly this many pixels per side, a progressive chi-square scan
// gets too few samples per histogram bin to be a stable statistic —
// verified against a real detector's own algorithm: an *unembedded*
// carrier this small could already read as suspicious on some channel
// purely from that sampling noise, regardless of anything we embed.
const MIN_SIDE = 320;

/**
 * Choose carrier canvas dimensions large enough to hold `byteLength` bytes
 * (header + ciphertext combined) at a low touch density (see
 * CAPACITY_MARGIN above) and past MIN_SIDE — one bit per usable (R/G/B)
 * channel byte.
 */
export function computeCanvasDimensions(byteLength, minSide = MIN_SIDE) {
  const bitsNeeded = byteLength * 8;
  const pixelsNeeded = Math.ceil((bitsNeeded / CHANNELS_PER_PIXEL) * CAPACITY_MARGIN);
  const side = Math.max(minSide, Math.ceil(Math.sqrt(pixelsNeeded)));
  const width = side;
  const height = Math.max(minSide, Math.ceil(pixelsNeeded / width));
  return { width, height };
}

function writeSequentialBits(data, bits) {
  for (let i = 0; i < bits.length; i++) {
    const idx = channelDataIndex(i);
    data[idx] = matchValueToBits(data[idx], bits[i], 1, randomBool());
  }
}

function readSequentialBits(data, numBits) {
  const bits = new Array(numBits);
  for (let i = 0; i < numBits; i++) {
    bits[i] = readBits(data[channelDataIndex(i)], 1);
  }
  return bits;
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
    if (bits[i]) out[i >> 3] |= 0x80 >> (i & 7);
  }
  return out;
}

/** Ordered (pre-shuffle) list of channel-slot indices available for the scattered ciphertext. */
function buildScatterSlots(totalCapacitySlots, headerSlotCount) {
  const slots = new Array(totalCapacitySlots - headerSlotCount);
  for (let i = 0; i < slots.length; i++) {
    slots[i] = channelDataIndex(headerSlotCount + i);
  }
  return slots;
}

/**
 * Embed `ciphertext` into `imageData` in place: the header (length, salt,
 * IV) is written sequentially at the start, and the ciphertext is
 * scattered across the rest of the canvas using a shuffle seeded from
 * `passphrase` and `salt`, so touched pixels aren't clustered together.
 */
export async function embedPacket(imageData, salt, iv, ciphertext, passphrase) {
  const data = imageData.data;
  const capacitySlots = Math.floor(data.length / 4) * CHANNELS_PER_PIXEL;
  const headerSlots = HEADER_SIZE * 8;
  const neededSlots = headerSlots + ciphertext.length * 8;
  if (neededSlots > capacitySlots) {
    throw new Error('Carrier image is too small to hold this payload.');
  }

  const header = buildHeader(salt, iv, ciphertext.length);
  writeSequentialBits(data, bytesToBits(header));

  const scatterSlots = buildScatterSlots(capacitySlots, headerSlots);
  const seed = await deriveSeed(passphrase, salt);
  shuffleWithSeed(scatterSlots, seed);

  const bits = bytesToBits(ciphertext);
  for (let i = 0; i < bits.length; i++) {
    const idx = scatterSlots[i];
    data[idx] = matchValueToBits(data[idx], bits[i], 1, randomBool());
  }
}

/**
 * Extract the hidden payload from `imageData`. Returns { salt, iv,
 * ciphertext } based purely on the declared length field and a capacity
 * bounds check — there's no signature to validate against, so a wrong
 * passphrase and "not a stego image" both surface identically, only once
 * AES-GCM decryption is attempted by the caller.
 */
export async function extractPacket(imageData, passphrase) {
  const data = imageData.data;
  const capacitySlots = Math.floor(data.length / 4) * CHANNELS_PER_PIXEL;
  const headerSlots = HEADER_SIZE * 8;

  if (capacitySlots < headerSlots) {
    throw new Error('Image is too small to contain a hidden payload.');
  }

  const headerBits = readSequentialBits(data, headerSlots);
  const headerBytes = bitsToBytes(headerBits);

  const ciphertextLength = new DataView(headerBytes.buffer).getUint32(0, false);
  const salt = headerBytes.slice(LENGTH_FIELD_SIZE, LENGTH_FIELD_SIZE + SALT_LENGTH);
  const iv = headerBytes.slice(LENGTH_FIELD_SIZE + SALT_LENGTH, HEADER_SIZE);

  const neededSlots = headerSlots + ciphertextLength * 8;
  if (neededSlots > capacitySlots) {
    throw new Error('No hidden data found in this image, or the file is corrupted.');
  }

  const scatterSlots = buildScatterSlots(capacitySlots, headerSlots);
  const seed = await deriveSeed(passphrase, salt);
  shuffleWithSeed(scatterSlots, seed);

  const neededBits = ciphertextLength * 8;
  const bits = new Array(neededBits);
  for (let i = 0; i < neededBits; i++) {
    bits[i] = readBits(data[scatterSlots[i]], 1);
  }
  const ciphertext = bitsToBytes(bits);

  return { salt, iv, ciphertext };
}
