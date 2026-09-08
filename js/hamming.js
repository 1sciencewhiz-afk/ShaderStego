// Matrix (Hamming) coding: a lightweight stand-in for Syndrome-Trellis Codes.
// Embeds 3 message bits into a group of 7 carrier bits by flipping at most
// one bit, minimizing embedding distortion versus plain sequential LSB
// (which flips ~50% of visited bits). This is the classical (7,4) Hamming
// parity-check trick used by F5-style matrix embedding.
//
// For 7 bits b1..b7, the syndrome s = s1 + 2*s2 + 4*s3 where:
//   s1 = b1 ^ b3 ^ b5 ^ b7   (columns whose binary index has bit 0 set)
//   s2 = b2 ^ b3 ^ b6 ^ b7   (bit 1 set)
//   s3 = b4 ^ b5 ^ b6 ^ b7   (bit 2 set)
// Flipping bit b_d toggles the syndrome by exactly d (since column d's
// binary value is d), so to make the syndrome equal a target message m,
// flip the bit at position d = s ^ m (or flip nothing if d is 0).

export const GROUP_SIZE = 7;
export const BITS_PER_GROUP = 3;

function syndrome(bits7) {
  const b = bits7; // 1-indexed access via b[1]..b[7]
  const s1 = b[1] ^ b[3] ^ b[5] ^ b[7];
  const s2 = b[2] ^ b[3] ^ b[6] ^ b[7];
  const s3 = b[4] ^ b[5] ^ b[6] ^ b[7];
  return s1 | (s2 << 1) | (s3 << 2);
}

/**
 * Given 7 carrier bits (array indices 1..7 used, index 0 ignored) and a
 * 3-bit message (0-7), return the index (1-7) to flip, or 0 if no change
 * is needed.
 */
export function findFlipIndex(bits7, message) {
  const s = syndrome(bits7);
  return s ^ message;
}

/** Recover the embedded 3-bit message from 7 carrier bits. */
export function decodeGroup(bits7) {
  return syndrome(bits7);
}

/**
 * Embed a bit array (array of 0/1, MSB-first stream) into a sequence of
 * "slots" using getBit/setBit accessors, via Hamming(7,3) matrix coding.
 *
 * @param {number[]} bitStream - message bits to embed, length must be <= floor(slots.length/7)*3
 * @param {number[]|Uint32Array} slots - opaque slot identifiers, in embedding order
 * @param {(slot:number) => number} getBit - read the current LSB carried by a slot
 * @param {(slot:number, bit:number) => void} setBit - overwrite the LSB carried by a slot
 */
export function embedBitstream(bitStream, slots, getBit, setBit) {
  const groupCount = Math.floor(slots.length / GROUP_SIZE);
  const capacityBits = groupCount * BITS_PER_GROUP;
  if (bitStream.length > capacityBits) {
    throw new Error('Not enough adaptive capacity for this payload.');
  }

  let bitPos = 0;
  for (let g = 0; g < groupCount && bitPos < bitStream.length; g++) {
    const base = g * GROUP_SIZE;
    const bits7 = [0, 0, 0, 0, 0, 0, 0, 0]; // 1-indexed
    for (let k = 0; k < GROUP_SIZE; k++) {
      bits7[k + 1] = getBit(slots[base + k]);
    }

    let message = 0;
    for (let k = 0; k < BITS_PER_GROUP; k++) {
      const bit = bitPos + k < bitStream.length ? bitStream[bitPos + k] : 0;
      message = (message << 1) | bit;
    }

    const flipIndex = findFlipIndex(bits7, message);
    if (flipIndex !== 0) {
      const slot = slots[base + (flipIndex - 1)];
      setBit(slot, bits7[flipIndex] ^ 1);
    }

    bitPos += BITS_PER_GROUP;
  }
}

/**
 * Extract `numBits` message bits (MSB-first) from `slots` using Hamming(7,3)
 * decoding, reading via getBit.
 */
export function extractBitstream(numBits, slots, getBit) {
  const groupsNeeded = Math.ceil(numBits / BITS_PER_GROUP);
  if (groupsNeeded * GROUP_SIZE > slots.length) {
    throw new Error('Not enough data to extract the expected payload.');
  }

  const bits = [];
  for (let g = 0; g < groupsNeeded; g++) {
    const base = g * GROUP_SIZE;
    const bits7 = [0, 0, 0, 0, 0, 0, 0, 0];
    for (let k = 0; k < GROUP_SIZE; k++) {
      bits7[k + 1] = getBit(slots[base + k]);
    }
    const message = decodeGroup(bits7);
    for (let k = BITS_PER_GROUP - 1; k >= 0; k--) {
      bits.push((message >> k) & 1);
    }
  }

  return bits.slice(0, numBits);
}
