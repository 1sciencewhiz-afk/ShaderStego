// LSB steganography: packet framing and bit-level embed/extract over RGBA image data.
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
// Packet layout (all multi-byte fields big-endian):
//   [0:4]  uint32 ciphertext length (bytes)
//   [4:20] Salt (16 bytes)
//   [20:32] IV (12 bytes)
//   [32:]  Ciphertext (variable length)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';
import { matchValueToBits, readBits } from './lsbMatching.js';

const LENGTH_FIELD_SIZE = 4;
export const HEADER_SIZE = LENGTH_FIELD_SIZE + SALT_LENGTH + IV_LENGTH; // 32 bytes

/**
 * Build the full byte packet (header + ciphertext) to be hidden in the image.
 */
export function buildPacket(salt, iv, ciphertext) {
  const packet = new Uint8Array(HEADER_SIZE + ciphertext.length);

  const view = new DataView(packet.buffer);
  view.setUint32(0, ciphertext.length, false);

  packet.set(salt, LENGTH_FIELD_SIZE);
  packet.set(iv, LENGTH_FIELD_SIZE + SALT_LENGTH);
  packet.set(ciphertext, HEADER_SIZE);

  return packet;
}

// Bits are packed only into the R, G, B channels (3 per pixel). The alpha
// channel is left untouched at 255: browsers premultiply RGB by alpha when
// compositing a drawn image, so an alpha LSB flip (255 -> 254) silently
// rescales the RGB channels on redraw and corrupts the hidden bits.
const CHANNELS_PER_PIXEL = 3;

function channelDataIndex(bitIndex) {
  const pixel = Math.floor(bitIndex / CHANNELS_PER_PIXEL);
  const channel = bitIndex % CHANNELS_PER_PIXEL; // 0=R, 1=G, 2=B
  return pixel * 4 + channel;
}

function randomBool() {
  return Math.random() < 0.5;
}

/**
 * Choose carrier canvas dimensions large enough to hold `byteLength` bytes,
 * embedding one bit per usable (R/G/B) channel byte.
 */
export function computeCanvasDimensions(byteLength, minSide = 64) {
  const bitsNeeded = byteLength * 8;
  const pixelsNeeded = Math.ceil(bitsNeeded / CHANNELS_PER_PIXEL);
  const side = Math.max(minSide, Math.ceil(Math.sqrt(pixelsNeeded)));
  const width = side;
  const height = Math.max(minSide, Math.ceil(pixelsNeeded / width));
  return { width, height };
}

/**
 * Embed `packet` bytes into the LSB of each R/G/B channel byte of `imageData`, in place.
 */
export function embedPacket(imageData, packet) {
  const data = imageData.data;
  const bitsNeeded = packet.length * 8;
  const capacityBits = Math.floor(data.length / 4) * CHANNELS_PER_PIXEL;
  if (bitsNeeded > capacityBits) {
    throw new Error('Carrier image is too small to hold this payload.');
  }

  let bitIndex = 0;
  for (let i = 0; i < packet.length; i++) {
    const byte = packet[i];
    for (let bit = 7; bit >= 0; bit--) {
      const bitValue = (byte >> bit) & 1;
      const dataIndex = channelDataIndex(bitIndex);
      data[dataIndex] = matchValueToBits(data[dataIndex], bitValue, 1, randomBool());
      bitIndex++;
    }
  }
}

function extractBytes(data, startBitIndex, numBytes) {
  const out = new Uint8Array(numBytes);
  let bitIndex = startBitIndex;
  for (let i = 0; i < numBytes; i++) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit++) {
      byte = (byte << 1) | readBits(data[channelDataIndex(bitIndex)], 1);
      bitIndex++;
    }
    out[i] = byte;
  }
  return out;
}

/**
 * Extract the hidden packet from `imageData`. Returns { salt, iv,
 * ciphertext } based purely on the declared length field and a capacity
 * bounds check — there's no signature to validate against, so a wrong
 * passphrase and "not a stego image" both surface identically, only once
 * AES-GCM decryption is attempted by the caller.
 */
export function extractPacket(imageData) {
  const data = imageData.data;
  const capacityBits = Math.floor(data.length / 4) * CHANNELS_PER_PIXEL;

  if (capacityBits < HEADER_SIZE * 8) {
    throw new Error('Image is too small to contain a hidden payload.');
  }

  let offsetBytes = 0;
  const lengthBytes = extractBytes(data, offsetBytes * 8, LENGTH_FIELD_SIZE);
  const ciphertextLength = new DataView(lengthBytes.buffer).getUint32(0, false);
  offsetBytes += LENGTH_FIELD_SIZE;

  const salt = extractBytes(data, offsetBytes * 8, SALT_LENGTH);
  offsetBytes += SALT_LENGTH;

  const iv = extractBytes(data, offsetBytes * 8, IV_LENGTH);
  offsetBytes += IV_LENGTH;

  const totalBitsNeeded = (offsetBytes + ciphertextLength) * 8;
  if (totalBitsNeeded > capacityBits) {
    throw new Error('No hidden data found in this image, or the file is corrupted.');
  }

  const ciphertext = extractBytes(data, offsetBytes * 8, ciphertextLength);

  return { salt, iv, ciphertext };
}
