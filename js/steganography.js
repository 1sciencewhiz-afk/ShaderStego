// LSB steganography: packet framing and bit-level embed/extract over RGBA image data.
// Only the R, G, B channel LSBs are used (see CHANNELS_PER_PIXEL below); alpha
// is left untouched to avoid premultiplied-alpha rounding on redraw.
//
// Packet layout (all multi-byte fields big-endian):
//   [0:4]   Magic bytes 'STEG'
//   [4:8]   uint32 ciphertext length (bytes)
//   [8:24]  Salt (16 bytes)
//   [24:36] IV (12 bytes)
//   [36:]   Ciphertext (variable length)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';

const MAGIC = [0x53, 0x54, 0x45, 0x47]; // 'S','T','E','G'
const LENGTH_FIELD_SIZE = 4;
export const HEADER_SIZE = MAGIC.length + LENGTH_FIELD_SIZE + SALT_LENGTH + IV_LENGTH; // 36 bytes

/**
 * Build the full byte packet (header + ciphertext) to be hidden in the image.
 */
export function buildPacket(salt, iv, ciphertext) {
  const packet = new Uint8Array(HEADER_SIZE + ciphertext.length);
  packet.set(MAGIC, 0);

  const view = new DataView(packet.buffer);
  view.setUint32(MAGIC.length, ciphertext.length, false);

  packet.set(salt, MAGIC.length + LENGTH_FIELD_SIZE);
  packet.set(iv, MAGIC.length + LENGTH_FIELD_SIZE + SALT_LENGTH);
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
      data[dataIndex] = (data[dataIndex] & 0xfe) | bitValue;
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
      byte = (byte << 1) | (data[channelDataIndex(bitIndex)] & 1);
      bitIndex++;
    }
    out[i] = byte;
  }
  return out;
}

/**
 * Extract and validate the hidden packet from `imageData`.
 * Returns { salt, iv, ciphertext }. Throws if no valid packet is found.
 */
export function extractPacket(imageData) {
  const data = imageData.data;
  const capacityBits = Math.floor(data.length / 4) * CHANNELS_PER_PIXEL;

  if (capacityBits < HEADER_SIZE * 8) {
    throw new Error('Image is too small to contain a hidden payload.');
  }

  const magicBytes = extractBytes(data, 0, MAGIC.length);
  const magicOk = MAGIC.every((byte, i) => magicBytes[i] === byte);
  if (!magicOk) {
    throw new Error('No hidden data found in this image (magic bytes mismatch).');
  }

  let offsetBytes = MAGIC.length;
  const lengthBytes = extractBytes(data, offsetBytes * 8, LENGTH_FIELD_SIZE);
  const ciphertextLength = new DataView(lengthBytes.buffer).getUint32(0, false);
  offsetBytes += LENGTH_FIELD_SIZE;

  const salt = extractBytes(data, offsetBytes * 8, SALT_LENGTH);
  offsetBytes += SALT_LENGTH;

  const iv = extractBytes(data, offsetBytes * 8, IV_LENGTH);
  offsetBytes += IV_LENGTH;

  const totalBitsNeeded = (offsetBytes + ciphertextLength) * 8;
  if (totalBitsNeeded > capacityBits) {
    throw new Error('Hidden payload appears truncated or corrupted.');
  }

  const ciphertext = extractBytes(data, offsetBytes * 8, ciphertextLength);

  return { salt, iv, ciphertext };
}
