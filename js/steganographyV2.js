// V2 adaptive steganography: orchestrates complexity masking (complexity.js)
// and Hamming matrix coding (hamming.js) around the same AES-GCM payload
// crypto.js already provides.
//
// Layout inside the image:
//   1. A "header region" — the first N pixels in simple raster order — holds
//      the fixed header fields followed by the packed embed mask, written
//      with plain sequential LSB (1 bit per R/G/B channel). This must be
//      readable without knowing anything else about the image, so it never
//      uses adaptive selection or matrix coding.
//   2. The ciphertext is embedded via Hamming(7,3) matrix coding, but only
//      into channel slots belonging to blocks the embed mask marks as 1.
//      Blocks touched by the header region are always excluded from the
//      mask at encode time, so the two regions never collide.
//
// Header fields (big-endian):
//   [0:6]   Magic 'STEGV2'
//   [6:22]  Salt (16 bytes)
//   [22:34] IV (12 bytes)
//   [34:35] Block size in pixels (1 byte)
//   [35:37] Mask columns (uint16)
//   [37:39] Mask rows (uint16)
//   [39:43] Ciphertext length in bytes (uint32)
//   [43:...] Packed embed mask (ceil(maskCols*maskRows/8) bytes)

import { SALT_LENGTH, IV_LENGTH } from './crypto.js';
import {
  computeReservedBlockRows,
  computeBlockScores,
  buildMask,
  packMaskBits,
  unpackMaskBits,
} from './complexity.js';
import { embedBitstream, extractBitstream } from './hamming.js';

const MAGIC = [0x53, 0x54, 0x45, 0x47, 0x56, 0x32]; // 'STEGV2'
const FIXED_HEADER_SIZE = MAGIC.length + SALT_LENGTH + IV_LENGTH + 1 + 2 + 2 + 4; // 43

function sequentialSlot(index) {
  return Math.floor(index / 3) * 4 + (index % 3);
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

function writeSequentialBytes(data, startSlot, bytes) {
  const bits = bytesToBits(bytes);
  for (let i = 0; i < bits.length; i++) {
    const idx = sequentialSlot(startSlot + i);
    data[idx] = (data[idx] & 0xfe) | bits[i];
  }
}

function readSequentialBytes(data, startSlot, numBytes) {
  const numBits = numBytes * 8;
  const bits = new Array(numBits);
  for (let i = 0; i < numBits; i++) {
    bits[i] = data[sequentialSlot(startSlot + i)] & 1;
  }
  return bitsToBytes(bits);
}

function buildFixedHeader(salt, iv, blockSize, maskCols, maskRows, ciphertextLength) {
  const header = new Uint8Array(FIXED_HEADER_SIZE);
  header.set(MAGIC, 0);
  header.set(salt, MAGIC.length);
  header.set(iv, MAGIC.length + SALT_LENGTH);
  header[MAGIC.length + SALT_LENGTH + IV_LENGTH] = blockSize;

  const view = new DataView(header.buffer);
  const maskColsOffset = MAGIC.length + SALT_LENGTH + IV_LENGTH + 1;
  view.setUint16(maskColsOffset, maskCols, false);
  view.setUint16(maskColsOffset + 2, maskRows, false);
  view.setUint32(maskColsOffset + 4, ciphertextLength, false);

  return header;
}

function parseFixedHeader(bytes) {
  const magicOk = MAGIC.every((b, i) => bytes[i] === b);
  if (!magicOk) {
    throw new Error('No adaptive hidden data found in this image (magic bytes mismatch).');
  }
  const salt = bytes.slice(MAGIC.length, MAGIC.length + SALT_LENGTH);
  const iv = bytes.slice(MAGIC.length + SALT_LENGTH, MAGIC.length + SALT_LENGTH + IV_LENGTH);
  const blockSize = bytes[MAGIC.length + SALT_LENGTH + IV_LENGTH];

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const maskColsOffset = MAGIC.length + SALT_LENGTH + IV_LENGTH + 1;
  const maskCols = view.getUint16(maskColsOffset, false);
  const maskRows = view.getUint16(maskColsOffset + 2, false);
  const ciphertextLength = view.getUint32(maskColsOffset + 4, false);

  return { salt, iv, blockSize, maskCols, maskRows, ciphertextLength };
}

/** Build the flat list of data-array byte indices for blocks marked 1 in mask. */
function buildAdaptiveSlots(mask, maskCols, maskRows, blockSize, width) {
  const slots = [];
  for (let by = 0; by < maskRows; by++) {
    for (let bx = 0; bx < maskCols; bx++) {
      if (!mask[by * maskCols + bx]) continue;
      for (let y = 0; y < blockSize; y++) {
        const py = by * blockSize + y;
        const rowBase = py * width;
        for (let x = 0; x < blockSize; x++) {
          const px = bx * blockSize + x;
          const pixelIdx = (rowBase + px) * 4;
          slots.push(pixelIdx, pixelIdx + 1, pixelIdx + 2);
        }
      }
    }
  }
  return slots;
}

/**
 * Run the expensive part of carrier analysis (Sobel + per-block scoring)
 * once for a given carrier + block size. The result can be re-used across
 * many threshold changes via `buildAnalysis` below, so a UI slider doesn't
 * re-run the Sobel pass on every tick.
 */
export function scoreCarrier(imageData, blockSize) {
  const { width, height } = imageData;
  const maskCols = Math.floor(width / blockSize);
  const maskRows = Math.floor(height / blockSize);
  const maskBytes = Math.ceil((maskCols * maskRows) / 8);
  const headerTotalBytes = FIXED_HEADER_SIZE + maskBytes;
  const reservedBlockRows = computeReservedBlockRows(width, height, blockSize, headerTotalBytes);

  const { scores } = computeBlockScores(imageData, blockSize);

  return { scores, width, height, blockSize, maskCols, maskRows, reservedBlockRows };
}

/**
 * Cheaply derive the embed mask, capacity, and stats for a threshold
 * percentile from a pre-computed `scoreCarrier` result. Used to drive the
 * Complexity Visualizer and Capacity Meter in the UI.
 */
export function buildAnalysis(scored, percentile) {
  const { scores, width, height, blockSize, maskCols, maskRows, reservedBlockRows } = scored;

  const { mask, threshold, selectedCount } = buildMask(
    scores,
    maskCols,
    maskRows,
    reservedBlockRows,
    percentile
  );

  const adaptiveCapacityBits = Math.floor((selectedCount * blockSize * blockSize * 3) / 7) * 3;
  const sequentialCapacityBits = width * height * 3; // R/G/B per pixel

  return {
    width,
    height,
    blockSize,
    maskCols,
    maskRows,
    reservedBlockRows,
    totalBlocks: maskCols * maskRows,
    selectedBlocks: selectedCount,
    threshold,
    mask,
    adaptiveCapacityBits,
    sequentialCapacityBits,
  };
}

/** Convenience: score + build analysis in one call (used by tests / one-off calls). */
export function analyzeCarrier(imageData, blockSize, percentile) {
  return buildAnalysis(scoreCarrier(imageData, blockSize), percentile);
}

/**
 * Embed `ciphertext` (already AES-GCM encrypted) into `imageData` in place,
 * using a previously computed `analysis` (from buildAnalysis/analyzeCarrier)
 * so the mask actually embedded matches whatever the UI last showed the user.
 */
export function embedAdaptive(imageData, salt, iv, ciphertext, analysis) {
  const { blockSize, maskCols, maskRows, mask, adaptiveCapacityBits } = analysis;

  const payloadBits = ciphertext.length * 8;
  if (payloadBits > adaptiveCapacityBits) {
    throw new Error(
      `Payload needs ${payloadBits} bits but only ${adaptiveCapacityBits} bits are available ` +
        `at the current complexity threshold. Lower the threshold or use a larger/more complex image.`
    );
  }

  const maskBytes = packMaskBits(mask);
  const fixedHeader = buildFixedHeader(salt, iv, blockSize, maskCols, maskRows, ciphertext.length);

  const headerPacket = new Uint8Array(fixedHeader.length + maskBytes.length);
  headerPacket.set(fixedHeader, 0);
  headerPacket.set(maskBytes, fixedHeader.length);

  const data = imageData.data;
  writeSequentialBytes(data, 0, headerPacket);

  const adaptiveSlots = buildAdaptiveSlots(mask, maskCols, maskRows, blockSize, imageData.width);
  const getBit = (slot) => data[slot] & 1;
  const setBit = (slot, bit) => {
    data[slot] = (data[slot] & 0xfe) | bit;
  };
  embedBitstream(bytesToBits(ciphertext), adaptiveSlots, getBit, setBit);

  return analysis;
}

/**
 * Extract and decrypt-ready material from a stego image produced by
 * embedAdaptive. Returns { salt, iv, ciphertext, mask, maskCols, maskRows,
 * blockSize } — the caller decrypts ciphertext with crypto.js.
 */
export function extractAdaptive(imageData) {
  const data = imageData.data;
  const totalSlots = Math.floor((data.length / 4) * 3);

  if (totalSlots < FIXED_HEADER_SIZE * 8) {
    throw new Error('Image is too small to contain an adaptive header.');
  }

  const fixedHeaderBytes = readSequentialBytes(data, 0, FIXED_HEADER_SIZE);
  const { salt, iv, blockSize, maskCols, maskRows, ciphertextLength } =
    parseFixedHeader(fixedHeaderBytes);

  const maskByteLength = Math.ceil((maskCols * maskRows) / 8);
  const maskBytes = readSequentialBytes(data, FIXED_HEADER_SIZE * 8, maskByteLength);
  const mask = unpackMaskBits(maskBytes, maskCols * maskRows);

  const adaptiveSlots = buildAdaptiveSlots(mask, maskCols, maskRows, blockSize, imageData.width);
  const getBit = (slot) => data[slot] & 1;
  const bits = extractBitstream(ciphertextLength * 8, adaptiveSlots, getBit);
  const ciphertext = bitsToBytes(bits);

  return { salt, iv, ciphertext, mask, maskCols, maskRows, blockSize };
}
