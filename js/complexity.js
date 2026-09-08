// Adaptive complexity masking: scores image blocks by local gradient energy
// (a 3x3 Sobel operator over luminance) and selects the highest-complexity
// blocks as eligible embedding regions, to bias hidden data away from flat,
// low-entropy areas where LSB changes are more statistically detectable.
//
// Complexity is always computed from the top 7 bits of each channel
// (value & 0xFE). LSB embedding never touches those bits, so the encoder
// (scoring the clean carrier) and the decoder (scoring the stego image)
// always compute byte-identical scores without needing to transmit them.

export const DEFAULT_BLOCK_SIZE = 8;

function luminance(r, g, b) {
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/**
 * Build a luminance map from imageData using only the top 7 bits of each
 * channel, so the map is unaffected by any LSB steganography already
 * present in the pixels.
 */
function buildLuminanceMap(imageData) {
  const { data, width, height } = imageData;
  const lum = new Float32Array(width * height);
  for (let i = 0, p = 0; p < width * height; i += 4, p++) {
    const r = data[i] & 0xfe;
    const g = data[i + 1] & 0xfe;
    const b = data[i + 2] & 0xfe;
    lum[p] = luminance(r, g, b);
  }
  return lum;
}

/** Per-pixel Sobel gradient magnitude over the luminance map, edge-clamped. */
function computeSobelMagnitude(lum, width, height) {
  const mag = new Float32Array(width * height);
  const at = (x, y) => {
    const cx = Math.min(width - 1, Math.max(0, x));
    const cy = Math.min(height - 1, Math.max(0, y));
    return lum[cy * width + cx];
  };

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const gx =
        -at(x - 1, y - 1) + at(x + 1, y - 1) +
        -2 * at(x - 1, y) + 2 * at(x + 1, y) +
        -at(x - 1, y + 1) + at(x + 1, y + 1);
      const gy =
        -at(x - 1, y - 1) - 2 * at(x, y - 1) - at(x + 1, y - 1) +
        at(x - 1, y + 1) + 2 * at(x, y + 1) + at(x + 1, y + 1);
      mag[y * width + x] = Math.sqrt(gx * gx + gy * gy);
    }
  }
  return mag;
}

/**
 * Number of leading full block-rows (spanning the whole width) that must be
 * reserved for the plain, sequentially-embedded header. Computed purely
 * from image geometry and the header's byte size, so both encoder and
 * decoder derive the same reservation before any complexity scoring.
 */
export function computeReservedBlockRows(width, height, blockSize, headerTotalBytes) {
  const slotsPerBlockRow = width * blockSize * 3; // 3 usable (R/G/B) channels per pixel
  const slotsNeeded = headerTotalBytes * 8;
  const reservedBlockRows = Math.ceil(slotsNeeded / slotsPerBlockRow);
  const maskRows = Math.floor(height / blockSize);
  if (reservedBlockRows > maskRows) {
    throw new Error('Carrier image is too small to hold the header for this payload.');
  }
  return reservedBlockRows;
}

/**
 * Compute per-block complexity scores (mean Sobel magnitude) for a
 * blockSize x blockSize grid over the image.
 */
export function computeBlockScores(imageData, blockSize) {
  const { width, height } = imageData;
  const lum = buildLuminanceMap(imageData);
  const mag = computeSobelMagnitude(lum, width, height);

  const maskCols = Math.floor(width / blockSize);
  const maskRows = Math.floor(height / blockSize);
  const scores = new Float32Array(maskCols * maskRows);

  for (let by = 0; by < maskRows; by++) {
    for (let bx = 0; bx < maskCols; bx++) {
      let sum = 0;
      for (let y = 0; y < blockSize; y++) {
        const py = by * blockSize + y;
        const rowOffset = py * width;
        for (let x = 0; x < blockSize; x++) {
          sum += mag[rowOffset + bx * blockSize + x];
        }
      }
      scores[by * maskCols + bx] = sum / (blockSize * blockSize);
    }
  }

  return { scores, maskCols, maskRows };
}

/**
 * Build a binary embed mask (1 = eligible for adaptive embedding) by
 * keeping blocks whose score is at or above the given percentile among
 * blocks outside the reserved header rows. Reserved rows are always 0.
 */
export function buildMask(scores, maskCols, maskRows, reservedBlockRows, percentile) {
  const mask = new Uint8Array(maskCols * maskRows);
  const eligibleScores = [];
  for (let by = reservedBlockRows; by < maskRows; by++) {
    for (let bx = 0; bx < maskCols; bx++) {
      eligibleScores.push(scores[by * maskCols + bx]);
    }
  }

  if (eligibleScores.length === 0) {
    return { mask, threshold: Infinity, selectedCount: 0 };
  }

  eligibleScores.sort((a, b) => a - b);
  const idx = Math.min(
    eligibleScores.length - 1,
    Math.floor((percentile / 100) * eligibleScores.length)
  );
  const threshold = eligibleScores[idx];

  let selectedCount = 0;
  for (let by = reservedBlockRows; by < maskRows; by++) {
    for (let bx = 0; bx < maskCols; bx++) {
      const i = by * maskCols + bx;
      if (scores[i] >= threshold) {
        mask[i] = 1;
        selectedCount++;
      }
    }
  }

  return { mask, threshold, selectedCount };
}

/** Pack a 0/1-per-block mask into bits, MSB-first, row-major over blocks. */
export function packMaskBits(mask) {
  const byteLength = Math.ceil(mask.length / 8);
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < mask.length; i++) {
    if (mask[i]) {
      bytes[i >> 3] |= 0x80 >> (i & 7);
    }
  }
  return bytes;
}

/** Inverse of packMaskBits. */
export function unpackMaskBits(bytes, blockCount) {
  const mask = new Uint8Array(blockCount);
  for (let i = 0; i < blockCount; i++) {
    const bit = (bytes[i >> 3] >> (7 - (i & 7))) & 1;
    mask[i] = bit;
  }
  return mask;
}

/**
 * Render a semi-transparent overlay (same pixel size as the carrier) that
 * highlights selected blocks in green, unselected eligible blocks in a dim
 * red, and the reserved header region in a neutral hatch-free gray. Used as
 * the "Complexity Visualizer" in the UI.
 */
export function renderMaskOverlay(width, height, blockSize, mask, maskCols, maskRows, reservedBlockRows) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');

  for (let by = 0; by < maskRows; by++) {
    for (let bx = 0; bx < maskCols; bx++) {
      let color;
      if (by < reservedBlockRows) {
        color = 'rgba(140, 140, 150, 0.55)';
      } else if (mask[by * maskCols + bx]) {
        color = 'rgba(79, 191, 143, 0.55)';
      } else {
        color = 'rgba(229, 101, 122, 0.25)';
      }
      ctx.fillStyle = color;
      ctx.fillRect(bx * blockSize, by * blockSize, blockSize, blockSize);
    }
  }

  return canvas;
}
