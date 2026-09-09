// Variance cost map: scores each pixel by local luminance variance and
// allocates a per-pixel bit budget — 0 bits in smooth regions, 1 bit in
// moderate-texture regions, 2 bits (the two lowest bits of the blue
// channel) in high-variance/textured regions — so payload capacity
// concentrates in areas where LSB changes are least statistically
// detectable, while smooth regions (the areas most vulnerable to
// steganalysis) are left completely untouched.
//
// Only the blue channel is ever modified, and variance is always computed
// from data the embedding step never touches: full-precision red/green,
// and the top 6 bits of blue (`& 0xFC`), since a "2 bits" pixel can have
// blue's bottom two bits rewritten. That makes the cost map provably
// identical whether computed on a clean carrier or a stego image, so it
// never needs to be transmitted — only the two percentile thresholds that
// parameterize it (a couple of bytes) go in the header.

function luminance(r, g, bMasked) {
  return 0.2126 * r + 0.7152 * g + 0.0722 * bMasked;
}

/**
 * Build a luminance map using full-precision R/G and blue with its bottom
 * two bits cleared, so the map is unaffected by any prior 2-bit embedding.
 */
function buildLuminanceMap(imageData) {
  const { data, width, height } = imageData;
  const lum = new Float32Array(width * height);
  for (let i = 0, p = 0; p < width * height; i += 4, p++) {
    lum[p] = luminance(data[i], data[i + 1], data[i + 2] & 0xfc);
  }
  return lum;
}

/** Per-pixel local variance of the luminance map over a (2r+1)x(2r+1) window, edge-clamped. */
function computeLocalVariance(lum, width, height, radius) {
  const variance = new Float32Array(width * height);
  const at = (x, y) => {
    const cx = Math.min(width - 1, Math.max(0, x));
    const cy = Math.min(height - 1, Math.max(0, y));
    return lum[cy * width + cx];
  };

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let sum = 0;
      let sumSq = 0;
      let count = 0;
      for (let dy = -radius; dy <= radius; dy++) {
        for (let dx = -radius; dx <= radius; dx++) {
          const v = at(x + dx, y + dy);
          sum += v;
          sumSq += v * v;
          count++;
        }
      }
      const mean = sum / count;
      variance[y * width + x] = sumSq / count - mean * mean;
    }
  }
  return variance;
}

/**
 * Number of leading pixels (raster order) that must be reserved for the
 * plain, sequentially-embedded header (1 bit per pixel, via blue LSB).
 * Purely a function of image geometry and the header's byte size, so both
 * encoder and decoder derive the same reservation before any variance
 * analysis.
 */
export function computeReservedPixelCount(width, height, headerTotalBytes) {
  const reserved = headerTotalBytes * 8;
  if (reserved > width * height) {
    throw new Error('Carrier image is too small to hold the header for this payload.');
  }
  return reserved;
}

/**
 * Compute the local variance map for a carrier — the expensive pass (a
 * (2r+1)x(2r+1) window per pixel). Independent of the percentile
 * thresholds, so it only needs to re-run when the carrier or window radius
 * changes; `classifyTiers` below is cheap and can re-run on every UI
 * threshold change.
 */
export function computeVarianceMap(imageData, windowRadius) {
  const { width, height } = imageData;
  const lum = buildLuminanceMap(imageData);
  const variance = computeLocalVariance(lum, width, height, windowRadius);
  return { variance, width, height, windowRadius };
}

/**
 * Cheaply derive a percentile-based bit-depth tier (0, 1, or 2) for every
 * pixel outside the reserved header region, from a pre-computed variance
 * map. Reserved pixels always get tier 0.
 *
 * Tiers are assigned by *rank* (position in the sorted-by-variance order),
 * not by comparing against a threshold value: large flat regions (sky,
 * backgrounds, solid UI chrome) can put many thousands of pixels at an
 * identical — often exactly zero — variance, and a value-based threshold
 * would dump all of them into a single tier instead of splitting cleanly
 * at the requested percentiles.
 */
export function classifyTiers(variance, width, height, reservedPixelCount, lowPercentile, highPercentile) {
  const totalPixels = width * height;
  const eligibleCount = totalPixels - reservedPixelCount;
  const tiers = new Uint8Array(totalPixels); // defaults to 0

  if (eligibleCount <= 0) {
    return { tiers, lowThreshold: Infinity, highThreshold: Infinity, tierCounts: [totalPixels, 0, 0] };
  }

  const order = new Array(eligibleCount);
  for (let i = 0; i < eligibleCount; i++) order[i] = reservedPixelCount + i;
  order.sort((a, b) => variance[a] - variance[b]);

  const lowCut = Math.floor((lowPercentile / 100) * eligibleCount);
  const highCut = Math.floor((highPercentile / 100) * eligibleCount);

  const tierCounts = [reservedPixelCount, 0, 0];
  for (let rank = 0; rank < eligibleCount; rank++) {
    const p = order[rank];
    const tier = rank >= highCut ? 2 : rank >= lowCut ? 1 : 0;
    tiers[p] = tier;
    tierCounts[tier]++;
  }

  const lowThreshold = variance[order[Math.min(lowCut, eligibleCount - 1)]];
  const highThreshold = variance[order[Math.min(highCut, eligibleCount - 1)]];

  return { tiers, lowThreshold, highThreshold, tierCounts };
}

/**
 * Render a semi-transparent overlay (same pixel size as the carrier) that
 * highlights each pixel's tier: none for 0 bits (smooth, skipped), amber
 * for 1 bit, green for 2 bits, and a neutral gray for the header-reserved
 * region. Used as the "Complexity Visualizer" in the UI. Drawn at a coarse
 * block resolution for legibility/performance rather than literal per-pixel
 * dots.
 */
export function renderTierOverlay(width, height, tiers, reservedPixelCount, blockSize = 4) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');

  const tierColor = ['rgba(0,0,0,0)', 'rgba(230, 179, 60, 0.45)', 'rgba(79, 191, 143, 0.55)'];
  const reservedColor = 'rgba(140, 140, 150, 0.55)';

  for (let by = 0; by < height; by += blockSize) {
    for (let bx = 0; bx < width; bx += blockSize) {
      const p = by * width + bx;
      const color = p < reservedPixelCount ? reservedColor : tierColor[tiers[p]];
      if (color === tierColor[0]) continue;
      ctx.fillStyle = color;
      ctx.fillRect(bx, by, blockSize, blockSize);
    }
  }

  return canvas;
}
