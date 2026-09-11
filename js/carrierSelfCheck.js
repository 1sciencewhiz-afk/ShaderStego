// Self-check for procedurally-generated carriers: computes the same
// Westfeld pairs-of-values chi-square statistic a steganalysis scanner
// would (verified against a real scanner's own algorithm — see README),
// on the carrier *before* anything is embedded into it.
//
// Why this exists: the WebGL shader carrier is a smooth analytic gradient
// (Voronoi cell distance + a Julia-set glow), and quantizing a smooth
// gradient to 8 bits can produce "banding" — histogram plateaus whose
// exact shape happens to imbalance the chi-square pairs statistic, purely
// from how the continuous color function's local slope interacts with a
// given image's pixel dimensions. This was found empirically at specific
// sizes (e.g. 839x839) reading as 90-100% "suspicious" with *nothing*
// embedded yet. It isn't a fixed property of the shader design that a
// one-time constant (like a dither term) reliably cancels out — testing
// found per-pixel dithering, even at large amplitudes, only modestly
// moved the statistic and sometimes made it worse. But since the shader
// draws a fresh random Voronoi jitter each render (`uSeed`), a different
// render at the *same* dimensions produces a materially different value
// distribution — so checking and, if needed, re-rendering with a new seed
// is a direct, verifiable way to guarantee the carrier that actually gets
// used passes the same test a real scanner would run, rather than trying
// to reason a shader change into always being safe.

function lngamma(z) {
  const coeff = [
    76.18009172947146, -86.50532032941677,
    24.01409824083091, -1.231739572450155,
    0.1208650973866179e-2, -0.5395239384953e-5,
  ];
  const x = z;
  let y = z;
  let tmp = x + 5.5;
  tmp -= (x + 0.5) * Math.log(tmp);
  let ser = 1.000000000190015;
  for (let j = 0; j <= 5; j++) {
    y += 1;
    ser += coeff[j] / y;
  }
  return -tmp + Math.log((2.5066282746310005 * ser) / x);
}

function gammaCDF(a, x) {
  if (x <= 0) return 0;
  if (x > 300) return 1;
  let sum = 1 / a;
  let term = 1 / a;
  for (let n = 1; n < 200; n++) {
    term *= x / (a + n);
    sum += term;
    if (term < sum * 1e-12) break;
  }
  const logVal = -x + a * Math.log(x) - lngamma(a);
  if (logVal < -700) return 0;
  return Math.min(1, Math.max(0, sum * Math.exp(logVal)));
}

function chiSquarePValue(chi2, df) {
  if (df <= 0 || chi2 <= 0) return 0;
  const a = df / 2;
  const x = chi2 / 2;
  return Math.max(0, Math.min(1, 1 - gammaCDF(a, x)));
}

function pValueFromHistogram(freq) {
  let chiSquare = 0;
  let df = 0;
  for (let k = 0; k < 128; k++) {
    const n2k = freq[2 * k];
    const n2k1 = freq[2 * k + 1];
    const totalPair = n2k + n2k1;
    if (totalPair > 0) {
      const diff = n2k - n2k1;
      chiSquare += (diff * diff) / totalPair;
      df++;
    }
  }
  return chiSquarePValue(chiSquare, df);
}

/**
 * Worst (max) chi-square p-value across all four channels a scanner might
 * pick (Red/Green/Blue/Grayscale) for this carrier's raw pixel data. Builds
 * all four histograms in one pass over the pixel buffer (rather than one
 * pass per channel) so repeated self-check attempts stay cheap.
 */
export function worstChannelPValue(imageData) {
  const { data } = imageData;
  const totalPixels = data.length / 4;
  const freqR = new Array(256).fill(0);
  const freqG = new Array(256).fill(0);
  const freqB = new Array(256).fill(0);
  const freqGray = new Array(256).fill(0);

  for (let i = 0; i < totalPixels; i++) {
    const pxIdx = i * 4;
    const r = data[pxIdx];
    const g = data[pxIdx + 1];
    const b = data[pxIdx + 2];
    freqR[r]++;
    freqG[g]++;
    freqB[b]++;
    freqGray[Math.round(0.299 * r + 0.587 * g + 0.114 * b)]++;
  }

  return Math.max(
    pValueFromHistogram(freqR),
    pValueFromHistogram(freqG),
    pValueFromHistogram(freqB),
    pValueFromHistogram(freqGray)
  );
}
