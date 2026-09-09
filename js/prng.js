// Deterministic, passphrase-seeded pseudorandom permutation used to scatter
// payload bits across the pixels allocated by the variance cost map
// (complexity.js), rather than writing them in predictable raster order.
//
// Without the correct passphrase, an attacker who suspects LSB steganography
// still can't know which pixels carry which bit without also knowing the
// scatter order — a defense-in-depth layer on top of AES-GCM's cryptographic
// secrecy of the payload itself, aimed at resisting structural/blind
// steganalysis rather than replacing key secrecy.
//
// The seed is derived via a *domain-separated* SHA-256 hash of the
// passphrase and salt (distinct from the AES-GCM key derivation, so the
// permutation seed reveals nothing about the encryption key and the AES key
// never needs to be exportable). The seed then feeds a fast, non-cryptographic
// xorshift128 generator for the actual (potentially millions-of-draws) shuffle
// — a strong seed expanded by a cheap stream, rather than a slow hash per draw.

const SEED_DOMAIN = 'ShaderStego-permutation-seed-v1';

/**
 * Derive a 128-bit permutation seed (as four uint32 words) from a passphrase
 * and salt, independent of the AES-GCM key derivation.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @returns {Promise<Uint32Array>} length-4 array of seed words
 */
export async function deriveSeed(passphrase, salt) {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(SEED_DOMAIN);
  const passphraseBytes = encoder.encode(passphrase);

  const material = new Uint8Array(domainBytes.length + passphraseBytes.length + salt.length);
  material.set(domainBytes, 0);
  material.set(passphraseBytes, domainBytes.length);
  material.set(salt, domainBytes.length + passphraseBytes.length);

  const digest = await crypto.subtle.digest('SHA-256', material);
  const view = new DataView(digest);

  // Use the first 16 bytes of the digest as four uint32 seed words.
  const words = new Uint32Array(4);
  for (let i = 0; i < 4; i++) {
    words[i] = view.getUint32(i * 4, false);
  }
  // xorshift128 requires a non-zero state; astronomically unlikely with a
  // real SHA-256 digest, but guard against the degenerate all-zero case.
  if (words.every((w) => w === 0)) {
    words[0] = 1;
  }
  return words;
}

/** xorshift128 PRNG, seeded with four uint32 words. Fast, deterministic, not cryptographic. */
class Xorshift128 {
  constructor(seedWords) {
    this.x = seedWords[0] >>> 0;
    this.y = seedWords[1] >>> 0;
    this.z = seedWords[2] >>> 0;
    this.w = seedWords[3] >>> 0;
  }

  /** Next pseudorandom uint32, as an unsigned integer in [0, 2^32). */
  nextUint32() {
    const t = (this.x ^ (this.x << 11)) >>> 0;
    this.x = this.y;
    this.y = this.z;
    this.z = this.w;
    this.w = (this.w ^ (this.w >>> 19) ^ t ^ (t >>> 8)) >>> 0;
    return this.w;
  }

  /** Uniform pseudorandom integer in [0, bound). */
  nextInt(bound) {
    return Math.floor((this.nextUint32() / 4294967296) * bound);
  }
}

/**
 * Fisher-Yates shuffle of `array` in place, driven by a passphrase/salt-derived
 * seed. Deterministic: the same seed always produces the same permutation,
 * so the decoder can reproduce it exactly given the same passphrase and salt.
 * @param {Array|Uint32Array} array
 * @param {Uint32Array} seedWords - from deriveSeed()
 */
export function shuffleWithSeed(array, seedWords) {
  const prng = new Xorshift128(seedWords);
  for (let i = array.length - 1; i > 0; i--) {
    const j = prng.nextInt(i + 1);
    const tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
  }
}
