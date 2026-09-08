# ShaderStego

A privacy-first web app that encrypts text client-side and hides it inside the
least-significant bits of a procedurally generated WebGL2 shader image.
Everything happens locally in the browser — nothing is ever uploaded.

## How it works

1. **Encrypt** — Your text is encrypted with AES-GCM. The key is derived from
   your passphrase using PBKDF2-SHA256 (250,000 iterations) with a random
   16-byte salt. A random 12-byte IV is generated per encryption.
2. **Frame** — The salt, IV, and ciphertext are packed behind a small header
   (`'STEG'` magic bytes + ciphertext length) so the decoder can find and size
   everything it needs.
3. **Hide** — A WebGL2 fragment shader renders a procedural Voronoi/fractal
   image sized to have enough pixels to carry the packet. Each byte of the
   packet is spread one bit per Red/Green/Blue channel (the least significant
   bit), which is visually imperceptible. The alpha channel is left untouched
   at 255, since browsers premultiply RGB by alpha when compositing a drawn
   image — flipping alpha's LSB would silently rescale the RGB channels on
   redraw and corrupt the hidden bits.
4. **Export** — The result is exported as a lossless PNG (JPEG would destroy
   the hidden bits through lossy compression).
5. **Decode** — Uploading the PNG re-reads its raw pixel buffer via
   `getImageData()`, pulls the bits back into bytes, and decrypts them with
   your passphrase. Wrong passphrase or corrupted data fails the AES-GCM
   authentication check and is reported as an error.

## Adaptive mode (V2)

The **Adaptive Encoder**/**Adaptive Decoder** tabs implement a second,
detectability-conscious scheme on top of the same AES-GCM crypto:

- **Complexity masking** — the carrier (an uploaded photo/art PNG, or a
  generated procedural shader image) is scored in `blockSize x blockSize`
  blocks using a 3x3 Sobel gradient operator over luminance. Only blocks
  whose score is at or above a user-chosen percentile threshold ("top N% of
  blocks") are eligible to carry data, biasing hidden bits toward
  high-texture regions where LSB changes are least statistically
  detectable. Scoring always reads the top 7 bits of each channel, so it's
  unaffected by any LSB embedding already present — the same code scores a
  clean carrier or a stego image identically.
- **Hamming matrix coding** — instead of plain sequential LSB, ciphertext
  bits are embedded 3-at-a-time into groups of 7 carrier bits using a
  (7,4) Hamming-code syndrome trick (a lightweight relative of
  Syndrome-Trellis Codes): for any 7 bits, at most one needs to flip to
  encode any 3-bit message. This cuts the fraction of visited bits that
  actually change from ~50% (plain LSB) to ~1/7 in the worst case.
- **Header & mask transport** — a small fixed header (`'STEGV2'` magic,
  salt, IV, block size, mask dimensions, ciphertext length) plus the packed
  1-bit-per-block embed mask are written with plain sequential LSB into the
  image's leading rows; those rows are always excluded from the adaptive
  mask so the two regions never collide. The mask is transmitted rather
  than re-derived, so decoding never depends on both sides computing
  identical floating-point Sobel scores.
- **UI** — the Complexity Visualizer overlays selected (green), unselected
  (red), and header-reserved (gray) blocks on the carrier; the Capacity
  Meter compares adaptive capacity at the current threshold against plain
  sequential-LSB capacity.

## Project layout

```
index.html              Encoder / Decoder / Adaptive Encoder / Adaptive Decoder UI
css/style.css           Styling
js/crypto.js            AES-GCM + PBKDF2 (Web Crypto API)
js/steganography.js     V1 packet framing + sequential LSB embed/extract
js/steganographyV2.js   V2 header framing + adaptive embed/extract orchestration
js/complexity.js        Sobel-based block complexity scoring + embed mask
js/hamming.js           Hamming(7,3) matrix coding (embed/extract)
js/shaderRenderer.js    WebGL2 procedural shader carrier image
js/main.js              UI wiring
```

## Running locally

The app uses native ES modules, which browsers block from `file://` origins.
Serve the directory with any static file server, for example:

```sh
python3 -m http.server 8000
# or
npx serve .
```

Then open `http://localhost:8000` in a browser that supports WebGL2 (all
modern evergreen browsers).
