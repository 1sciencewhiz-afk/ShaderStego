# ShaderStego

A privacy-first web app that encrypts text or any file client-side and hides
it inside the least-significant bits of a procedurally generated WebGL2
shader image. Everything happens locally in the browser — nothing is ever
uploaded.

## How it works

1. **Pack** — The payload — either the typed text, or an attached file read
   via `File.arrayBuffer()` — is wrapped behind a small metadata header:
   `[2-byte big-endian header length] + [JSON {"name", "type"}] + [raw bytes]`
   (`js/filePacking.js`). Plain text is packed the same way, as a virtual
   `message.txt` / `text/plain` file, so encoder and decoder only ever deal
   with one payload shape.
2. **Compress, then encrypt** — The packed bytes are gzipped via the
   Compression Streams API (`CompressionStream('gzip')`) before AES-GCM
   encryption, and gunzipped (`DecompressionStream`) after decryption —
   both in `js/crypto.js`, so every payload (text or file, in either
   encoder) benefits automatically. Compressible payloads (text, source
   code, many document formats) need fewer LSB slots in the carrier;
   already-compressed formats (JPEG, MP3, ZIP) just carry a small (~20-byte)
   gzip-framing overhead. The key is derived from your passphrase using
   PBKDF2-SHA256 (250,000 iterations) with a random 16-byte salt. A random
   12-byte IV is generated per encryption.
3. **Frame** — The salt, IV, and ciphertext are packed behind a small outer
   header (`'STEG'` magic bytes + ciphertext length) so the decoder can find
   and size everything it needs.
4. **Hide** — A WebGL2 fragment shader renders a procedural Voronoi/fractal
   image sized to have enough pixels to carry the packet. Each byte of the
   packet is spread one bit per Red/Green/Blue channel (the least significant
   bit), which is visually imperceptible. The alpha channel is left untouched
   at 255, since browsers premultiply RGB by alpha when compositing a drawn
   image — flipping alpha's LSB would silently rescale the RGB channels on
   redraw and corrupt the hidden bits. The Encoder shows a live capacity hint
   and rejects payloads that would need an impractically large carrier
   (past 4096x4096px).
5. **Export** — The result is exported as a lossless PNG (JPEG would destroy
   the hidden bits through lossy compression).
6. **Decode** — Uploading the PNG re-reads its raw pixel buffer via
   `getImageData()`, pulls the bits back into bytes, decrypts them with your
   passphrase, and unpacks the metadata header. Wrong passphrase or corrupted
   data fails the AES-GCM authentication check and is reported as an error.
   If the recovered metadata's MIME type starts with `text/`, the payload is
   shown as text; otherwise it's wrapped in a `Blob` with the original MIME
   type, handed an object URL, and offered as a "Download Extracted File"
   button that preserves the original name and extension.

## Hiding a file instead of text

Both the Encoder and the Adaptive Encoder have a drag-and-drop zone (or
click-to-browse) next to the text area. Attaching a file disables the text
area and hides that file's bytes instead — any format works (PDF, ZIP, MP3,
EXE, ...), since the pipeline never assumes the payload is text. The
matching Decoder tab automatically reconstructs the original file on
successful decryption.

## Adaptive mode (V2)

The **Adaptive Encoder**/**Adaptive Decoder** tabs implement a second,
capacity- and detectability-conscious scheme on top of the same
AES-GCM(+gzip) crypto, tuned to maximize how much a given carrier can hold
while keeping changes concentrated where they're least visible.

- **Variance cost map** (`js/complexity.js`) — every pixel outside the
  header region is scored by local luminance variance over a 3x3 (or 5x5)
  window. Two user-adjustable percentile cutoffs then bucket each pixel
  into a bit budget: **0 bits** (smooth regions — left completely
  untouched, since flat areas are the most statistically vulnerable to LSB
  steganalysis), **1 bit** (moderate texture — blue channel LSB only), or
  **2 bits** (high-detail/textured regions — blue channel's two lowest
  bits, LSB and LSB+1). Red and green are never modified; all embedding is
  concentrated in blue, the channel human vision is least sensitive to.
  Tiers are assigned by *rank* in the sorted variance order rather than by
  comparing against a raw threshold value, so large flat regions (which
  often share an exactly-equal, frequently zero, variance) still split
  cleanly at the requested percentiles instead of collapsing into one tier.
  Variance is computed from full-precision red/green and blue with its
  bottom two bits cleared, so — like V1's channel choice — the cost map is
  mathematically unaffected by the embedding itself and never needs to be
  transmitted; only the two percentile thresholds (a couple of bytes) go in
  the header.
- **Passphrase-seeded scatter** (`js/prng.js`) — rather than writing
  payload bits into allocated pixels in raster order, they're scattered
  using a Fisher-Yates shuffle driven by a fast xorshift128 generator,
  seeded from a SHA-256 hash of the passphrase and salt (domain-separated
  from the AES-GCM key derivation, so the seed reveals nothing about the
  encryption key). Without the correct passphrase, the scatter order — and
  so which bits are the payload — is unrecoverable even by an attacker who
  reproduces the variance analysis exactly. This is defense-in-depth
  against structural/blind steganalysis on top of, not instead of, AES-GCM
  secrecy.
- **Header transport** — a small fixed header (`'STEGV3'` magic, salt, IV,
  variance window radius, the two percentile thresholds, ciphertext length)
  is written with plain sequential LSB (blue channel only) into the image's
  leading pixels; those pixels are always excluded from the variance cost
  map so the two regions never collide.
- **UI** — the Complexity Visualizer overlays each pixel's tier (amber for
  1 bit, green for 2 bits, gray for the header-reserved region, untouched
  for 0 bits) on the carrier; the Capacity Meter shows the 0/1/2-bit pixel
  counts and total adaptive capacity against a plain sequential-LSB
  reference.

## Project layout

```
index.html              How to Use / Encoder / Decoder / Adaptive Encoder / Adaptive Decoder UI
css/style.css           Styling
js/crypto.js            AES-GCM + PBKDF2 + gzip (Web Crypto / Compression Streams API)
js/filePacking.js       Metadata header packing/unpacking (name + MIME type)
js/steganography.js     V1 packet framing + sequential LSB embed/extract
js/steganographyV2.js   V2 header framing + variance-tiered embed/extract orchestration
js/complexity.js        Per-pixel local variance scoring + percentile tier classification
js/prng.js              Passphrase-seeded PRNG + Fisher-Yates shuffle for bit scatter
js/shaderRenderer.js    WebGL2 procedural shader carrier image
js/main.js              UI wiring (drag-and-drop, capacity hints, file downloads)
```

Note: this is a plain ES-modules static app with no build step (see
"Running locally" below) — there's no `src/` or TypeScript toolchain, so the
binary crypto/packing logic lives in `js/crypto.js` and `js/filePacking.js`
rather than a `src/core/*.ts` layout, and the adaptive carrier logic lives
in `js/complexity.js`/`js/steganographyV2.js` rather than `src/core/glEncoder.ts`.

## Compatibility note

Gzip compression changed what gets encrypted (V1 and V2 alike), and V2's
embedding scheme was replaced outright (block-mask + Hamming coding →
per-pixel variance tiers + passphrase-seeded scatter, with the magic bytes
bumped `'STEGV2'` → `'STEGV3'`). Images produced by earlier versions of
this app are not decodable by the current one, in either mode.

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
