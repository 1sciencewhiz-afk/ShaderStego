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
2. **Encrypt** — The packed bytes are encrypted with AES-GCM
   (`crypto.subtle.encrypt` operates on raw `Uint8Array`/`ArrayBuffer` data
   throughout, in `js/crypto.js`). The key is derived from your passphrase
   using PBKDF2-SHA256 (250,000 iterations) with a random 16-byte salt. A
   random 12-byte IV is generated per encryption.
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
js/crypto.js            AES-GCM + PBKDF2 over raw bytes (Web Crypto API)
js/filePacking.js       Metadata header packing/unpacking (name + MIME type)
js/steganography.js     V1 packet framing + sequential LSB embed/extract
js/steganographyV2.js   V2 header framing + adaptive embed/extract orchestration
js/complexity.js        Sobel-based block complexity scoring + embed mask
js/hamming.js           Hamming(7,3) matrix coding (embed/extract)
js/shaderRenderer.js    WebGL2 procedural shader carrier image
js/main.js              UI wiring (drag-and-drop, capacity hints, file downloads)
```

Note: this is a plain ES-modules static app with no build step (see
"Running locally" below) — there's no `src/` or TypeScript toolchain, so the
binary crypto/packing logic lives in `js/crypto.js` and `js/filePacking.js`
rather than a `src/core/*.ts` layout.

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
