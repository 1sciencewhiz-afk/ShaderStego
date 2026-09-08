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

## Project layout

```
index.html            Encoder / Decoder UI
css/style.css          Styling
js/crypto.js           AES-GCM + PBKDF2 (Web Crypto API)
js/steganography.js    Packet framing + LSB embed/extract
js/shaderRenderer.js   WebGL2 procedural shader carrier image
js/main.js             UI wiring
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
