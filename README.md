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
2. **Compress, then encrypt** — The packed bytes are deflated via the
   Compression Streams API (`CompressionStream('deflate')`) before AES-GCM
   encryption, and inflated (`DecompressionStream('deflate')`) after
   decryption — both in `js/crypto.js`, so every payload (text or file, in
   either encoder) benefits automatically. Compressible payloads (text,
   source code, many document formats) need fewer LSB slots in the carrier;
   already-compressed formats (JPEG, MP3, ZIP) just carry a small (~6-byte)
   zlib-framing overhead. The key is derived from your passphrase using
   PBKDF2-SHA256 (250,000 iterations) with a random 16-byte salt. A random
   12-byte IV is generated per encryption.
3. **Frame** — The ciphertext length, salt, and IV are packed behind a small
   outer header so the decoder can find and size everything it needs.
   Deliberately no magic-byte signature: earlier versions led with a literal
   ASCII tag at a fixed, fully predictable location, which is exactly what a
   basic signature-scanning steganalysis tool checks for first. Validity
   now rests entirely on AES-GCM's own authentication tag — it either
   verifies or it doesn't, so "wrong passphrase" and "not a stego image at
   all" are indistinguishable to anyone without the passphrase.
4. **Hide** — A WebGL2 fragment shader renders a procedural Voronoi/fractal
   image sized to have enough pixels to carry the packet — with real slack
   built in (see "Capacity margin vs. detectability" below), not just a
   tight fit. Only the small fixed header (length, salt, IV) is written
   sequentially, starting at pixel 0 — it has to be, since finding it is
   how the decoder learns the salt needed to derive anything else. The
   ciphertext itself is scattered across the *entire remaining canvas*, in
   an order set by a Fisher-Yates shuffle seeded from the passphrase and
   salt (the same mechanism the Adaptive mode uses — see below). Embedding
   the whole payload sequentially from pixel 0, as earlier versions did,
   leaves a spatially contiguous block of touched pixels that a
   windowed/progressive scanner can localize regardless of how individual
   bits were written; scattering spreads it across the whole image instead.
   Every written bit — header and ciphertext alike — uses LSB matching
   (±1 embedding, see "Adaptive mode" below for why) rather than direct bit
   replacement. The alpha channel is left untouched at 255, since browsers
   premultiply RGB by alpha when compositing a drawn image — flipping
   alpha's LSB would silently rescale the RGB channels on redraw and
   corrupt the hidden bits. The Encoder shows a live capacity hint and
   rejects payloads that would need an impractically large carrier
   (past 4096x4096px).
5. **Export** — The result is exported as a lossless PNG (JPEG would destroy
   the hidden bits through lossy compression).
6. **Decode** — Uploading the PNG re-reads its raw pixel buffer via
   `getImageData()`, pulls the bits back into bytes, decrypts them with your
   passphrase, and unpacks the metadata header. Wrong passphrase or corrupted
   data fails the AES-GCM authentication check and is reported as an error —
   the same generic error a non-stego image gets, on purpose. If the
   recovered metadata's MIME type starts with `text/`, the payload is shown
   as text; otherwise it's wrapped in a `Blob` with the original MIME type,
   handed an object URL, and offered as a "Download Extracted File" button
   that preserves the original name and extension.

## Capacity margin vs. detectability

`js/steganography.js`'s `computeCanvasDimensions` sizes the carrier at 8x
the pixel capacity the payload strictly needs (`CAPACITY_MARGIN = 8`, ~12.5%
touch density) with a 320px minimum side, not a tight fit. This came from
reading a specific detector's exact chi-square implementation (Westfeld
pairs-of-values: `Σ (n₂ₖ − n₂ₖ₊₁)² / (n₂ₖ + n₂ₖ₊₁)` over cumulative
progressive slices of the image) and working through it by hand: LSB
matching alone reduces but doesn't zero out each pair's count imbalance —
a mismatched pixel moves to *either* neighboring value with equal
probability, so roughly a quarter of a pair's "wrong-parity" population
leaks into the adjacent pair rather than resolving within the same one,
leaving each pair's natural imbalance at roughly 25% of a clean image's
once every available slot is touched. Diluting the touched fraction of the
image pushes that residual down further.

That margin alone (8x, no size floor) wasn't sufficient by itself: testing
against a verbatim reproduction of the detector's own chi-square code found
that *small* carriers (under roughly 200px per side) gave the test too few
samples per histogram bin to be stable, producing spuriously high readings
on some channel even for an *unembedded* carrier of the same size — a
statistical artifact of the test itself at that scale, not something the
embedding introduced. A 320px floor keeps every carrier comfortably past
where that instability showed up.

**This has been empirically verified**, using a verbatim port of the
detector's `lngamma`/`gammaCDF`/`chiSquarePValue`/pairs-of-values code
(the pieces that actually decide its "Prob" badge and
CLEAN/SUSPICIOUS/HIGH verdict, both driven only by the final —
100%-of-image — value, not the max across the progressive chart) run
against real images produced by this app's own Encoder in a real browser.
Across 80 trials spanning payloads from 39 to 11,614 characters at the
current margin and floor, the worst final probability seen on any of the
detector's four channel options (Red/Green/Blue/Grayscale) was 1.4%, all
far under its 35% "suspicious" cutoff. Before the 320px floor was added,
15 trials biased toward small payloads (200–1700 characters) produced one
result over the cutoff (41.9%) and, at even smaller sizes still hitting the
old 64px floor, results as high as 92.3% on a single channel — this is
what the floor fixes. This is evidence against one specific detector's
algorithm on the payload sizes tested, not a universal guarantee against
every possible steganalysis technique or payload size.

### Carrier self-check (banding, independent of anything embedded)

A wider sweep — testing every power-of-ten-ish payload size from 10 bytes
to 400,000 characters, not just the 39–11,614 range above — turned up a
different problem, unrelated to embedding density: at some specific carrier
dimensions (839x839 was the one found), the shader's output *by itself*,
with nothing hidden in it at all, read as 90-100% suspicious on Red and/or
Grayscale. The Voronoi field's color is a smooth analytic function of
distance-to-nearest-point; quantizing a slow gradient to 8 bits produces
histogram "banding" whose exact shape can imbalance the pairs-of-values
statistic purely from how that gradient's local slope interacts with a
given image's pixel dimensions — confirmed by checking completely
unembedded renders at the same size, which read just as suspicious.

Per-pixel dithering was tried first (adding small random noise before
quantization, both in the shader itself and via a numerically safer
trig-free hash after `sin()`-based noise was suspected of its own precision
issues at large coordinates) — but even at amplitudes well above normal
dithering (±8 of 255, clearly visible-scale noise), the statistic barely
moved and sometimes got worse. Rather than keep tuning a shader constant
against one statistic by feel, `js/carrierSelfCheck.js` runs the same
single-shot pairs-of-values p-value calculation the detector would, and:

- `renderShaderCanvas` (`js/shaderRenderer.js`) checks its own raw output
  before returning it, and re-renders with a fresh random Voronoi seed
  (the shader already varies this per call) up to 20 times if a channel
  reads above a 0.2 p-value — comfortably under the detector's 0.35 cutoff,
  leaving margin for embedding's own contribution.
- The Encoder's embed step (`js/main.js`) checks again *after* embedding,
  since a carrier that was clean on its own can still cross the cutoff
  once real data is scattered into it (the residual pair imbalance LSB
  matching leaves under full touch density, described above) — and
  retries against a freshly-rendered carrier (up to 5 times) if so, keeping
  the best (lowest worst-channel p-value) attempt even if none clear the
  threshold outright, so encoding never gets stuck.

**Re-verified** at 839x839 specifically (the size that failed before any of
this): 8 real encode round-trips through the actual Encoder UI all landed
at or under 14.5% on every channel (versus 90-99.9% before the fix), and a
repeat of the wide payload-size sweep (10 bytes to 400,000 characters, 16
sizes) came back with 0 of 64 channel-trials over the 35% cutoff, worst
case 10.2%.

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
AES-GCM(+deflate) crypto, tuned to maximize how much a given carrier can
hold while keeping changes concentrated where they're least visible and
statistically hardest to fingerprint.

- **Variance cost map** (`js/complexity.js`) — every pixel outside the
  header region is scored by local luminance variance over a 3x3 (or 5x5)
  window. Two user-adjustable percentile cutoffs then bucket each pixel
  into a bit budget: **0 bits** (smooth regions — left completely
  untouched, since flat areas are the most statistically vulnerable to LSB
  steganalysis), **1 bit** (moderate texture — blue channel LSB only), or
  **2 bits** (high-detail/textured regions — blue channel's two lowest
  bits, LSB and LSB+1). Red and green are never modified at all; all
  embedding is concentrated in blue, the channel human vision is least
  sensitive to. Tiers are assigned by *rank* in the sorted variance order
  rather than by comparing against a raw threshold value, so large flat
  regions (which often share an exactly-equal, frequently zero, variance)
  still split cleanly at the requested percentiles instead of collapsing
  into one tier. Variance is computed from red and green *only* — not
  blue at all, not even its nominally-untouched high bits, since LSB
  matching's ±1 arithmetic (below) can carry into bits above the ones it
  targets. Excluding blue entirely makes the cost map mathematically
  unaffected by the embedding, so it never needs to be transmitted; only
  the two percentile thresholds (a couple of bytes) go in the header.
- **LSB matching, not replacement** (`js/lsbMatching.js`) — a pixel's
  target bits are reached by nudging its blue channel value up or down by
  the smallest amount that works, rather than directly overwriting its low
  bits. Direct bit replacement has a well-known statistical signature: it
  only ever turns an even value into itself-or-odd+1, never odd-1, so
  values end up asymmetrically "paired" — exactly what the classic
  chi-square steganalysis attack tests for. LSB matching removes that
  asymmetry by choosing the direction at random whenever both directions
  reach the target equally well (verified by exhaustive test: for every
  value/target/tier combination, the two directions are chosen with
  identical frequency). A 2-bit pixel's bits are always written and read
  together as one atomic 2-bit match — not as two independent bits —
  since a carry from matching one bit could otherwise clobber the other.
- **Passphrase-seeded scatter** (`js/prng.js`) — rather than writing
  payload bits into allocated pixels in raster order, whole pixels
  (each contributing its 1- or 2-bit budget) are visited in an order
  scattered by a Fisher-Yates shuffle driven by a fast xorshift128
  generator, seeded from a SHA-256 hash of the passphrase and salt
  (domain-separated from the AES-GCM key derivation, so the seed reveals
  nothing about the encryption key). Without the correct passphrase, the
  scatter order — and so which bits are the payload — is unrecoverable
  even by an attacker who reproduces the variance analysis exactly. This
  is defense-in-depth against structural/blind steganalysis on top of, not
  instead of, AES-GCM secrecy.
- **Header transport** — a small fixed header (salt, IV, variance window
  radius, the two percentile thresholds, ciphertext length — no magic-byte
  signature, for the same signature-scanning reason as V1 above) is written
  one bit per pixel (blue channel, LSB matching) into the image's leading
  pixels; those pixels are always excluded from the variance cost map so
  the two regions never collide. A header whose window radius or
  percentiles fall outside the only values this app ever writes is
  rejected up front as implausible, without revealing whether that's
  because it's not a stego image or because the passphrase is wrong.
- **UI** — the Complexity Visualizer overlays each pixel's tier (amber for
  1 bit, green for 2 bits, gray for the header-reserved region, untouched
  for 0 bits) on the carrier; the Capacity Meter shows the 0/1/2-bit pixel
  counts and total adaptive capacity against a plain sequential-LSB
  reference.

Because red and green are never touched at all, a per-channel pairs-of-values
chi-square test reading either channel sees nothing from the embedding itself
(it can still occasionally read high on its own, purely from sampling noise —
see the floor discussion below). Reading blue (or a grayscale value derived
from it) is where the payload actually lives, and — unlike red/green — this
was checked, not just reasoned through: a Node-only stress harness embedded
payloads across a spread of carrier sizes (128px to 1024px), percentile
threshold settings (default 40/75, aggressive 90/98, loose 0/50), and fill
levels (from light to as near the tier-identified capacity as the code would
allow) and ran the detector's own verbatim chi-square code against the
result. Before any fix, this found real, large detections: near-capacity
payloads on an otherwise-clean 512x512 carrier reached 90.8% on blue, and a
256x256 carrier reached 95.6% even at a modest 8.4% fill — both far past the
35% "suspicious" cutoff, and analogous to what V1 had before its own margin
and floor above.

Two changes fixed this, both enforced in `embedAdaptive` itself (an embed
call throws rather than silently producing a detectable image):

- **A hard cap on usable capacity** — at most one quarter of the
  variance-identified capacity (`CAPACITY_MARGIN = 4` in
  `js/steganographyV2.js`) may actually be used per embed. V1 dilutes touch
  density by inflating its own generated carrier; V2 frequently gets a
  user-supplied carrier it can't resize, so the margin here is a cap
  enforced at embed time instead. The UI's capacity meter and payload-size
  hint both show this margin-adjusted "safe usable capacity" figure
  alongside the raw tier-map total, so the number a user sees before
  encoding matches what will actually be accepted.
- **A 512px minimum carrier side** (`MIN_SIDE` in `js/steganographyV2.js`) —
  smaller carriers starve the chi-square test's histogram bins regardless of
  what's embedded (confirmed with completely unembedded carriers: some
  channel spuriously read over the cutoff on carriers as large as 480px in
  testing). This is a higher floor than V1's 320px: V1's floor was verified
  against carriers it generates itself, which have more locally-varied
  texture than an arbitrary user upload can be assumed to have, and 512px
  (matching this app's own procedural default) is the smallest size that
  tested reliably clean against a low-texture synthetic carrier meant to
  stand in for a worst-case upload.

**Re-verified after the fix**, same methodology (verbatim detector chi-square
code, both the Node-only stress harness and the real Adaptive Encoder in a
real browser): across every non-rejected scenario in the stress harness —
spanning the 512px floor exactly, aggressive and loose threshold settings,
carriers up to 1024px, and payloads filled to 90% of the safe cap — the blue
channel (the only channel ever written) read 0.0% in every single run.
Red/Green/Grayscale occasionally still read above the cutoff (up to 38% on
green at 1024px in one run), but the same noise shows up on those channels in
carriers with nothing embedded at all — it's the detector's own baseline
false-positive rate on channels this scheme never touches, not a signal this
app produces. Separately, 15 trials through the real Adaptive Encoder UI at
default settings (512x512 procedural carrier, 50-8000 character payloads)
came back 0.0% on all four channels, with no regression to normal encode/
decode/wrong-password behavior.

## Project layout

```
index.html              How to Use / Encoder / Decoder / Adaptive Encoder / Adaptive Decoder UI
css/style.css           Styling
js/crypto.js            AES-GCM + PBKDF2 + deflate (Web Crypto / Compression Streams API)
js/filePacking.js       Metadata header packing/unpacking (name + MIME type)
js/steganography.js     V1 header framing + passphrase-scattered LSB-matched embed/extract
js/steganographyV2.js   V2 header framing + variance-tiered embed/extract orchestration
js/complexity.js        Per-pixel local variance scoring + percentile tier classification
js/lsbMatching.js       LSB matching (±1 embedding) for a pixel's low k bits
js/prng.js              Passphrase-seeded PRNG + Fisher-Yates shuffle for pixel scatter
js/shaderRenderer.js    WebGL2 procedural shader carrier image
js/main.js              UI wiring (drag-and-drop, capacity hints, file downloads)
```

Note: this is a plain ES-modules static app with no build step (see
"Running locally" below) — there's no `src/` or TypeScript toolchain, so the
binary crypto/packing logic lives in `js/crypto.js` and `js/filePacking.js`
rather than a `src/core/crypto.ts`, and the adaptive cost map lives in
`js/complexity.js` rather than `src/core/adaptiveMask.ts`.

## Compatibility note

Compression changed what gets encrypted (V1 and V2 alike; gzip → deflate
too), and both modes' embedding mechanism changed — LSB matching instead of
direct bit replacement, magic-byte signatures dropped entirely in favor of
AES-GCM-only validation, and (V2 always, V1 now too) pixels/bits scattered
across the whole canvas via a passphrase-seeded shuffle instead of written
sequentially from pixel 0 — enough that even the *same* passphrase produces
a different bit order than before. There's deliberately no version marker
to signal this cleanly anymore (that's the point — see "Frame" and "Header
transport" above): a stale image just fails AES-GCM authentication like any
other wrong-passphrase or non-stego image would. Images produced by earlier
versions of this app are not decodable by the current one, in either mode.

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
