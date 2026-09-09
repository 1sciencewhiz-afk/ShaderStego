import { encryptText, decryptToText } from './crypto.js';
import { buildPacket, computeCanvasDimensions, embedPacket, extractPacket } from './steganography.js';
import { renderShaderCanvas } from './shaderRenderer.js';
import { renderMaskOverlay } from './complexity.js';
import { scoreCarrier, buildAnalysis, embedAdaptive, extractAdaptive } from './steganographyV2.js';

// Mimics the filename Google Gemini gives its generated-image downloads
// (e.g. "Gemini_Generated_Image_a1b2c3.png"), so the stego PNG blends in
// with ordinary AI-generated image downloads rather than standing out.
function generateGeminiFilename() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let suffix = '';
  for (let i = 0; i < 6; i++) {
    suffix += chars[Math.floor(Math.random() * chars.length)];
  }
  return `Gemini_Generated_Image_${suffix}.png`;
}

// --- Tab switching ---------------------------------------------------------

const tabButtons = document.querySelectorAll('.tab-button');
const tabPanels = document.querySelectorAll('.tab-panel');

tabButtons.forEach((button) => {
  button.addEventListener('click', () => {
    tabButtons.forEach((b) => b.classList.remove('active'));
    tabPanels.forEach((p) => p.classList.remove('active'));
    button.classList.add('active');
    document.getElementById(button.dataset.target).classList.add('active');
  });
});

// --- Encoder -----------------------------------------------------------------

const encodeText = document.getElementById('encode-text');
const encodePassword = document.getElementById('encode-password');
const encodeButton = document.getElementById('encode-button');
const encodeStatus = document.getElementById('encode-status');
const encodePreview = document.getElementById('encode-preview');
const downloadLink = document.getElementById('download-link');

function setStatus(el, message, kind = 'info') {
  el.textContent = message;
  el.className = `status status-${kind}`;
}

encodeButton.addEventListener('click', async () => {
  const text = encodeText.value;
  const password = encodePassword.value;

  if (!text.trim()) {
    setStatus(encodeStatus, 'Enter some text to hide.', 'error');
    return;
  }
  if (!password) {
    setStatus(encodeStatus, 'Enter a passphrase to encrypt the data.', 'error');
    return;
  }

  encodeButton.disabled = true;
  downloadLink.classList.add('hidden');
  encodePreview.classList.add('hidden');
  setStatus(encodeStatus, 'Encrypting data...', 'info');

  try {
    const { salt, iv, ciphertext } = await encryptText(text, password);
    const packet = buildPacket(salt, iv, ciphertext);

    setStatus(encodeStatus, 'Generating carrier image...', 'info');
    const { width, height } = computeCanvasDimensions(packet.length);
    const canvas = renderShaderCanvas(width, height);
    const ctx = canvas.getContext('2d');

    const imageData = ctx.getImageData(0, 0, width, height);
    embedPacket(imageData, packet);
    ctx.putImageData(imageData, 0, 0);

    encodePreview.src = canvas.toDataURL('image/png');
    encodePreview.classList.remove('hidden');

    canvas.toBlob((blob) => {
      const url = URL.createObjectURL(blob);
      downloadLink.href = url;
      downloadLink.download = generateGeminiFilename();
      downloadLink.classList.remove('hidden');
    }, 'image/png');

    setStatus(
      encodeStatus,
      `Done. Payload hidden in a ${width}x${height} image.`,
      'success'
    );
  } catch (err) {
    console.error(err);
    setStatus(encodeStatus, `Error: ${err.message}`, 'error');
  } finally {
    encodeButton.disabled = false;
  }
});

// --- Decoder -----------------------------------------------------------------

const decodeFile = document.getElementById('decode-file');
const decodePassword = document.getElementById('decode-password');
const decodeButton = document.getElementById('decode-button');
const decodeStatus = document.getElementById('decode-status');
const decodeOutput = document.getElementById('decode-output');

function loadImageFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Could not load the selected image.'));
    };
    img.src = url;
  });
}

decodeButton.addEventListener('click', async () => {
  const file = decodeFile.files[0];
  const password = decodePassword.value;

  decodeOutput.value = '';

  if (!file) {
    setStatus(decodeStatus, 'Choose a PNG file to decode.', 'error');
    return;
  }
  if (!password) {
    setStatus(decodeStatus, 'Enter the passphrase used to encrypt the data.', 'error');
    return;
  }

  decodeButton.disabled = true;
  setStatus(decodeStatus, 'Reading image...', 'info');

  try {
    const img = await loadImageFile(file);
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    setStatus(decodeStatus, 'Extracting hidden payload...', 'info');
    const { salt, iv, ciphertext } = extractPacket(imageData);

    setStatus(decodeStatus, 'Decrypting...', 'info');
    const plaintext = await decryptToText(ciphertext, password, salt, iv);

    decodeOutput.value = plaintext;
    setStatus(decodeStatus, 'Decrypted successfully.', 'success');
  } catch (err) {
    console.error(err);
    setStatus(
      decodeStatus,
      `Error: ${err.message || 'Incorrect passphrase or corrupted image.'}`,
      'error'
    );
  } finally {
    decodeButton.disabled = false;
  }
});

// --- Adaptive Encoder (V2) ----------------------------------------------------

const adaptiveCarrierFile = document.getElementById('adaptive-carrier-file');
const adaptiveGenerateButton = document.getElementById('adaptive-generate-button');
const adaptiveCarrierPreview = document.getElementById('adaptive-carrier-preview');
const adaptiveBlockSizeSelect = document.getElementById('adaptive-block-size');
const adaptiveThreshold = document.getElementById('adaptive-threshold');
const adaptiveThresholdValue = document.getElementById('adaptive-threshold-value');
const adaptiveCapacityMeter = document.getElementById('adaptive-capacity-meter');
const adaptiveSelectedBlocksEl = document.getElementById('adaptive-selected-blocks');
const adaptiveCapacityBitsEl = document.getElementById('adaptive-capacity-bits');
const adaptiveSequentialBitsEl = document.getElementById('adaptive-sequential-bits');
const adaptiveVisualizer = document.getElementById('adaptive-visualizer');
const adaptiveEncodeText = document.getElementById('adaptive-encode-text');
const adaptiveEncodePassword = document.getElementById('adaptive-encode-password');
const adaptiveEncodeButton = document.getElementById('adaptive-encode-button');
const adaptiveEncodeStatus = document.getElementById('adaptive-encode-status');
const adaptiveEncodePreview = document.getElementById('adaptive-encode-preview');
const adaptiveDownloadLink = document.getElementById('adaptive-download-link');

let adaptiveScored = null; // expensive Sobel/block-score pass, cached per carrier + block size
let adaptiveAnalysis = null; // cheap threshold-derived mask, cached per slider position

function formatBits(bits) {
  return `${bits} bits (${(bits / 8).toFixed(0)} bytes)`;
}

function drawCarrierToPreview(canvasLike) {
  adaptiveCarrierPreview.width = canvasLike.width;
  adaptiveCarrierPreview.height = canvasLike.height;
  adaptiveCarrierPreview.getContext('2d').drawImage(canvasLike, 0, 0);
  adaptiveCarrierPreview.classList.remove('hidden');
}

function recomputeAdaptiveScoring() {
  if (!adaptiveCarrierPreview.width) return;
  const ctx = adaptiveCarrierPreview.getContext('2d');
  const imageData = ctx.getImageData(0, 0, adaptiveCarrierPreview.width, adaptiveCarrierPreview.height);
  const blockSize = Number(adaptiveBlockSizeSelect.value);
  try {
    adaptiveScored = scoreCarrier(imageData, blockSize);
    recomputeAdaptiveAnalysis();
  } catch (err) {
    adaptiveScored = null;
    adaptiveAnalysis = null;
    setStatus(adaptiveEncodeStatus, `Error: ${err.message}`, 'error');
  }
}

function recomputeAdaptiveAnalysis() {
  if (!adaptiveScored) return;
  const percentile = Number(adaptiveThreshold.value);
  adaptiveThresholdValue.textContent = String(percentile);
  adaptiveAnalysis = buildAnalysis(adaptiveScored, percentile);

  const { width, height, blockSize, mask, maskCols, maskRows, reservedBlockRows, selectedBlocks, totalBlocks, adaptiveCapacityBits, sequentialCapacityBits } = adaptiveAnalysis;

  adaptiveSelectedBlocksEl.textContent = `${selectedBlocks} / ${totalBlocks}`;
  adaptiveCapacityBitsEl.textContent = formatBits(adaptiveCapacityBits);
  adaptiveSequentialBitsEl.textContent = formatBits(sequentialCapacityBits);
  adaptiveCapacityMeter.classList.remove('hidden');

  const overlay = renderMaskOverlay(width, height, blockSize, mask, maskCols, maskRows, reservedBlockRows);
  adaptiveVisualizer.width = width;
  adaptiveVisualizer.height = height;
  const vctx = adaptiveVisualizer.getContext('2d');
  vctx.drawImage(adaptiveCarrierPreview, 0, 0);
  vctx.drawImage(overlay, 0, 0);
  adaptiveVisualizer.classList.remove('hidden');
}

adaptiveCarrierFile.addEventListener('change', async () => {
  const file = adaptiveCarrierFile.files[0];
  if (!file) return;
  try {
    const img = await loadImageFile(file);
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    canvas.getContext('2d').drawImage(img, 0, 0);
    drawCarrierToPreview(canvas);
    recomputeAdaptiveScoring();
    setStatus(adaptiveEncodeStatus, 'Carrier loaded. Analyzing complexity...', 'info');
  } catch (err) {
    setStatus(adaptiveEncodeStatus, `Error: ${err.message}`, 'error');
  }
});

adaptiveGenerateButton.addEventListener('click', () => {
  try {
    const canvas = renderShaderCanvas(512, 512);
    drawCarrierToPreview(canvas);
    recomputeAdaptiveScoring();
    setStatus(adaptiveEncodeStatus, 'Procedural carrier generated. Analyzing complexity...', 'info');
  } catch (err) {
    setStatus(adaptiveEncodeStatus, `Error: ${err.message}`, 'error');
  }
});

adaptiveBlockSizeSelect.addEventListener('change', recomputeAdaptiveScoring);
adaptiveThreshold.addEventListener('input', recomputeAdaptiveAnalysis);

adaptiveEncodeButton.addEventListener('click', async () => {
  const text = adaptiveEncodeText.value;
  const password = adaptiveEncodePassword.value;

  if (!adaptiveAnalysis) {
    setStatus(adaptiveEncodeStatus, 'Load or generate a carrier image first.', 'error');
    return;
  }
  if (!text.trim()) {
    setStatus(adaptiveEncodeStatus, 'Enter some text to hide.', 'error');
    return;
  }
  if (!password) {
    setStatus(adaptiveEncodeStatus, 'Enter a passphrase to encrypt the data.', 'error');
    return;
  }

  adaptiveEncodeButton.disabled = true;
  adaptiveDownloadLink.classList.add('hidden');
  adaptiveEncodePreview.classList.add('hidden');
  setStatus(adaptiveEncodeStatus, 'Encrypting and embedding...', 'info');

  try {
    const { salt, iv, ciphertext } = await encryptText(text, password);

    const ctx = adaptiveCarrierPreview.getContext('2d');
    const imageData = ctx.getImageData(0, 0, adaptiveCarrierPreview.width, adaptiveCarrierPreview.height);

    embedAdaptive(imageData, salt, iv, ciphertext, adaptiveAnalysis);
    ctx.putImageData(imageData, 0, 0);

    adaptiveEncodePreview.src = adaptiveCarrierPreview.toDataURL('image/png');
    adaptiveEncodePreview.classList.remove('hidden');

    adaptiveCarrierPreview.toBlob((blob) => {
      const url = URL.createObjectURL(blob);
      adaptiveDownloadLink.href = url;
      adaptiveDownloadLink.download = generateGeminiFilename();
      adaptiveDownloadLink.classList.remove('hidden');
    }, 'image/png');

    setStatus(
      adaptiveEncodeStatus,
      `Done. Payload hidden across ${adaptiveAnalysis.selectedBlocks} high-complexity blocks.`,
      'success'
    );
  } catch (err) {
    console.error(err);
    setStatus(adaptiveEncodeStatus, `Error: ${err.message}`, 'error');
  } finally {
    adaptiveEncodeButton.disabled = false;
  }
});

// --- Adaptive Decoder (V2) ----------------------------------------------------

const adaptiveDecodeFile = document.getElementById('adaptive-decode-file');
const adaptiveDecodePassword = document.getElementById('adaptive-decode-password');
const adaptiveDecodeButton = document.getElementById('adaptive-decode-button');
const adaptiveDecodeStatus = document.getElementById('adaptive-decode-status');
const adaptiveDecodeVisualizer = document.getElementById('adaptive-decode-visualizer');
const adaptiveDecodeOutput = document.getElementById('adaptive-decode-output');

adaptiveDecodeButton.addEventListener('click', async () => {
  const file = adaptiveDecodeFile.files[0];
  const password = adaptiveDecodePassword.value;

  adaptiveDecodeOutput.value = '';

  if (!file) {
    setStatus(adaptiveDecodeStatus, 'Choose a PNG file to decode.', 'error');
    return;
  }
  if (!password) {
    setStatus(adaptiveDecodeStatus, 'Enter the passphrase used to encrypt the data.', 'error');
    return;
  }

  adaptiveDecodeButton.disabled = true;
  setStatus(adaptiveDecodeStatus, 'Reading image...', 'info');

  try {
    const img = await loadImageFile(file);
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    setStatus(adaptiveDecodeStatus, 'Extracting hidden payload...', 'info');
    const { salt, iv, ciphertext, mask, maskCols, maskRows, blockSize } = extractAdaptive(imageData);

    const overlay = renderMaskOverlay(canvas.width, canvas.height, blockSize, mask, maskCols, maskRows, 0);
    adaptiveDecodeVisualizer.width = canvas.width;
    adaptiveDecodeVisualizer.height = canvas.height;
    const vctx = adaptiveDecodeVisualizer.getContext('2d');
    vctx.drawImage(canvas, 0, 0);
    vctx.drawImage(overlay, 0, 0);
    adaptiveDecodeVisualizer.classList.remove('hidden');

    setStatus(adaptiveDecodeStatus, 'Decrypting...', 'info');
    const plaintext = await decryptToText(ciphertext, password, salt, iv);

    adaptiveDecodeOutput.value = plaintext;
    setStatus(adaptiveDecodeStatus, 'Decrypted successfully.', 'success');
  } catch (err) {
    console.error(err);
    setStatus(
      adaptiveDecodeStatus,
      `Error: ${err.message || 'Incorrect passphrase or corrupted image.'}`,
      'error'
    );
  } finally {
    adaptiveDecodeButton.disabled = false;
  }
});
