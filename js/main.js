import { encryptBytes, decryptBytes } from './crypto.js';
import { packPayload, unpackPayload } from './filePacking.js';
import { buildPacket, computeCanvasDimensions, embedPacket, extractPacket } from './steganography.js';
import { renderShaderCanvas } from './shaderRenderer.js';
import { renderMaskOverlay } from './complexity.js';
import { scoreCarrier, buildAnalysis, embedAdaptive, extractAdaptive } from './steganographyV2.js';

// Practical safety cap: a WebGL2/2D canvas this large is at the edge of what
// browsers reliably allocate, and gets slow well before that. Payloads that
// would need a bigger carrier are rejected with a clear error instead of
// hanging the tab.
const MAX_CANVAS_DIMENSION = 4096;

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function readFileAsBytes(file) {
  const buffer = await file.arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Wires a drag-and-drop + click-to-browse file zone, an attached-file info
 * chip with a "Remove" button, and (optionally) a text area that gets
 * disabled while a file is attached. Returns { getFile } so callers can read
 * the currently attached File (or null) at submit time.
 */
function createFileDropzone({ dropzoneId, inputId, infoId, nameId, sizeId, clearId, textareaEl, onChange }) {
  const dropzone = document.getElementById(dropzoneId);
  const input = document.getElementById(inputId);
  const info = document.getElementById(infoId);
  const nameEl = document.getElementById(nameId);
  const sizeEl = document.getElementById(sizeId);
  const clearButton = document.getElementById(clearId);

  let selectedFile = null;
  const defaultPlaceholder = textareaEl ? textareaEl.placeholder : '';

  function setFile(file) {
    selectedFile = file || null;
    if (selectedFile) {
      nameEl.textContent = selectedFile.name;
      sizeEl.textContent = formatFileSize(selectedFile.size);
      info.classList.remove('hidden');
      if (textareaEl) {
        textareaEl.disabled = true;
        textareaEl.placeholder = 'A file is attached below instead.';
      }
    } else {
      info.classList.add('hidden');
      if (textareaEl) {
        textareaEl.disabled = false;
        textareaEl.placeholder = defaultPlaceholder;
      }
    }
    if (onChange) onChange(selectedFile);
  }

  input.addEventListener('change', () => setFile(input.files[0] || null));

  clearButton.addEventListener('click', () => {
    input.value = '';
    setFile(null);
  });

  ['dragover', 'dragenter'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });
  ['dragleave', 'dragend'].forEach((evt) => {
    dropzone.addEventListener(evt, () => dropzone.classList.remove('dragover'));
  });
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
  });

  return { getFile: () => selectedFile };
}

/**
 * Renders a decrypted+unpacked payload: plain text goes into the textarea,
 * anything else becomes a downloadable Blob (with the original name and
 * MIME type) behind a "Download Extracted File" link.
 */
function displayDecodedPayload({ bytes, name, type, textarea, label, fileResult, fileResultInfo, downloadLink: dlLink }) {
  const mimeType = type || 'application/octet-stream';

  if (dlLink._objectUrl) {
    URL.revokeObjectURL(dlLink._objectUrl);
    dlLink._objectUrl = null;
  }

  if (mimeType.startsWith('text/')) {
    label.classList.remove('hidden');
    textarea.classList.remove('hidden');
    textarea.value = new TextDecoder().decode(bytes);
    fileResult.classList.add('hidden');
  } else {
    label.classList.add('hidden');
    textarea.classList.add('hidden');
    textarea.value = '';

    const blob = new Blob([bytes], { type: mimeType });
    const url = URL.createObjectURL(blob);
    dlLink._objectUrl = url;
    dlLink.href = url;
    dlLink.download = name || 'extracted-file';
    fileResultInfo.textContent = `${name || 'extracted-file'} — ${formatFileSize(bytes.length)} — ${mimeType}`;
    fileResult.classList.remove('hidden');
  }
}

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
const encodeCapacityHint = document.getElementById('encode-capacity-hint');

function setStatus(el, message, kind = 'info') {
  el.textContent = message;
  el.className = `status status-${kind}`;
}

function updateEncodeCapacityHint() {
  const file = encodeFileInput.getFile();
  const approxBytes = file ? file.size : new TextEncoder().encode(encodeText.value).length;

  if (approxBytes === 0) {
    encodeCapacityHint.classList.add('hidden');
    return;
  }

  // Rough overhead estimate (metadata header + AES-GCM tag + outer packet
  // header); the real check at encode time uses the exact packed size.
  const { width, height } = computeCanvasDimensions(approxBytes + 100);
  const tooBig = width > MAX_CANVAS_DIMENSION || height > MAX_CANVAS_DIMENSION;

  encodeCapacityHint.textContent = tooBig
    ? `This payload (~${formatFileSize(approxBytes)}) would need a carrier larger than ${MAX_CANVAS_DIMENSION}x${MAX_CANVAS_DIMENSION}px, past the practical LSB storage limit. Use a smaller file.`
    : `Estimated carrier image size: ${width} x ${height}px.`;
  encodeCapacityHint.classList.toggle('capacity-warning', tooBig);
  encodeCapacityHint.classList.remove('hidden');
}

const encodeFileInput = createFileDropzone({
  dropzoneId: 'encode-dropzone',
  inputId: 'encode-file',
  infoId: 'encode-file-info',
  nameId: 'encode-file-name',
  sizeId: 'encode-file-size',
  clearId: 'encode-file-clear',
  textareaEl: encodeText,
  onChange: updateEncodeCapacityHint,
});
encodeText.addEventListener('input', updateEncodeCapacityHint);

encodeButton.addEventListener('click', async () => {
  const text = encodeText.value;
  const password = encodePassword.value;
  const file = encodeFileInput.getFile();

  if (!file && !text.trim()) {
    setStatus(encodeStatus, 'Enter some text or attach a file to hide.', 'error');
    return;
  }
  if (!password) {
    setStatus(encodeStatus, 'Enter a passphrase to encrypt the data.', 'error');
    return;
  }

  encodeButton.disabled = true;
  downloadLink.classList.add('hidden');
  encodePreview.classList.add('hidden');
  setStatus(encodeStatus, 'Preparing payload...', 'info');

  try {
    let payloadBytes, name, type;
    if (file) {
      payloadBytes = await readFileAsBytes(file);
      name = file.name;
      type = file.type || 'application/octet-stream';
    } else {
      payloadBytes = new TextEncoder().encode(text);
      name = 'message.txt';
      type = 'text/plain';
    }
    const packed = packPayload(payloadBytes, name, type);

    setStatus(encodeStatus, 'Encrypting data...', 'info');
    const { salt, iv, ciphertext } = await encryptBytes(packed, password);
    const packet = buildPacket(salt, iv, ciphertext);

    const { width, height } = computeCanvasDimensions(packet.length);
    if (width > MAX_CANVAS_DIMENSION || height > MAX_CANVAS_DIMENSION) {
      throw new Error(
        `This payload needs a ${width}x${height} carrier, past the practical ` +
          `${MAX_CANVAS_DIMENSION}x${MAX_CANVAS_DIMENSION}px LSB storage limit. Use a smaller file.`
      );
    }

    setStatus(encodeStatus, 'Generating carrier image...', 'info');
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
const decodeOutputLabel = document.getElementById('decode-output-label');
const decodeFileResult = document.getElementById('decode-file-result');
const decodeFileResultInfo = document.getElementById('decode-file-result-info');
const decodeDownloadLink = document.getElementById('decode-download-link');

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
  decodeFileResult.classList.add('hidden');

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
    const packed = await decryptBytes(ciphertext, password, salt, iv);
    const { name, type, bytes } = unpackPayload(packed);

    displayDecodedPayload({
      bytes,
      name,
      type,
      textarea: decodeOutput,
      label: decodeOutputLabel,
      fileResult: decodeFileResult,
      fileResultInfo: decodeFileResultInfo,
      downloadLink: decodeDownloadLink,
    });

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
const adaptiveEncodeCapacityHint = document.getElementById('adaptive-encode-capacity-hint');

let adaptiveScored = null; // expensive Sobel/block-score pass, cached per carrier + block size
let adaptiveAnalysis = null; // cheap threshold-derived mask, cached per slider position

function formatBits(bits) {
  return `${bits} bits (${(bits / 8).toFixed(0)} bytes)`;
}

function updateAdaptivePayloadCapacityHint() {
  const file = adaptiveEncodeFileInput.getFile();
  const approxBytes = file ? file.size : new TextEncoder().encode(adaptiveEncodeText.value).length;

  if (!adaptiveAnalysis || approxBytes === 0) {
    adaptiveEncodeCapacityHint.classList.add('hidden');
    return;
  }

  // Rough overhead estimate (metadata header + AES-GCM tag); the real check
  // at embed time uses the exact packed+encrypted ciphertext length.
  const neededBits = (approxBytes + 60) * 8;
  const available = adaptiveAnalysis.adaptiveCapacityBits;
  const tooBig = neededBits > available;

  adaptiveEncodeCapacityHint.textContent = tooBig
    ? `Payload (~${formatFileSize(approxBytes)}) likely exceeds the ${formatBits(available)} available at this threshold. Lower the threshold, use a bigger/more complex carrier, or a smaller file.`
    : `Payload (~${formatFileSize(approxBytes)}) fits within the ${formatBits(available)} available at this threshold.`;
  adaptiveEncodeCapacityHint.classList.toggle('capacity-warning', tooBig);
  adaptiveEncodeCapacityHint.classList.remove('hidden');
}

const adaptiveEncodeFileInput = createFileDropzone({
  dropzoneId: 'adaptive-encode-dropzone',
  inputId: 'adaptive-encode-file',
  infoId: 'adaptive-encode-file-info',
  nameId: 'adaptive-encode-file-name',
  sizeId: 'adaptive-encode-file-size',
  clearId: 'adaptive-encode-file-clear',
  textareaEl: adaptiveEncodeText,
  onChange: updateAdaptivePayloadCapacityHint,
});
adaptiveEncodeText.addEventListener('input', updateAdaptivePayloadCapacityHint);

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

  updateAdaptivePayloadCapacityHint();
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
  const file = adaptiveEncodeFileInput.getFile();

  if (!adaptiveAnalysis) {
    setStatus(adaptiveEncodeStatus, 'Load or generate a carrier image first.', 'error');
    return;
  }
  if (!file && !text.trim()) {
    setStatus(adaptiveEncodeStatus, 'Enter some text or attach a file to hide.', 'error');
    return;
  }
  if (!password) {
    setStatus(adaptiveEncodeStatus, 'Enter a passphrase to encrypt the data.', 'error');
    return;
  }

  adaptiveEncodeButton.disabled = true;
  adaptiveDownloadLink.classList.add('hidden');
  adaptiveEncodePreview.classList.add('hidden');
  setStatus(adaptiveEncodeStatus, 'Preparing payload...', 'info');

  try {
    let payloadBytes, name, type;
    if (file) {
      payloadBytes = await readFileAsBytes(file);
      name = file.name;
      type = file.type || 'application/octet-stream';
    } else {
      payloadBytes = new TextEncoder().encode(text);
      name = 'message.txt';
      type = 'text/plain';
    }
    const packed = packPayload(payloadBytes, name, type);

    setStatus(adaptiveEncodeStatus, 'Encrypting and embedding...', 'info');
    const { salt, iv, ciphertext } = await encryptBytes(packed, password);

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
const adaptiveDecodeOutputLabel = document.getElementById('adaptive-decode-output-label');
const adaptiveDecodeFileResult = document.getElementById('adaptive-decode-file-result');
const adaptiveDecodeFileResultInfo = document.getElementById('adaptive-decode-file-result-info');
const adaptiveDecodeDownloadLink = document.getElementById('adaptive-decode-download-link');

adaptiveDecodeButton.addEventListener('click', async () => {
  const file = adaptiveDecodeFile.files[0];
  const password = adaptiveDecodePassword.value;

  adaptiveDecodeOutput.value = '';
  adaptiveDecodeFileResult.classList.add('hidden');

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
    const packed = await decryptBytes(ciphertext, password, salt, iv);
    const { name, type, bytes } = unpackPayload(packed);

    displayDecodedPayload({
      bytes,
      name,
      type,
      textarea: adaptiveDecodeOutput,
      label: adaptiveDecodeOutputLabel,
      fileResult: adaptiveDecodeFileResult,
      fileResultInfo: adaptiveDecodeFileResultInfo,
      downloadLink: adaptiveDecodeDownloadLink,
    });

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
