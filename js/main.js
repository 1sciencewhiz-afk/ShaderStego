import { encryptText, decryptToText } from './crypto.js';
import { buildPacket, computeCanvasDimensions, embedPacket, extractPacket } from './steganography.js';
import { renderShaderCanvas } from './shaderRenderer.js';

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
      downloadLink.download = 'shaderstego.png';
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
