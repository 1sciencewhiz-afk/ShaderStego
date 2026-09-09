// AES-GCM encryption with PBKDF2 key derivation, using the Web Crypto API.
// Payload bytes are gzip-compressed before encryption (and decompressed
// after decryption) via the Compression Streams API, so compressible
// payloads (text, source code, many document formats) need fewer LSB slots
// in the carrier image. Already-compressed formats (JPEG, MP3, ZIP) simply
// pass through with a small (~20-byte) gzip framing overhead.

export const SALT_LENGTH = 16; // bytes
export const IV_LENGTH = 12; // bytes, recommended size for AES-GCM
const PBKDF2_ITERATIONS = 250000;

/** Pipe `bytes` through a Compression/DecompressionStream and collect the result. */
async function pipeThroughStream(bytes, streamCtor) {
  const stream = new Blob([bytes]).stream().pipeThrough(new streamCtor('gzip'));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

async function gzipCompress(bytes) {
  return pipeThroughStream(bytes, CompressionStream);
}

async function gzipDecompress(bytes) {
  return pipeThroughStream(bytes, DecompressionStream);
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase and salt via PBKDF2-SHA256.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {'encrypt'|'decrypt'} usage
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(passphrase, salt, usage) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

/**
 * Compress then encrypt raw bytes with a passphrase, generating a fresh
 * random salt and IV. This is the core binary primitive — text and
 * packed-file payloads both funnel through here as plain Uint8Array data.
 * @param {Uint8Array} plaintextBytes
 * @param {string} passphrase
 * @returns {Promise<{salt: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array}>}
 */
export async function encryptBytes(plaintextBytes, passphrase) {
  const compressed = await gzipCompress(plaintextBytes);

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt, 'encrypt');

  const ciphertextBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, compressed);

  return { salt, iv, ciphertext: new Uint8Array(ciphertextBuffer) };
}

/**
 * Decrypt then decompress a ciphertext given the passphrase, salt, and IV
 * used to encrypt it, returning the raw plaintext bytes. Throws if the
 * passphrase is wrong or the data has been tampered with (AES-GCM
 * authentication failure).
 * @param {Uint8Array} ciphertext
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {Uint8Array} iv
 * @returns {Promise<Uint8Array>}
 */
export async function decryptBytes(ciphertext, passphrase, salt, iv) {
  const key = await deriveKey(passphrase, salt, 'decrypt');
  const compressedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return gzipDecompress(new Uint8Array(compressedBuffer));
}
