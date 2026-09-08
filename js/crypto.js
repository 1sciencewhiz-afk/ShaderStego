// AES-GCM encryption with PBKDF2 key derivation, using the Web Crypto API.

export const SALT_LENGTH = 16; // bytes
export const IV_LENGTH = 12; // bytes, recommended size for AES-GCM
const PBKDF2_ITERATIONS = 250000;

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
 * Encrypt plaintext with a passphrase, generating a fresh random salt and IV.
 * @param {string} plaintext
 * @param {string} passphrase
 * @returns {Promise<{salt: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array}>}
 */
export async function encryptText(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt, 'encrypt');

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );

  return { salt, iv, ciphertext: new Uint8Array(ciphertextBuffer) };
}

/**
 * Decrypt a ciphertext given the passphrase, salt, and IV used to encrypt it.
 * Throws if the passphrase is wrong or the data has been tampered with
 * (AES-GCM authentication failure).
 * @param {Uint8Array} ciphertext
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {Uint8Array} iv
 * @returns {Promise<string>}
 */
export async function decryptToText(ciphertext, passphrase, salt, iv) {
  const key = await deriveKey(passphrase, salt, 'decrypt');
  const plaintextBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintextBuffer);
}
