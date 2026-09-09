// Wraps arbitrary payload bytes (text or a binary file) with a small
// metadata header before encryption, so the decoder can reconstruct the
// original file name and MIME type after decrypting.
//
// Structure: [2-byte big-endian header length] + [JSON metadata] + [raw bytes]

const HEADER_LENGTH_FIELD_SIZE = 2;
const MAX_HEADER_LENGTH = 0xffff;

/**
 * Pack `bytes` behind a JSON metadata header describing the payload.
 * @param {Uint8Array} bytes
 * @param {string} name - file name, e.g. "photo.png" or "message.txt"
 * @param {string} type - MIME type, e.g. "image/png" or "text/plain"
 * @returns {Uint8Array}
 */
export function packPayload(bytes, name, type) {
  const metadataJson = JSON.stringify({ name, type });
  const metadataBytes = new TextEncoder().encode(metadataJson);

  if (metadataBytes.length > MAX_HEADER_LENGTH) {
    throw new Error('File name/type metadata is too large to encode.');
  }

  const packed = new Uint8Array(HEADER_LENGTH_FIELD_SIZE + metadataBytes.length + bytes.length);
  const view = new DataView(packed.buffer);
  view.setUint16(0, metadataBytes.length, false);
  packed.set(metadataBytes, HEADER_LENGTH_FIELD_SIZE);
  packed.set(bytes, HEADER_LENGTH_FIELD_SIZE + metadataBytes.length);

  return packed;
}

/**
 * Inverse of packPayload: split `packed` back into metadata and raw bytes.
 * @param {Uint8Array} packed
 * @returns {{name: string, type: string, bytes: Uint8Array}}
 */
export function unpackPayload(packed) {
  if (packed.length < HEADER_LENGTH_FIELD_SIZE) {
    throw new Error('Decrypted data is too short to contain file metadata.');
  }

  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  const metadataLength = view.getUint16(0, false);

  const metadataStart = HEADER_LENGTH_FIELD_SIZE;
  const metadataEnd = metadataStart + metadataLength;
  if (metadataEnd > packed.length) {
    throw new Error('Decrypted data is corrupted (metadata header overruns payload).');
  }

  const metadataBytes = packed.subarray(metadataStart, metadataEnd);
  let metadata;
  try {
    metadata = JSON.parse(new TextDecoder().decode(metadataBytes));
  } catch {
    throw new Error('Decrypted data is corrupted (invalid metadata JSON).');
  }

  const bytes = packed.subarray(metadataEnd);
  return { name: metadata.name, type: metadata.type, bytes };
}
