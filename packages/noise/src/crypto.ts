/**
 * Cryptographic primitives for Noise Protocol.
 *
 * Wraps @noble/* libraries to provide the DH, AEAD, and Hash
 * functions required by the Noise spec (Section 4).
 *
 * Protocol: Noise_*_25519_ChaChaPoly_BLAKE2b
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { blake2b } from '@noble/hashes/blake2.js';

// ── Constants ────────────────────────────────────────────────────────────────

/** Curve25519 DH output and key length (32 bytes). */
export const DHLEN = 32;

/** BLAKE2b hash output length (64 bytes). */
export const HASHLEN = 64;

/** BLAKE2b block size (128 bytes). Used for HMAC. */
export const BLOCKLEN = 128;

/** ChaCha20-Poly1305 AEAD tag length (16 bytes). */
export const TAG_LEN = 16;

/** Maximum Noise message size (65535 bytes). */
export const MAX_MESSAGE_LEN = 65535;

/** Maximum nonce value before rekey is required. */
export const MAX_NONCE = 2n ** 64n - 1n;

/** Empty byte array, used as default AD. */
export const EMPTY = new Uint8Array(0);

// ── DH Functions (Section 4.1: 25519) ────────────────────────────────────────

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate an X25519 keypair. */
export function generateKeypair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** Perform X25519 DH. Returns 32-byte shared secret. */
export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/** Get the public key for a private key. */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

// ── Cipher Functions (Section 4.2: ChaChaPoly) ──────────────────────────────

/**
 * AEAD encrypt with ChaCha20-Poly1305.
 * Nonce is 4 zero bytes + 8-byte little-endian counter (per Noise spec Section 4).
 */
export function encrypt(
  key: Uint8Array,
  nonce: bigint,
  ad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const n = nonceToBytes(nonce);
  const cipher = chacha20poly1305(key, n, ad);
  return cipher.encrypt(plaintext);
}

/**
 * AEAD decrypt with ChaCha20-Poly1305.
 * Returns plaintext or throws on auth failure.
 */
export function decrypt(
  key: Uint8Array,
  nonce: bigint,
  ad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const n = nonceToBytes(nonce);
  const cipher = chacha20poly1305(key, n, ad);
  return cipher.decrypt(ciphertext);
}

/** Convert a 64-bit nonce to the 12-byte format: 4 zero bytes + 8-byte LE. */
function nonceToBytes(n: bigint): Uint8Array {
  const buf = new Uint8Array(12);
  // First 4 bytes are zero (per Noise spec for ChaChaPoly)
  // Next 8 bytes are little-endian nonce
  let val = n;
  for (let i = 4; i < 12; i++) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return buf;
}

// ── Hash Functions (Section 4.3: BLAKE2b) ────────────────────────────────────

/** BLAKE2b hash (64 bytes output). */
export function hash(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: HASHLEN });
}

/**
 * HMAC-BLAKE2b.
 *
 * HMAC(key, data) = HASH(opad || HASH(ipad || data))
 * where ipad = key XOR 0x36, opad = key XOR 0x5c
 *
 * Note: We use HKDF from @noble/hashes which handles HMAC internally,
 * but we need raw HMAC for the Noise HKDF construction.
 */
export function hmacBlake2b(key: Uint8Array, data: Uint8Array): Uint8Array {
  // Pad or hash the key to BLOCKLEN
  let paddedKey: Uint8Array;
  if (key.length > BLOCKLEN) {
    paddedKey = new Uint8Array(BLOCKLEN);
    paddedKey.set(hash(key));
  } else {
    paddedKey = new Uint8Array(BLOCKLEN);
    paddedKey.set(key);
  }

  const ipad = new Uint8Array(BLOCKLEN);
  const opad = new Uint8Array(BLOCKLEN);
  for (let i = 0; i < BLOCKLEN; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  // HASH(ipad || data)
  const inner = hash(concat(ipad, data));
  // HASH(opad || inner)
  return hash(concat(opad, inner));
}

/**
 * HKDF per Noise spec (Section 4.3).
 *
 * HKDF(chaining_key, input_key_material, num_outputs):
 *   temp_key = HMAC-HASH(chaining_key, input_key_material)
 *   output1 = HMAC-HASH(temp_key, byte(0x01))
 *   output2 = HMAC-HASH(temp_key, output1 || byte(0x02))
 *   output3 = HMAC-HASH(temp_key, output2 || byte(0x03))  // if num_outputs == 3
 *
 * Returns [output1, output2] or [output1, output2, output3].
 */
export function noiseHkdf(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array,
  numOutputs: 2 | 3,
): Uint8Array[] {
  const tempKey = hmacBlake2b(chainingKey, inputKeyMaterial);
  const output1 = hmacBlake2b(tempKey, new Uint8Array([0x01]));
  const output2 = hmacBlake2b(tempKey, concat(output1, new Uint8Array([0x02])));

  if (numOutputs === 2) {
    return [output1, output2];
  }

  const output3 = hmacBlake2b(tempKey, concat(output2, new Uint8Array([0x03])));
  return [output1, output2, output3];
}

// ── Utilities ────────────────────────────────────────────────────────────────

/** Concatenate byte arrays. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Truncate a byte array to the given length. */
export function truncate(data: Uint8Array, length: number): Uint8Array {
  return data.slice(0, length);
}
