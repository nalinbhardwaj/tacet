/**
 * Noise transport message encryption/decryption.
 *
 * After a handshake completes, the two CipherStates are used for
 * bidirectional encrypted communication. This module also handles
 * chunked framing for payloads exceeding 65535 bytes.
 *
 * Framing protocol:
 *   [2-byte BE length][Noise AEAD ciphertext (up to 65535 bytes)]
 *   [2-byte BE length][Noise AEAD ciphertext]
 *   ...
 *   [0x00 0x00]  (zero-length = end of payload)
 *
 * Each chunk is a separate Noise transport message with its own AEAD
 * tag and incrementing nonce.
 */

import { CipherState } from './cipher-state.js';
import { EMPTY, MAX_MESSAGE_LEN, TAG_LEN, concat } from './crypto.js';

/**
 * Maximum plaintext per chunk.
 * 65535 (max Noise message) - 16 (AEAD tag) = 65519 bytes.
 */
const MAX_PLAINTEXT_PER_CHUNK = MAX_MESSAGE_LEN - TAG_LEN;

/**
 * A NoiseTransport wraps the two CipherStates from a completed handshake.
 * It provides encrypt/decrypt for transport messages in both directions.
 */
export class NoiseTransport {
  private sendCipher: CipherState;
  private recvCipher: CipherState;
  private handshakeHash: Uint8Array;

  /**
   * @param sendCipher CipherState for encrypting outgoing messages.
   * @param recvCipher CipherState for decrypting incoming messages.
   * @param handshakeHash The handshake hash (channel binding value).
   */
  constructor(
    sendCipher: CipherState,
    recvCipher: CipherState,
    handshakeHash: Uint8Array,
  ) {
    this.sendCipher = sendCipher;
    this.recvCipher = recvCipher;
    this.handshakeHash = handshakeHash;
  }

  /**
   * Encrypt a single transport message (≤ MAX_PLAINTEXT_PER_CHUNK bytes).
   * Returns the AEAD ciphertext (plaintext + 16-byte tag).
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length > MAX_PLAINTEXT_PER_CHUNK) {
      throw new Error(
        `Plaintext too large for single message: ${plaintext.length} > ${MAX_PLAINTEXT_PER_CHUNK}. Use encryptFramed().`,
      );
    }
    return this.sendCipher.encryptWithAd(EMPTY, plaintext);
  }

  /**
   * Decrypt a single transport message.
   * Returns the plaintext.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return this.recvCipher.decryptWithAd(EMPTY, ciphertext);
  }

  /**
   * Encrypt a payload of arbitrary size using chunked framing.
   *
   * Returns a framed buffer:
   *   [2-byte BE length][ciphertext]
   *   [2-byte BE length][ciphertext]
   *   ...
   *   [0x00 0x00]
   */
  encryptFramed(plaintext: Uint8Array): Uint8Array {
    const parts: Uint8Array[] = [];
    let offset = 0;

    while (offset < plaintext.length) {
      const chunkSize = Math.min(
        plaintext.length - offset,
        MAX_PLAINTEXT_PER_CHUNK,
      );
      const chunk = plaintext.slice(offset, offset + chunkSize);
      const encrypted = this.sendCipher.encryptWithAd(EMPTY, chunk);

      // 2-byte big-endian length prefix
      const lenPrefix = new Uint8Array(2);
      lenPrefix[0] = (encrypted.length >> 8) & 0xff;
      lenPrefix[1] = encrypted.length & 0xff;

      parts.push(lenPrefix);
      parts.push(encrypted);

      offset += chunkSize;
    }

    // End-of-payload marker
    parts.push(new Uint8Array([0x00, 0x00]));

    return concat(...parts);
  }

  /**
   * Decrypt a framed payload.
   *
   * Reads chunks until a zero-length marker, decrypts each,
   * and concatenates the plaintext.
   */
  decryptFramed(data: Uint8Array): Uint8Array {
    const parts: Uint8Array[] = [];
    let offset = 0;

    while (offset < data.length) {
      if (offset + 2 > data.length) {
        throw new Error('Truncated frame: missing length prefix');
      }

      const len = (data[offset]! << 8) | data[offset + 1]!;
      offset += 2;

      if (len === 0) {
        // End-of-payload marker
        break;
      }

      if (offset + len > data.length) {
        throw new Error(`Truncated frame: expected ${len} bytes, got ${data.length - offset}`);
      }

      const chunk = data.slice(offset, offset + len);
      const decrypted = this.recvCipher.decryptWithAd(EMPTY, chunk);
      parts.push(decrypted);

      offset += len;
    }

    return concat(...parts);
  }

  /** Rekey the send cipher. */
  rekeySend(): void {
    this.sendCipher.rekey();
  }

  /** Rekey the receive cipher. */
  rekeyRecv(): void {
    this.recvCipher.rekey();
  }

  /** Get the handshake hash (channel binding value). */
  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.handshakeHash);
  }
}
