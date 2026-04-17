/**
 * CipherState per Noise Protocol spec (Section 5.1).
 *
 * Encapsulates a cipher key and nonce counter.
 * After a handshake completes, Split() produces two CipherStates
 * (one per direction) for transport encryption.
 */

import {
  encrypt as aeadEncrypt,
  decrypt as aeadDecrypt,
  EMPTY,
  MAX_NONCE,
  MAX_MESSAGE_LEN,
  TAG_LEN,
  noiseHkdf,
  HASHLEN,
  truncate,
} from './crypto.js';

export class CipherState {
  private k: Uint8Array | undefined;
  private n: bigint;

  constructor() {
    this.k = undefined;
    this.n = 0n;
  }

  /** InitializeKey(key): Sets k and resets n to 0. */
  initializeKey(key: Uint8Array | undefined): void {
    this.k = key;
    this.n = 0n;
  }

  /** HasKey(): Returns true if k is set. */
  hasKey(): boolean {
    return this.k !== undefined;
  }

  /** SetNonce(nonce): Sets the nonce. */
  setNonce(nonce: bigint): void {
    this.n = nonce;
  }

  /**
   * EncryptWithAd(ad, plaintext): If k is set, encrypts plaintext
   * with associated data and increments nonce. Otherwise returns plaintext.
   */
  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (this.k === undefined) {
      return plaintext;
    }
    if (this.n >= MAX_NONCE) {
      throw new Error('Nonce overflow: maximum nonce value exceeded');
    }
    const ciphertext = aeadEncrypt(this.k, this.n, ad, plaintext);
    this.n += 1n;
    return ciphertext;
  }

  /**
   * DecryptWithAd(ad, ciphertext): If k is set, decrypts ciphertext
   * with associated data and increments nonce. Otherwise returns ciphertext.
   */
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (this.k === undefined) {
      return ciphertext;
    }
    if (this.n >= MAX_NONCE) {
      throw new Error('Nonce overflow: maximum nonce value exceeded');
    }
    const plaintext = aeadDecrypt(this.k, this.n, ad, ciphertext);
    this.n += 1n;
    return plaintext;
  }

  /**
   * Rekey(): Sets k = REKEY(k).
   * Per Noise spec: REKEY(k) = EncryptWithAd(k, maxnonce, "", zeros(32))
   * where maxnonce = 2^64 - 1.
   */
  rekey(): void {
    if (this.k === undefined) {
      throw new Error('Cannot rekey: no key set');
    }
    const zeros = new Uint8Array(32);
    this.k = truncate(aeadEncrypt(this.k, MAX_NONCE, EMPTY, zeros), 32);
  }

  /** Get the current nonce value (for testing/debugging). */
  getNonce(): bigint {
    return this.n;
  }
}
