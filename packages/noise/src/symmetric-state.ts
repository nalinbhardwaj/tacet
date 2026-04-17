/**
 * SymmetricState per Noise Protocol spec (Section 5.2).
 *
 * Maintains the chaining key (ck) and handshake hash (h).
 * Wraps a CipherState for encrypting/decrypting handshake payloads.
 */

import { CipherState } from './cipher-state.js';
import {
  hash,
  noiseHkdf,
  concat,
  HASHLEN,
  DHLEN,
  EMPTY,
  truncate,
} from './crypto.js';

export class SymmetricState {
  private ck: Uint8Array;
  private h: Uint8Array;
  private cipherState: CipherState;

  constructor() {
    this.ck = new Uint8Array(HASHLEN);
    this.h = new Uint8Array(HASHLEN);
    this.cipherState = new CipherState();
  }

  /**
   * InitializeSymmetric(protocol_name):
   * If protocol_name <= HASHLEN bytes, pad with zeros → h.
   * Otherwise h = HASH(protocol_name).
   * ck = h.
   */
  initializeSymmetric(protocolName: string): void {
    const nameBytes = new TextEncoder().encode(protocolName);

    if (nameBytes.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(nameBytes);
    } else {
      this.h = hash(nameBytes);
    }
    this.ck = new Uint8Array(this.h);
    this.cipherState = new CipherState();
  }

  /** MixKey(input_key_material): HKDF(ck, ikm) → new ck + cipher key. */
  mixKey(inputKeyMaterial: Uint8Array): void {
    const [ck, tempK] = noiseHkdf(this.ck, inputKeyMaterial, 2);
    this.ck = ck;
    this.cipherState.initializeKey(truncate(tempK, 32));
  }

  /** MixHash(data): h = HASH(h || data). */
  mixHash(data: Uint8Array): void {
    this.h = hash(concat(this.h, data));
  }

  /**
   * MixKeyAndHash(input_key_material):
   * HKDF(ck, ikm, 3) → new ck + temp_h (mixed into h) + cipher key.
   */
  mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    const [ck, tempH, tempK] = noiseHkdf(this.ck, inputKeyMaterial, 3);
    this.ck = ck;
    this.mixHash(tempH);
    this.cipherState.initializeKey(truncate(tempK, 32));
  }

  /** GetHandshakeHash(): Returns h (used as the channel binding after handshake). */
  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.h);
  }

  /**
   * EncryptAndHash(plaintext):
   * ciphertext = EncryptWithAd(h, plaintext)
   * h = HASH(h || ciphertext)
   * return ciphertext
   */
  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ciphertext = this.cipherState.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  /**
   * DecryptAndHash(ciphertext):
   * plaintext = DecryptWithAd(h, ciphertext)
   * h = HASH(h || ciphertext)
   * return plaintext
   */
  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const plaintext = this.cipherState.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  /**
   * Split(): Returns two CipherState objects for transport encryption.
   * HKDF(ck, "", 2) → (tempK1, tempK2)
   * c1 = CipherState(tempK1), c2 = CipherState(tempK2)
   */
  split(): [CipherState, CipherState] {
    const [tempK1, tempK2] = noiseHkdf(this.ck, EMPTY, 2);
    const c1 = new CipherState();
    c1.initializeKey(truncate(tempK1, 32));
    const c2 = new CipherState();
    c2.initializeKey(truncate(tempK2, 32));
    return [c1, c2];
  }

  /** Check if the cipher state has a key (handshake encryption active). */
  hasKey(): boolean {
    return this.cipherState.hasKey();
  }
}
