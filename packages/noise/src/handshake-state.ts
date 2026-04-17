/**
 * HandshakeState per Noise Protocol spec (Section 5.3).
 *
 * Manages the handshake flow: processes pattern tokens,
 * performs DH operations, and produces transport CipherStates.
 */

import { CipherState } from './cipher-state.js';
import { SymmetricState } from './symmetric-state.js';
import {
  type HandshakePattern,
  type MessagePattern,
  type Token,
} from './patterns.js';
import {
  type KeyPair,
  generateKeypair,
  dh,
  concat,
  DHLEN,
  EMPTY,
} from './crypto.js';

/** Role in the handshake (initiator sends first message). */
export type Role = 'initiator' | 'responder';

/** Configuration for initializing a HandshakeState. */
export interface HandshakeConfig {
  /** The handshake pattern to execute (NK, XX, etc.). */
  pattern: HandshakePattern;
  /** Whether this party is the initiator or responder. */
  role: Role;
  /** Optional prologue data (mixed into handshake hash). */
  prologue?: Uint8Array;
  /** This party's static keypair (if the pattern requires it). */
  s?: KeyPair;
  /** This party's ephemeral keypair (if pre-generated, otherwise auto-generated). */
  e?: KeyPair;
  /** Remote party's static public key (if known, e.g., NK pattern). */
  rs?: Uint8Array;
  /** Remote party's ephemeral public key (if known). */
  re?: Uint8Array;
}

/** Result of processing a handshake message. */
export interface HandshakeResult {
  /** The message bytes to send (for WriteMessage) or the decrypted payload (for ReadMessage). */
  messageBuffer: Uint8Array;
  /** If the handshake is complete, the two transport CipherStates. */
  cipherStates?: [CipherState, CipherState];
  /** If the handshake is complete, the handshake hash (channel binding). */
  handshakeHash?: Uint8Array;
}

/**
 * The protocol name for our Noise configuration.
 * Format: Noise_[Pattern]_25519_ChaChaPoly_BLAKE2b
 */
function protocolName(patternName: string): string {
  return `Noise_${patternName}_25519_ChaChaPoly_BLAKE2b`;
}

export class HandshakeState {
  private symmetricState: SymmetricState;
  private role: Role;
  private pattern: HandshakePattern;
  private messageIndex: number;

  // Local keypairs
  private s: KeyPair | undefined;
  private e: KeyPair | undefined;

  // Remote public keys
  private rs: Uint8Array | undefined;
  private re: Uint8Array | undefined;

  constructor(config: HandshakeConfig) {
    this.role = config.role;
    this.pattern = config.pattern;
    this.messageIndex = 0;

    this.s = config.s;
    this.e = config.e;
    this.rs = config.rs ? new Uint8Array(config.rs) : undefined;
    this.re = config.re ? new Uint8Array(config.re) : undefined;

    // Initialize symmetric state with protocol name
    this.symmetricState = new SymmetricState();
    this.symmetricState.initializeSymmetric(protocolName(config.pattern.name));

    // Mix in prologue
    this.symmetricState.mixHash(config.prologue ?? EMPTY);

    // Process pre-messages
    this.processPreMessages();
  }

  /** Process pre-message patterns (Section 5.3, Initialize). */
  private processPreMessages(): void {
    const pre = this.pattern.preMessages;

    // Initiator pre-message
    for (const token of pre.initiator) {
      if (token === 'e') {
        // Initiator's ephemeral is known
        const key = this.role === 'initiator' ? this.e!.publicKey : this.re!;
        this.symmetricState.mixHash(key);
      } else if (token === 's') {
        // Initiator's static is known
        const key = this.role === 'initiator' ? this.s!.publicKey : this.rs!;
        this.symmetricState.mixHash(key);
      }
    }

    // Responder pre-message
    for (const token of pre.responder) {
      if (token === 'e') {
        const key = this.role === 'responder' ? this.e!.publicKey : this.re!;
        this.symmetricState.mixHash(key);
      } else if (token === 's') {
        const key = this.role === 'responder' ? this.s!.publicKey : this.rs!;
        this.symmetricState.mixHash(key);
      }
    }
  }

  /** Check if it's this party's turn to write. */
  private isMyTurn(): boolean {
    // Even indices are initiator's turn, odd are responder's
    const isInitiatorTurn = this.messageIndex % 2 === 0;
    return this.role === 'initiator' ? isInitiatorTurn : !isInitiatorTurn;
  }

  /** Whether the handshake is complete. */
  isComplete(): boolean {
    return this.messageIndex >= this.pattern.messagePatterns.length;
  }

  /**
   * WriteMessage(payload): Process the next outgoing handshake message.
   *
   * Writes tokens according to the current message pattern, appends
   * the encrypted payload, and returns the message buffer.
   */
  writeMessage(payload: Uint8Array = EMPTY): HandshakeResult {
    if (this.isComplete()) {
      throw new Error('Handshake already complete');
    }
    if (!this.isMyTurn()) {
      throw new Error(`Not this party's turn to write (message ${this.messageIndex})`);
    }

    const messagePattern = this.pattern.messagePatterns[this.messageIndex]!;
    const parts: Uint8Array[] = [];

    for (const token of messagePattern) {
      this.processWriteToken(token, parts);
    }

    // Encrypt and append payload
    const encryptedPayload = this.symmetricState.encryptAndHash(payload);
    parts.push(encryptedPayload);

    this.messageIndex++;

    const messageBuffer = concat(...parts);

    // Check if handshake is complete
    if (this.isComplete()) {
      const [c1, c2] = this.symmetricState.split();
      return {
        messageBuffer,
        cipherStates: [c1, c2],
        handshakeHash: this.symmetricState.getHandshakeHash(),
      };
    }

    return { messageBuffer };
  }

  /**
   * ReadMessage(message): Process the next incoming handshake message.
   *
   * Reads tokens according to the current message pattern, decrypts
   * the payload, and returns it.
   */
  readMessage(message: Uint8Array): HandshakeResult {
    if (this.isComplete()) {
      throw new Error('Handshake already complete');
    }
    if (this.isMyTurn()) {
      throw new Error(`Not this party's turn to read (message ${this.messageIndex})`);
    }

    const messagePattern = this.pattern.messagePatterns[this.messageIndex]!;
    let offset = 0;

    for (const token of messagePattern) {
      offset = this.processReadToken(token, message, offset);
    }

    // Decrypt remaining bytes as payload
    const encryptedPayload = message.slice(offset);
    const payload = this.symmetricState.decryptAndHash(encryptedPayload);

    this.messageIndex++;

    // Check if handshake is complete
    if (this.isComplete()) {
      const [c1, c2] = this.symmetricState.split();
      return {
        messageBuffer: payload,
        cipherStates: [c1, c2],
        handshakeHash: this.symmetricState.getHandshakeHash(),
      };
    }

    return { messageBuffer: payload };
  }

  /** Process a single token during WriteMessage. */
  private processWriteToken(token: Token, parts: Uint8Array[]): void {
    switch (token) {
      case 'e': {
        // Generate ephemeral keypair if not pre-set
        if (!this.e) {
          this.e = generateKeypair();
        }
        parts.push(this.e.publicKey);
        this.symmetricState.mixHash(this.e.publicKey);
        break;
      }
      case 's': {
        // Encrypt and send static public key
        if (!this.s) {
          throw new Error('Static keypair required but not set');
        }
        const encrypted = this.symmetricState.encryptAndHash(this.s.publicKey);
        parts.push(encrypted);
        break;
      }
      case 'ee': {
        this.symmetricState.mixKey(dh(this.e!.privateKey, this.re!));
        break;
      }
      case 'es': {
        if (this.role === 'initiator') {
          this.symmetricState.mixKey(dh(this.e!.privateKey, this.rs!));
        } else {
          this.symmetricState.mixKey(dh(this.s!.privateKey, this.re!));
        }
        break;
      }
      case 'se': {
        if (this.role === 'initiator') {
          this.symmetricState.mixKey(dh(this.s!.privateKey, this.re!));
        } else {
          this.symmetricState.mixKey(dh(this.e!.privateKey, this.rs!));
        }
        break;
      }
      case 'ss': {
        this.symmetricState.mixKey(dh(this.s!.privateKey, this.rs!));
        break;
      }
    }
  }

  /** Process a single token during ReadMessage. Returns new offset. */
  private processReadToken(
    token: Token,
    message: Uint8Array,
    offset: number,
  ): number {
    switch (token) {
      case 'e': {
        // Read remote ephemeral public key
        this.re = message.slice(offset, offset + DHLEN);
        this.symmetricState.mixHash(this.re);
        return offset + DHLEN;
      }
      case 's': {
        // Read and decrypt remote static public key
        const hasKey = this.symmetricState.hasKey();
        const len = hasKey ? DHLEN + 16 : DHLEN; // +16 for AEAD tag if encrypted
        const encrypted = message.slice(offset, offset + len);
        this.rs = this.symmetricState.decryptAndHash(encrypted);
        return offset + len;
      }
      case 'ee': {
        this.symmetricState.mixKey(dh(this.e!.privateKey, this.re!));
        return offset;
      }
      case 'es': {
        if (this.role === 'initiator') {
          this.symmetricState.mixKey(dh(this.e!.privateKey, this.rs!));
        } else {
          this.symmetricState.mixKey(dh(this.s!.privateKey, this.re!));
        }
        return offset;
      }
      case 'se': {
        if (this.role === 'initiator') {
          this.symmetricState.mixKey(dh(this.s!.privateKey, this.re!));
        } else {
          this.symmetricState.mixKey(dh(this.e!.privateKey, this.rs!));
        }
        return offset;
      }
      case 'ss': {
        this.symmetricState.mixKey(dh(this.s!.privateKey, this.rs!));
        return offset;
      }
    }
  }

  /** Get the remote party's static public key (available after handshake in XX). */
  getRemoteStaticKey(): Uint8Array | undefined {
    return this.rs ? new Uint8Array(this.rs) : undefined;
  }

  /** Get the handshake hash (channel binding). */
  getHandshakeHash(): Uint8Array {
    return this.symmetricState.getHandshakeHash();
  }
}
