/**
 * High-level Noise Protocol session API.
 *
 * Provides a clean interface for creating and using Noise sessions
 * without needing to understand the internal state machine.
 */

import { z } from 'zod';
import { HandshakeState, type HandshakeConfig, type Role } from './handshake-state.js';
import { NoiseTransport } from './transport.js';
import { CipherState } from './cipher-state.js';
import { type HandshakePattern, NK, XX, PATTERNS } from './patterns.js';
import { type KeyPair, generateKeypair, EMPTY } from './crypto.js';

// ── Schemas ──────────────────────────────────────────────────────────────────

export const NoiseSessionConfigSchema = z.object({
  /** Pattern name: "NK" or "XX". */
  pattern: z.enum(['NK', 'XX']),
  /** Role in the handshake. */
  role: z.enum(['initiator', 'responder']),
  /** This party's static keypair (required for responder in NK, both in XX). */
  staticKeypair: z.object({
    publicKey: z.instanceof(Uint8Array),
    privateKey: z.instanceof(Uint8Array),
  }).optional(),
  /** Remote party's static public key (required for initiator in NK). */
  remoteStaticKey: z.instanceof(Uint8Array).optional(),
  /** Optional prologue data. */
  prologue: z.instanceof(Uint8Array).optional(),
  /** Pre-generated ephemeral keypair (for testing only). */
  ephemeralKeypair: z.object({
    publicKey: z.instanceof(Uint8Array),
    privateKey: z.instanceof(Uint8Array),
  }).optional(),
});

export type NoiseSessionConfig = z.infer<typeof NoiseSessionConfigSchema>;

/** State of a Noise session. */
export type SessionState = 'handshake' | 'transport' | 'error';

/**
 * A Noise Protocol session.
 *
 * Usage:
 *   1. Create session with config
 *   2. Exchange handshake messages (writeHandshake / readHandshake)
 *   3. Once handshake completes, use encrypt/decrypt for transport
 *
 * Example (NK initiator):
 *   const session = NoiseSession.create({
 *     pattern: 'NK',
 *     role: 'initiator',
 *     remoteStaticKey: serverPublicKey,
 *   });
 *   const msg1 = session.writeHandshake(requestPayload);  // → send to server
 *   session.readHandshake(serverResponse);                 // ← from server
 *   // Now in transport mode
 *   const encrypted = session.encrypt(data);
 *   const decrypted = session.decrypt(incoming);
 */
export class NoiseSession {
  private handshakeState: HandshakeState | null;
  private transport: NoiseTransport | null;
  private _state: SessionState;
  private role: Role;

  private constructor(config: HandshakeConfig) {
    this.role = config.role;
    this.handshakeState = new HandshakeState(config);
    this.transport = null;
    this._state = 'handshake';
  }

  /** Create a new Noise session. */
  static create(config: NoiseSessionConfig): NoiseSession {
    const parsed = NoiseSessionConfigSchema.parse(config);
    const pattern = PATTERNS[parsed.pattern];
    if (!pattern) {
      throw new Error(`Unknown pattern: ${parsed.pattern}`);
    }

    const handshakeConfig: HandshakeConfig = {
      pattern,
      role: parsed.role as Role,
      prologue: parsed.prologue,
      s: parsed.staticKeypair,
      e: parsed.ephemeralKeypair,
      rs: parsed.remoteStaticKey,
    };

    return new NoiseSession(handshakeConfig);
  }

  /** Current session state. */
  get state(): SessionState {
    return this._state;
  }

  /**
   * Write the next handshake message.
   * Returns the message bytes to send to the remote party.
   */
  writeHandshake(payload: Uint8Array = EMPTY): Uint8Array {
    if (this._state !== 'handshake' || !this.handshakeState) {
      throw new Error(`Cannot write handshake in state: ${this._state}`);
    }

    const result = this.handshakeState.writeMessage(payload);

    if (result.cipherStates) {
      this.transitionToTransport(result.cipherStates, result.handshakeHash!);
    }

    return result.messageBuffer;
  }

  /**
   * Read the next handshake message from the remote party.
   * Returns the decrypted payload.
   */
  readHandshake(message: Uint8Array): Uint8Array {
    if (this._state !== 'handshake' || !this.handshakeState) {
      throw new Error(`Cannot read handshake in state: ${this._state}`);
    }

    const result = this.handshakeState.readMessage(message);

    if (result.cipherStates) {
      this.transitionToTransport(result.cipherStates, result.handshakeHash!);
    }

    return result.messageBuffer;
  }

  /** Transition from handshake to transport mode. */
  private transitionToTransport(
    cipherStates: [CipherState, CipherState],
    handshakeHash: Uint8Array,
  ): void {
    const [c1, c2] = cipherStates;
    // Split() returns [c1, c2] where:
    //   c1 = initiator→responder cipher
    //   c2 = responder→initiator cipher
    const [sendCipher, recvCipher] =
      this.role === 'initiator' ? [c1, c2] : [c2, c1];

    this.transport = new NoiseTransport(sendCipher, recvCipher, handshakeHash);
    this.handshakeState = null;
    this._state = 'transport';
  }

  /**
   * Encrypt a transport message.
   * For small payloads (< 65519 bytes), returns a single AEAD ciphertext.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot encrypt in state: ${this._state}`);
    }
    return this.transport.encrypt(plaintext);
  }

  /**
   * Decrypt a transport message.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot decrypt in state: ${this._state}`);
    }
    return this.transport.decrypt(ciphertext);
  }

  /**
   * Encrypt a large payload with chunked framing.
   */
  encryptFramed(plaintext: Uint8Array): Uint8Array {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot encrypt in state: ${this._state}`);
    }
    return this.transport.encryptFramed(plaintext);
  }

  /**
   * Decrypt a framed payload.
   */
  decryptFramed(data: Uint8Array): Uint8Array {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot decrypt in state: ${this._state}`);
    }
    return this.transport.decryptFramed(data);
  }

  /**
   * Rekey the send direction.
   */
  rekeySend(): void {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot rekey in state: ${this._state}`);
    }
    this.transport.rekeySend();
  }

  /**
   * Rekey the receive direction.
   */
  rekeyRecv(): void {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error(`Cannot rekey in state: ${this._state}`);
    }
    this.transport.rekeyRecv();
  }

  /**
   * Get the handshake hash (channel binding value).
   * Available after handshake completes.
   */
  getHandshakeHash(): Uint8Array {
    if (this._state !== 'transport' || !this.transport) {
      throw new Error('Handshake hash only available after handshake');
    }
    return this.transport.getHandshakeHash();
  }
}
