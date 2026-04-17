/**
 * @tacet/noise — Noise Protocol implementation for Tacet.
 *
 * Protocol: Noise_[NK|XX]_25519_ChaChaPoly_BLAKE2b
 *
 * @example
 * ```ts
 * import { NoiseSession, generateKeypair } from '@tacet/noise';
 *
 * // Server generates static keypair
 * const serverKeys = generateKeypair();
 *
 * // Client creates NK session (knows server's public key)
 * const client = NoiseSession.create({
 *   pattern: 'NK',
 *   role: 'initiator',
 *   remoteStaticKey: serverKeys.publicKey,
 * });
 *
 * // Server creates NK session
 * const server = NoiseSession.create({
 *   pattern: 'NK',
 *   role: 'responder',
 *   staticKeypair: serverKeys,
 * });
 *
 * // Handshake
 * const msg1 = client.writeHandshake();
 * server.readHandshake(msg1);
 * const msg2 = server.writeHandshake();
 * client.readHandshake(msg2);
 *
 * // Transport
 * const encrypted = client.encrypt(new TextEncoder().encode('hello'));
 * const decrypted = server.decrypt(encrypted);
 * ```
 */

// High-level API
export { NoiseSession, NoiseSessionConfigSchema } from './session.js';
export type { NoiseSessionConfig, SessionState } from './session.js';

// Patterns
export { NK, XX, PATTERNS } from './patterns.js';
export type { HandshakePattern, Token, MessagePattern, PreMessage } from './patterns.js';

// Low-level building blocks (for advanced usage / testing)
export { HandshakeState } from './handshake-state.js';
export type { HandshakeConfig, HandshakeResult, Role } from './handshake-state.js';
export { CipherState } from './cipher-state.js';
export { SymmetricState } from './symmetric-state.js';
export { NoiseTransport } from './transport.js';

// Crypto utilities
export { generateKeypair, getPublicKey } from './crypto.js';
export type { KeyPair } from './crypto.js';
export { DHLEN, HASHLEN, TAG_LEN, MAX_MESSAGE_LEN } from './crypto.js';
