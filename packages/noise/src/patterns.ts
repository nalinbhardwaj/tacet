/**
 * Noise Protocol handshake patterns (Section 7).
 *
 * Each pattern defines a sequence of message tokens that specify
 * which DH operations and key transmissions occur in each message.
 */

/** Handshake tokens that can appear in message patterns. */
export type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss';

/** A message pattern is a sequence of tokens. */
export type MessagePattern = Token[];

/** Pre-message pattern: keys known before the handshake. */
export interface PreMessage {
  /** Tokens for the initiator's pre-message (→). */
  initiator: Token[];
  /** Tokens for the responder's pre-message (←). */
  responder: Token[];
}

/** A complete handshake pattern. */
export interface HandshakePattern {
  /** Pattern name (e.g., "NK", "XX"). */
  name: string;
  /** Pre-message tokens (keys known before handshake). */
  preMessages: PreMessage;
  /** Sequence of message patterns (alternating initiator/responder). */
  messagePatterns: MessagePattern[];
}

/**
 * NK pattern: Client knows server's static key.
 *
 * Pre-messages:
 *   <- s              (server's static key known to client)
 *
 * Messages:
 *   -> e, es          (client sends ephemeral, DH with server static)
 *   <- e, ee          (server sends ephemeral, DH ephemeral-ephemeral)
 */
export const NK: HandshakePattern = {
  name: 'NK',
  preMessages: {
    initiator: [],
    responder: ['s'],
  },
  messagePatterns: [
    ['e', 'es'],  // → message 1 (initiator)
    ['e', 'ee'],  // ← message 2 (responder)
  ],
};

/**
 * XX pattern: Neither party knows the other's key.
 *
 * Pre-messages: (none)
 *
 * Messages:
 *   -> e              (client sends ephemeral)
 *   <- e, ee, s, es   (server sends ephemeral, DH, encrypted static, DH)
 *   -> s, se          (client sends encrypted static, DH)
 */
export const XX: HandshakePattern = {
  name: 'XX',
  preMessages: {
    initiator: [],
    responder: [],
  },
  messagePatterns: [
    ['e'],                // → message 1
    ['e', 'ee', 's', 'es'],  // ← message 2
    ['s', 'se'],          // → message 3
  ],
};

/** Map of pattern names to pattern definitions. */
export const PATTERNS: Record<string, HandshakePattern> = {
  NK,
  XX,
};
