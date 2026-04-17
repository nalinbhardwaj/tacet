/**
 * Tests against external test vectors from multiple sources:
 * - cacophony (haskell-cryptography/cacophony)
 * - snow (mcginty/snow — Rust implementation)
 * - noise-c (rweather/noise-c — C implementation)
 *
 * These validate that our implementation produces the exact same
 * ciphertext/handshake hash as other known-good implementations.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HandshakeState } from '../src/handshake-state.js';
import { NK, XX } from '../src/patterns.js';
import { getPublicKey } from '../src/crypto.js';
import type { KeyPair } from '../src/crypto.js';
import type { HandshakePattern } from '../src/patterns.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function hex(s: string): Uint8Array {
  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    bytes[i / 2] = parseInt(s.substring(i, i + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface TestVector {
  protocol_name: string;
  init_prologue: string;
  init_static?: string;
  init_ephemeral: string;
  init_remote_static?: string;
  resp_prologue: string;
  resp_static?: string;
  resp_ephemeral: string;
  resp_remote_static?: string;
  handshake_hash: string;
  messages: Array<{
    payload: string;
    ciphertext: string;
  }>;
  _source?: string;
}

function keypairFromPrivate(privateKeyHex: string): KeyPair {
  const privateKey = hex(privateKeyHex);
  const publicKey = getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function getPattern(name: string): HandshakePattern {
  if (name.includes('_NK_')) return NK;
  if (name.includes('_XX_')) return XX;
  throw new Error(`Unknown pattern in: ${name}`);
}

function getNumHandshakeMessages(pattern: HandshakePattern): number {
  return pattern.messagePatterns.length;
}

// ── Load vectors ─────────────────────────────────────────────────────────────

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const vectors: TestVector[] = JSON.parse(
  readFileSync(resolve(__dirname, 'vectors.json'), 'utf-8'),
);

// ── Tests ────────────────────────────────────────────────────────────────────

describe('external test vectors', () => {
  for (const vector of vectors) {
    const label = `${vector.protocol_name} [${vector._source ?? 'unknown'}]`;
    it(label, () => {
      const pattern = getPattern(vector.protocol_name);
      const numHandshake = getNumHandshakeMessages(pattern);
      const prologue = hex(vector.init_prologue);

      // Set up initiator
      const initConfig: ConstructorParameters<typeof HandshakeState>[0] = {
        pattern,
        role: 'initiator',
        prologue,
        e: keypairFromPrivate(vector.init_ephemeral),
        s: vector.init_static
          ? keypairFromPrivate(vector.init_static)
          : undefined,
        rs: vector.init_remote_static
          ? hex(vector.init_remote_static)
          : undefined,
      };

      // Set up responder
      const respConfig: ConstructorParameters<typeof HandshakeState>[0] = {
        pattern,
        role: 'responder',
        prologue: hex(vector.resp_prologue),
        e: keypairFromPrivate(vector.resp_ephemeral),
        s: vector.resp_static
          ? keypairFromPrivate(vector.resp_static)
          : undefined,
        rs: vector.resp_remote_static
          ? hex(vector.resp_remote_static)
          : undefined,
      };

      const initiator = new HandshakeState(initConfig);
      const responder = new HandshakeState(respConfig);

      let initCiphers: ReturnType<typeof initiator.writeMessage>['cipherStates'];
      let respCiphers: ReturnType<typeof responder.writeMessage>['cipherStates'];
      let initHash: Uint8Array | undefined;
      let respHash: Uint8Array | undefined;

      // Process handshake messages
      for (let i = 0; i < numHandshake; i++) {
        const msg = vector.messages[i]!;
        const payload = hex(msg.payload);
        const expectedCiphertext = hex(msg.ciphertext);

        if (i % 2 === 0) {
          // Initiator writes
          const result = initiator.writeMessage(payload);
          expect(toHex(result.messageBuffer)).toBe(msg.ciphertext);

          // Responder reads
          const readResult = responder.readMessage(result.messageBuffer);
          expect(toHex(readResult.messageBuffer)).toBe(msg.payload);

          if (result.cipherStates) {
            initCiphers = result.cipherStates;
            initHash = result.handshakeHash;
          }
          if (readResult.cipherStates) {
            respCiphers = readResult.cipherStates;
            respHash = readResult.handshakeHash;
          }
        } else {
          // Responder writes
          const result = responder.writeMessage(payload);
          expect(toHex(result.messageBuffer)).toBe(msg.ciphertext);

          // Initiator reads
          const readResult = initiator.readMessage(result.messageBuffer);
          expect(toHex(readResult.messageBuffer)).toBe(msg.payload);

          if (result.cipherStates) {
            respCiphers = result.cipherStates;
            respHash = result.handshakeHash;
          }
          if (readResult.cipherStates) {
            initCiphers = readResult.cipherStates;
            initHash = readResult.handshakeHash;
          }
        }
      }

      // Verify handshake hash
      expect(initHash).toBeDefined();
      expect(respHash).toBeDefined();
      // Both sides must agree on the handshake hash
      expect(toHex(initHash!)).toBe(toHex(respHash!));
      // If the vector includes a known handshake hash, verify against it
      if (vector.handshake_hash) {
        expect(toHex(initHash!)).toBe(vector.handshake_hash);
      }

      // Verify transport messages
      expect(initCiphers).toBeDefined();
      expect(respCiphers).toBeDefined();

      const [initC1, initC2] = initCiphers!;
      const [respC1, respC2] = respCiphers!;

      for (let i = numHandshake; i < vector.messages.length; i++) {
        const msg = vector.messages[i]!;
        const payload = hex(msg.payload);

        if (i % 2 === 0) {
          // Initiator sends (uses c1 = initiator→responder)
          const encrypted = initC1.encryptWithAd(new Uint8Array(0), payload);
          expect(toHex(encrypted)).toBe(msg.ciphertext);

          // Responder decrypts (uses c1 = initiator→responder)
          const decrypted = respC1.decryptWithAd(new Uint8Array(0), encrypted);
          expect(toHex(decrypted)).toBe(msg.payload);
        } else {
          // Responder sends (uses c2 = responder→initiator)
          const encrypted = respC2.encryptWithAd(new Uint8Array(0), payload);
          expect(toHex(encrypted)).toBe(msg.ciphertext);

          // Initiator decrypts (uses c2 = responder→initiator)
          const decrypted = initC2.decryptWithAd(new Uint8Array(0), encrypted);
          expect(toHex(decrypted)).toBe(msg.payload);
        }
      }
    });
  }
});
