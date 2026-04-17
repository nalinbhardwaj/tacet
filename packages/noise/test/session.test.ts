/**
 * Tests for the high-level NoiseSession API.
 */

import { describe, it, expect } from 'vitest';
import { NoiseSession, generateKeypair } from '../src/index.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

describe('NoiseSession NK', () => {
  it('completes handshake and encrypts/decrypts', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    expect(client.state).toBe('handshake');
    expect(server.state).toBe('handshake');

    // Message 1: client → server (e, es)
    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);

    // Message 2: server → client (e, ee)
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    expect(client.state).toBe('transport');
    expect(server.state).toBe('transport');

    // Transport: client → server
    const plaintext = encoder.encode('Hello, TEE!');
    const encrypted = client.encrypt(plaintext);
    const decrypted = server.decrypt(encrypted);
    expect(decoder.decode(decrypted)).toBe('Hello, TEE!');

    // Transport: server → client
    const response = encoder.encode('Response from TEE');
    const encResponse = server.encrypt(response);
    const decResponse = client.decrypt(encResponse);
    expect(decoder.decode(decResponse)).toBe('Response from TEE');
  });

  it('supports payload in handshake messages', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    // Send request payload with first handshake message
    const request = encoder.encode('{"messages":[{"role":"user","content":"hi"}]}');
    const msg1 = client.writeHandshake(request);
    const requestDecrypted = server.readHandshake(msg1);
    expect(decoder.decode(requestDecrypted)).toBe(
      '{"messages":[{"role":"user","content":"hi"}]}',
    );

    // Server responds with handshake + response payload
    const response = encoder.encode('{"choices":[{"message":{"content":"hello"}}]}');
    const msg2 = server.writeHandshake(response);
    const responseDecrypted = client.readHandshake(msg2);
    expect(decoder.decode(responseDecrypted)).toBe(
      '{"choices":[{"message":{"content":"hello"}}]}',
    );

    expect(client.state).toBe('transport');
    expect(server.state).toBe('transport');
  });

  it('handshake hashes match between parties', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    const clientHash = client.getHandshakeHash();
    const serverHash = server.getHandshakeHash();
    expect(clientHash).toEqual(serverHash);
  });

  it('rejects wrong operations in wrong state', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    // Can't encrypt during handshake
    expect(() => client.encrypt(new Uint8Array(1))).toThrow();

    // Can't decrypt during handshake
    expect(() => client.decrypt(new Uint8Array(17))).toThrow();
  });

  it('multiple transport messages with incrementing nonces', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    // Send many messages in both directions
    for (let i = 0; i < 100; i++) {
      const data = encoder.encode(`message ${i}`);

      if (i % 2 === 0) {
        const enc = client.encrypt(data);
        const dec = server.decrypt(enc);
        expect(decoder.decode(dec)).toBe(`message ${i}`);
      } else {
        const enc = server.encrypt(data);
        const dec = client.decrypt(enc);
        expect(decoder.decode(dec)).toBe(`message ${i}`);
      }
    }
  });
});

describe('NoiseSession XX', () => {
  it('completes handshake and encrypts/decrypts', () => {
    const clientKeys = generateKeypair();
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'XX',
      role: 'initiator',
      staticKeypair: clientKeys,
    });

    const server = NoiseSession.create({
      pattern: 'XX',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    // Message 1: client → server (e)
    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);

    // Message 2: server → client (e, ee, s, es)
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    // Message 3: client → server (s, se)
    const msg3 = client.writeHandshake();
    server.readHandshake(msg3);

    expect(client.state).toBe('transport');
    expect(server.state).toBe('transport');

    // Transport works
    const data = encoder.encode('Encrypted via XX');
    const enc = client.encrypt(data);
    const dec = server.decrypt(enc);
    expect(decoder.decode(dec)).toBe('Encrypted via XX');
  });

  it('XX handshake: 3 messages, last completes', () => {
    const clientKeys = generateKeypair();
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'XX',
      role: 'initiator',
      staticKeypair: clientKeys,
    });

    const server = NoiseSession.create({
      pattern: 'XX',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    const msg1 = client.writeHandshake();
    expect(client.state).toBe('handshake');
    server.readHandshake(msg1);
    expect(server.state).toBe('handshake');

    const msg2 = server.writeHandshake();
    expect(server.state).toBe('handshake');
    client.readHandshake(msg2);
    expect(client.state).toBe('handshake');

    // Last message completes handshake for both
    const msg3 = client.writeHandshake();
    expect(client.state).toBe('transport');
    server.readHandshake(msg3);
    expect(server.state).toBe('transport');
  });
});

describe('NoiseSession framed transport', () => {
  it('encrypts and decrypts framed messages', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    // Small framed message
    const data = encoder.encode('{"response":"hello"}');
    const framed = client.encryptFramed(data);
    const decoded = server.decryptFramed(framed);
    expect(decoder.decode(decoded)).toBe('{"response":"hello"}');
  });

  it('handles empty payloads', () => {
    const serverKeys = generateKeypair();

    const client = NoiseSession.create({
      pattern: 'NK',
      role: 'initiator',
      remoteStaticKey: serverKeys.publicKey,
    });

    const server = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: serverKeys,
    });

    const msg1 = client.writeHandshake();
    server.readHandshake(msg1);
    const msg2 = server.writeHandshake();
    client.readHandshake(msg2);

    const framed = client.encryptFramed(new Uint8Array(0));
    const decoded = server.decryptFramed(framed);
    expect(decoded.length).toBe(0);
  });
});

describe('NoiseSession config validation', () => {
  it('rejects invalid pattern', () => {
    expect(() =>
      NoiseSession.create({
        pattern: 'INVALID' as 'NK',
        role: 'initiator',
      }),
    ).toThrow();
  });

  it('rejects invalid role', () => {
    expect(() =>
      NoiseSession.create({
        pattern: 'NK',
        role: 'INVALID' as 'initiator',
      }),
    ).toThrow();
  });
});
