/**
 * Comprehensive property-based and edge-case tests for @tacet/noise.
 *
 * Covers:
 * - Crypto primitives (DH, AEAD, hash, HMAC, HKDF)
 * - CipherState (nonce, rekey, passthrough)
 * - SymmetricState (initialize, mix operations, split)
 * - HandshakeState (error paths, turn enforcement)
 * - Transport (single message, framed chunking, tamper detection)
 * - Session (roundtrip properties, prologue binding, rekey)
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  getPublicKey,
  NoiseSession,
  CipherState,
  SymmetricState,
  HandshakeState,
  NoiseTransport,
  NK,
  XX,
  DHLEN,
  HASHLEN,
  TAG_LEN,
  MAX_MESSAGE_LEN,
} from '../src/index.js';
import {
  dh,
  hash,
  hmacBlake2b,
  noiseHkdf,
  encrypt,
  decrypt,
  concat,
  EMPTY,
  BLOCKLEN,
  MAX_NONCE,
} from '../src/crypto.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function completeNKHandshake(
  opts: {
    clientPrologue?: Uint8Array;
    serverPrologue?: Uint8Array;
  } = {},
) {
  const serverKeys = generateKeypair();
  const client = NoiseSession.create({
    pattern: 'NK',
    role: 'initiator',
    remoteStaticKey: serverKeys.publicKey,
    prologue: opts.clientPrologue,
  });
  const server = NoiseSession.create({
    pattern: 'NK',
    role: 'responder',
    staticKeypair: serverKeys,
    prologue: opts.serverPrologue,
  });
  const msg1 = client.writeHandshake();
  server.readHandshake(msg1);
  const msg2 = server.writeHandshake();
  client.readHandshake(msg2);
  return { client, server, serverKeys };
}

function completeXXHandshake() {
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
  server.readHandshake(msg1);
  const msg2 = server.writeHandshake();
  client.readHandshake(msg2);
  const msg3 = client.writeHandshake();
  server.readHandshake(msg3);
  return { client, server, clientKeys, serverKeys };
}

// ── Crypto Primitives ────────────────────────────────────────────────────────

describe('crypto primitives', () => {
  describe('DH (X25519)', () => {
    it('DH is commutative: dh(a, B) == dh(b, A)', () => {
      const alice = generateKeypair();
      const bob = generateKeypair();
      const shared1 = dh(alice.privateKey, bob.publicKey);
      const shared2 = dh(bob.privateKey, alice.publicKey);
      expect(shared1).toEqual(shared2);
    });

    it('getPublicKey matches keypair generation', () => {
      const kp = generateKeypair();
      const pub = getPublicKey(kp.privateKey);
      expect(pub).toEqual(kp.publicKey);
    });

    it('different keys produce different DH outputs', () => {
      const a = generateKeypair();
      const b = generateKeypair();
      const c = generateKeypair();
      const ab = dh(a.privateKey, b.publicKey);
      const ac = dh(a.privateKey, c.publicKey);
      expect(ab).not.toEqual(ac);
    });

    it('public key is DHLEN bytes', () => {
      const kp = generateKeypair();
      expect(kp.publicKey.length).toBe(DHLEN);
      expect(kp.privateKey.length).toBe(32);
    });
  });

  describe('AEAD (ChaCha20-Poly1305)', () => {
    it('encrypt then decrypt roundtrips', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('test message');
      const ad = new TextEncoder().encode('associated data');
      const ct = encrypt(key, 0n, ad, plaintext);
      const pt = decrypt(key, 0n, ad, ct);
      expect(pt).toEqual(plaintext);
    });

    it('ciphertext is plaintext.length + TAG_LEN', () => {
      const key = randomBytes(32);
      const pt = randomBytes(100);
      const ct = encrypt(key, 0n, EMPTY, pt);
      expect(ct.length).toBe(pt.length + TAG_LEN);
    });

    it('different nonces produce different ciphertext', () => {
      const key = randomBytes(32);
      const pt = new TextEncoder().encode('same message');
      const ct1 = encrypt(key, 0n, EMPTY, pt);
      const ct2 = encrypt(key, 1n, EMPTY, pt);
      expect(ct1).not.toEqual(ct2);
    });

    it('wrong key fails decryption', () => {
      const key1 = randomBytes(32);
      const key2 = randomBytes(32);
      const ct = encrypt(key1, 0n, EMPTY, new Uint8Array([1, 2, 3]));
      expect(() => decrypt(key2, 0n, EMPTY, ct)).toThrow();
    });

    it('wrong AD fails decryption', () => {
      const key = randomBytes(32);
      const pt = new Uint8Array([1, 2, 3]);
      const ct = encrypt(key, 0n, new Uint8Array([1]), pt);
      expect(() => decrypt(key, 0n, new Uint8Array([2]), ct)).toThrow();
    });

    it('tampered ciphertext fails decryption', () => {
      const key = randomBytes(32);
      const ct = encrypt(key, 0n, EMPTY, new Uint8Array([1, 2, 3]));
      ct[0] ^= 0xff;
      expect(() => decrypt(key, 0n, EMPTY, ct)).toThrow();
    });

    it('empty plaintext produces TAG_LEN ciphertext', () => {
      const key = randomBytes(32);
      const ct = encrypt(key, 0n, EMPTY, EMPTY);
      expect(ct.length).toBe(TAG_LEN);
      const pt = decrypt(key, 0n, EMPTY, ct);
      expect(pt.length).toBe(0);
    });
  });

  describe('BLAKE2b hash', () => {
    it('output is HASHLEN bytes', () => {
      const h = hash(new Uint8Array([1, 2, 3]));
      expect(h.length).toBe(HASHLEN);
    });

    it('deterministic: same input → same output', () => {
      const data = randomBytes(64);
      expect(hash(data)).toEqual(hash(data));
    });

    it('different inputs → different outputs', () => {
      const h1 = hash(new Uint8Array([0]));
      const h2 = hash(new Uint8Array([1]));
      expect(h1).not.toEqual(h2);
    });

    it('empty input hashes to a known non-zero value', () => {
      const h = hash(EMPTY);
      expect(h.length).toBe(HASHLEN);
      expect(h.some((b) => b !== 0)).toBe(true);
    });
  });

  describe('HMAC-BLAKE2b', () => {
    it('different keys → different outputs', () => {
      const data = new Uint8Array([1, 2, 3]);
      const h1 = hmacBlake2b(new Uint8Array(32), data);
      const h2 = hmacBlake2b(new Uint8Array(32).fill(1), data);
      expect(h1).not.toEqual(h2);
    });

    it('different data → different outputs', () => {
      const key = new Uint8Array(32);
      const h1 = hmacBlake2b(key, new Uint8Array([1]));
      const h2 = hmacBlake2b(key, new Uint8Array([2]));
      expect(h1).not.toEqual(h2);
    });

    it('handles key longer than BLOCKLEN', () => {
      const longKey = randomBytes(BLOCKLEN + 32);
      const data = new Uint8Array([1, 2, 3]);
      const h = hmacBlake2b(longKey, data);
      expect(h.length).toBe(HASHLEN);
    });

    it('output is HASHLEN bytes', () => {
      const h = hmacBlake2b(new Uint8Array(32), new Uint8Array(10));
      expect(h.length).toBe(HASHLEN);
    });
  });

  describe('HKDF', () => {
    it('returns 2 outputs when requested', () => {
      const ck = randomBytes(HASHLEN);
      const ikm = randomBytes(32);
      const result = noiseHkdf(ck, ikm, 2);
      expect(result.length).toBe(2);
      expect(result[0].length).toBe(HASHLEN);
      expect(result[1].length).toBe(HASHLEN);
    });

    it('returns 3 outputs when requested', () => {
      const ck = randomBytes(HASHLEN);
      const ikm = randomBytes(32);
      const result = noiseHkdf(ck, ikm, 3);
      expect(result.length).toBe(3);
      expect(result[2].length).toBe(HASHLEN);
    });

    it('all outputs are distinct', () => {
      const ck = randomBytes(HASHLEN);
      const ikm = randomBytes(32);
      const [o1, o2, o3] = noiseHkdf(ck, ikm, 3);
      expect(o1).not.toEqual(o2);
      expect(o2).not.toEqual(o3);
      expect(o1).not.toEqual(o3);
    });

    it('deterministic: same inputs → same outputs', () => {
      const ck = randomBytes(HASHLEN);
      const ikm = randomBytes(32);
      const r1 = noiseHkdf(ck, ikm, 2);
      const r2 = noiseHkdf(ck, ikm, 2);
      expect(r1[0]).toEqual(r2[0]);
      expect(r1[1]).toEqual(r2[1]);
    });
  });

  describe('concat', () => {
    it('concatenates multiple arrays', () => {
      const result = concat(
        new Uint8Array([1, 2]),
        new Uint8Array([3]),
        new Uint8Array([4, 5, 6]),
      );
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    it('handles empty arrays', () => {
      const result = concat(EMPTY, new Uint8Array([1]), EMPTY);
      expect(result).toEqual(new Uint8Array([1]));
    });

    it('handles all empty arrays', () => {
      const result = concat(EMPTY, EMPTY);
      expect(result.length).toBe(0);
    });
  });
});

// ── CipherState ──────────────────────────────────────────────────────────────

describe('CipherState', () => {
  it('passthrough when no key is set', () => {
    const cs = new CipherState();
    const data = new Uint8Array([1, 2, 3, 4]);
    const encrypted = cs.encryptWithAd(EMPTY, data);
    expect(encrypted).toEqual(data);
    const decrypted = cs.decryptWithAd(EMPTY, data);
    expect(decrypted).toEqual(data);
  });

  it('encrypts when key is set', () => {
    const cs = new CipherState();
    cs.initializeKey(randomBytes(32));
    const data = new Uint8Array([1, 2, 3, 4]);
    const encrypted = cs.encryptWithAd(EMPTY, data);
    expect(encrypted.length).toBe(data.length + TAG_LEN);
    expect(encrypted).not.toEqual(data);
  });

  it('nonce increments on each operation', () => {
    const cs = new CipherState();
    cs.initializeKey(randomBytes(32));
    expect(cs.getNonce()).toBe(0n);
    cs.encryptWithAd(EMPTY, new Uint8Array([1]));
    expect(cs.getNonce()).toBe(1n);
    cs.encryptWithAd(EMPTY, new Uint8Array([2]));
    expect(cs.getNonce()).toBe(2n);
  });

  it('encrypt/decrypt roundtrips with matching CipherStates', () => {
    const key = randomBytes(32);
    const enc = new CipherState();
    enc.initializeKey(key);
    const dec = new CipherState();
    dec.initializeKey(new Uint8Array(key));

    for (let i = 0; i < 10; i++) {
      const pt = randomBytes(50 + i);
      const ct = enc.encryptWithAd(EMPTY, pt);
      const result = dec.decryptWithAd(EMPTY, ct);
      expect(result).toEqual(pt);
    }
  });

  it('initializeKey resets nonce', () => {
    const cs = new CipherState();
    cs.initializeKey(randomBytes(32));
    cs.encryptWithAd(EMPTY, new Uint8Array([1]));
    cs.encryptWithAd(EMPTY, new Uint8Array([2]));
    expect(cs.getNonce()).toBe(2n);
    cs.initializeKey(randomBytes(32));
    expect(cs.getNonce()).toBe(0n);
  });

  it('setNonce overrides the counter', () => {
    const cs = new CipherState();
    cs.initializeKey(randomBytes(32));
    cs.setNonce(100n);
    expect(cs.getNonce()).toBe(100n);
    cs.encryptWithAd(EMPTY, new Uint8Array([1]));
    expect(cs.getNonce()).toBe(101n);
  });

  it('rekey changes the key and messages still work in pairs', () => {
    const key = randomBytes(32);
    const enc = new CipherState();
    enc.initializeKey(new Uint8Array(key));
    const dec = new CipherState();
    dec.initializeKey(new Uint8Array(key));

    // encrypt a message before rekey
    const pt1 = new TextEncoder().encode('before rekey');
    const ct1 = enc.encryptWithAd(EMPTY, pt1);
    const r1 = dec.decryptWithAd(EMPTY, ct1);
    expect(r1).toEqual(pt1);

    // rekey both sides
    enc.rekey();
    dec.rekey();

    // encrypt a message after rekey
    const pt2 = new TextEncoder().encode('after rekey');
    const ct2 = enc.encryptWithAd(EMPTY, pt2);
    const r2 = dec.decryptWithAd(EMPTY, ct2);
    expect(r2).toEqual(pt2);
  });

  it('rekey without key throws', () => {
    const cs = new CipherState();
    expect(() => cs.rekey()).toThrow('Cannot rekey');
  });

  it('rekey desynchronizes if only one side rekeys', () => {
    const key = randomBytes(32);
    const enc = new CipherState();
    enc.initializeKey(new Uint8Array(key));
    const dec = new CipherState();
    dec.initializeKey(new Uint8Array(key));

    enc.rekey(); // only enc rekeys
    const ct = enc.encryptWithAd(EMPTY, new Uint8Array([1, 2, 3]));
    expect(() => dec.decryptWithAd(EMPTY, ct)).toThrow();
  });
});

// ── SymmetricState ───────────────────────────────────────────────────────────

describe('SymmetricState', () => {
  it('initializeSymmetric with short name pads to HASHLEN', () => {
    const ss = new SymmetricState();
    ss.initializeSymmetric('Noise_NK_25519_ChaChaPoly_BLAKE2b');
    const h = ss.getHandshakeHash();
    expect(h.length).toBe(HASHLEN);
  });

  it('different protocol names → different handshake hashes', () => {
    const ss1 = new SymmetricState();
    ss1.initializeSymmetric('Noise_NK_25519_ChaChaPoly_BLAKE2b');

    const ss2 = new SymmetricState();
    ss2.initializeSymmetric('Noise_XX_25519_ChaChaPoly_BLAKE2b');

    expect(ss1.getHandshakeHash()).not.toEqual(ss2.getHandshakeHash());
  });

  it('mixHash changes the handshake hash', () => {
    const ss = new SymmetricState();
    ss.initializeSymmetric('Noise_NK_25519_ChaChaPoly_BLAKE2b');
    const before = ss.getHandshakeHash();
    ss.mixHash(new Uint8Array([1, 2, 3]));
    const after = ss.getHandshakeHash();
    expect(before).not.toEqual(after);
  });

  it('mixKey enables encryption', () => {
    const ss = new SymmetricState();
    ss.initializeSymmetric('Noise_NK_25519_ChaChaPoly_BLAKE2b');
    expect(ss.hasKey()).toBe(false);

    ss.mixKey(randomBytes(32));
    expect(ss.hasKey()).toBe(true);

    // encryptAndHash should now produce ciphertext different from plaintext
    const pt = new Uint8Array([10, 20, 30]);
    const ct = ss.encryptAndHash(pt);
    expect(ct.length).toBe(pt.length + TAG_LEN);
  });

  it('split produces two distinct CipherStates', () => {
    const ss = new SymmetricState();
    ss.initializeSymmetric('Noise_NK_25519_ChaChaPoly_BLAKE2b');
    ss.mixKey(randomBytes(32));

    const [c1, c2] = ss.split();
    expect(c1.hasKey()).toBe(true);
    expect(c2.hasKey()).toBe(true);

    // They should encrypt differently (different keys)
    const pt = new Uint8Array([1, 2, 3]);
    const ct1 = c1.encryptWithAd(EMPTY, pt);
    const ct2 = c2.encryptWithAd(EMPTY, pt);
    expect(ct1).not.toEqual(ct2);
  });

  it('encryptAndHash then decryptAndHash roundtrips (no key)', () => {
    const ss = new SymmetricState();
    ss.initializeSymmetric('test');
    // Without mixKey, no encryption happens
    const pt = new Uint8Array([42, 43, 44]);
    const ct = ss.encryptAndHash(pt);
    expect(ct).toEqual(pt); // passthrough
  });
});

// ── HandshakeState ───────────────────────────────────────────────────────────

describe('HandshakeState', () => {
  it('NK: responder cannot write first', () => {
    const serverKeys = generateKeypair();
    const responder = new HandshakeState({
      pattern: NK,
      role: 'responder',
      s: serverKeys,
    });
    expect(() => responder.writeMessage()).toThrow(/turn/i);
  });

  it('NK: initiator cannot read first', () => {
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: NK,
      role: 'initiator',
      rs: serverKeys.publicKey,
    });
    expect(() => initiator.readMessage(new Uint8Array(100))).toThrow(/turn/i);
  });

  it('NK: writing after handshake complete throws', () => {
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: NK,
      role: 'initiator',
      rs: serverKeys.publicKey,
    });
    const responder = new HandshakeState({
      pattern: NK,
      role: 'responder',
      s: serverKeys,
    });

    const r1 = initiator.writeMessage();
    responder.readMessage(r1.messageBuffer);
    const r2 = responder.writeMessage();
    initiator.readMessage(r2.messageBuffer);

    expect(() => initiator.writeMessage()).toThrow(/complete/i);
    expect(() => responder.writeMessage()).toThrow(/complete/i);
  });

  it('NK: handshake completes on the last message', () => {
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: NK,
      role: 'initiator',
      rs: serverKeys.publicKey,
    });
    const responder = new HandshakeState({
      pattern: NK,
      role: 'responder',
      s: serverKeys,
    });

    const r1 = initiator.writeMessage();
    expect(r1.cipherStates).toBeUndefined();
    responder.readMessage(r1.messageBuffer);

    // Last message: should produce cipher states
    const r2 = responder.writeMessage();
    expect(r2.cipherStates).toBeDefined();

    const r3 = initiator.readMessage(r2.messageBuffer);
    expect(r3.cipherStates).toBeDefined();
    expect(r3.handshakeHash).toBeDefined();
  });

  it('XX: handshake requires 3 messages', () => {
    const clientKeys = generateKeypair();
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: XX,
      role: 'initiator',
      s: clientKeys,
    });
    const responder = new HandshakeState({
      pattern: XX,
      role: 'responder',
      s: serverKeys,
    });

    const r1 = initiator.writeMessage();
    expect(r1.cipherStates).toBeUndefined();
    responder.readMessage(r1.messageBuffer);

    const r2 = responder.writeMessage();
    expect(r2.cipherStates).toBeUndefined();
    initiator.readMessage(r2.messageBuffer);

    // Third message completes
    const r3 = initiator.writeMessage();
    expect(r3.cipherStates).toBeDefined();
    const r4 = responder.readMessage(r3.messageBuffer);
    expect(r4.cipherStates).toBeDefined();
  });

  it('XX: getRemoteStaticKey returns the remote static after handshake', () => {
    const clientKeys = generateKeypair();
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: XX,
      role: 'initiator',
      s: clientKeys,
    });
    const responder = new HandshakeState({
      pattern: XX,
      role: 'responder',
      s: serverKeys,
    });

    const r1 = initiator.writeMessage();
    responder.readMessage(r1.messageBuffer);
    const r2 = responder.writeMessage();
    initiator.readMessage(r2.messageBuffer);

    // After msg2, initiator knows responder's static
    expect(initiator.getRemoteStaticKey()).toEqual(serverKeys.publicKey);

    const r3 = initiator.writeMessage();
    responder.readMessage(r3.messageBuffer);

    // After msg3, responder knows initiator's static
    expect(responder.getRemoteStaticKey()).toEqual(clientKeys.publicKey);
  });

  it('handshake payload is recoverable', () => {
    const serverKeys = generateKeypair();
    const initiator = new HandshakeState({
      pattern: NK,
      role: 'initiator',
      rs: serverKeys.publicKey,
    });
    const responder = new HandshakeState({
      pattern: NK,
      role: 'responder',
      s: serverKeys,
    });

    const payload1 = new TextEncoder().encode('request data');
    const r1 = initiator.writeMessage(payload1);
    const read1 = responder.readMessage(r1.messageBuffer);
    expect(read1.messageBuffer).toEqual(payload1);

    const payload2 = new TextEncoder().encode('response data');
    const r2 = responder.writeMessage(payload2);
    const read2 = initiator.readMessage(r2.messageBuffer);
    expect(read2.messageBuffer).toEqual(payload2);
  });
});

// ── Transport ────────────────────────────────────────────────────────────────

describe('NoiseTransport', () => {
  function makeTransportPair(): [NoiseTransport, NoiseTransport] {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const hh = randomBytes(HASHLEN);

    const sendC1 = new CipherState();
    sendC1.initializeKey(new Uint8Array(key1));
    const sendC2 = new CipherState();
    sendC2.initializeKey(new Uint8Array(key2));

    const recvC1 = new CipherState();
    recvC1.initializeKey(new Uint8Array(key1));
    const recvC2 = new CipherState();
    recvC2.initializeKey(new Uint8Array(key2));

    const alice = new NoiseTransport(sendC1, recvC2, new Uint8Array(hh));
    const bob = new NoiseTransport(sendC2, recvC1, new Uint8Array(hh));
    return [alice, bob];
  }

  it('encrypt/decrypt roundtrips', () => {
    const [alice, bob] = makeTransportPair();
    const pt = new TextEncoder().encode('hello transport');
    const ct = alice.encrypt(pt);
    const result = bob.decrypt(ct);
    expect(result).toEqual(pt);
  });

  it('bidirectional messaging works', () => {
    const [alice, bob] = makeTransportPair();

    // Alice → Bob
    const ct1 = alice.encrypt(new TextEncoder().encode('a→b'));
    expect(new TextDecoder().decode(bob.decrypt(ct1))).toBe('a→b');

    // Bob → Alice
    const ct2 = bob.encrypt(new TextEncoder().encode('b→a'));
    expect(new TextDecoder().decode(alice.decrypt(ct2))).toBe('b→a');
  });

  it('tampered ciphertext fails', () => {
    const [alice, bob] = makeTransportPair();
    const ct = alice.encrypt(new Uint8Array([1, 2, 3]));
    ct[ct.length - 1] ^= 0xff; // flip last byte of tag
    expect(() => bob.decrypt(ct)).toThrow();
  });

  it('rejects oversized single message', () => {
    const [alice] = makeTransportPair();
    const oversized = new Uint8Array(MAX_MESSAGE_LEN); // too large for single msg
    expect(() => alice.encrypt(oversized)).toThrow(/too large/i);
  });

  describe('framed transport', () => {
    it('small payload frames and unframes correctly', () => {
      const [alice, bob] = makeTransportPair();
      const pt = new TextEncoder().encode('small framed');
      const framed = alice.encryptFramed(pt);
      const result = bob.decryptFramed(framed);
      expect(result).toEqual(pt);
    });

    it('empty payload produces just the end marker', () => {
      const [alice, bob] = makeTransportPair();
      const framed = alice.encryptFramed(EMPTY);
      // Should be just [0x00, 0x00]
      expect(framed).toEqual(new Uint8Array([0x00, 0x00]));
      const result = bob.decryptFramed(framed);
      expect(result.length).toBe(0);
    });

    it('truncated frame length prefix throws', () => {
      const [, bob] = makeTransportPair();
      expect(() => bob.decryptFramed(new Uint8Array([0x01]))).toThrow(
        /truncated/i,
      );
    });

    it('truncated frame body throws', () => {
      const [, bob] = makeTransportPair();
      // Length says 100 bytes but only 2 bytes follow
      const bad = new Uint8Array([0x00, 100, 0x01, 0x02]);
      expect(() => bob.decryptFramed(bad)).toThrow(/truncated/i);
    });

    it('rekey works with framed transport', () => {
      const [alice, bob] = makeTransportPair();

      const pt1 = new TextEncoder().encode('before rekey');
      const f1 = alice.encryptFramed(pt1);
      expect(bob.decryptFramed(f1)).toEqual(pt1);

      alice.rekeySend();
      bob.rekeyRecv();

      const pt2 = new TextEncoder().encode('after rekey');
      const f2 = alice.encryptFramed(pt2);
      expect(bob.decryptFramed(f2)).toEqual(pt2);
    });
  });
});

// ── NoiseSession Properties ──────────────────────────────────────────────────

describe('NoiseSession properties', () => {
  describe('NK pattern', () => {
    it('handshake hashes are 64 bytes and match', () => {
      const { client, server } = completeNKHandshake();
      const ch = client.getHandshakeHash();
      const sh = server.getHandshakeHash();
      expect(ch.length).toBe(HASHLEN);
      expect(ch).toEqual(sh);
    });

    it('different server keys → different handshake hashes', () => {
      const { client: c1 } = completeNKHandshake();
      const { client: c2 } = completeNKHandshake();
      // Random keys each time → overwhelmingly different hashes
      expect(c1.getHandshakeHash()).not.toEqual(c2.getHandshakeHash());
    });

    it('prologue mismatch causes handshake failure', () => {
      const serverKeys = generateKeypair();
      const client = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
        prologue: new TextEncoder().encode('version1'),
      });
      const server = NoiseSession.create({
        pattern: 'NK',
        role: 'responder',
        staticKeypair: serverKeys,
        prologue: new TextEncoder().encode('version2'),
      });

      const msg1 = client.writeHandshake();
      // Fails on msg1 read: after es, the cipher has a key but h (used
      // as AD) differs due to different prologue → AEAD tag check fails.
      expect(() => server.readHandshake(msg1)).toThrow();
    });

    it('same prologue produces matching hashes', () => {
      const prologue = new TextEncoder().encode('v1.0');
      const { client, server } = completeNKHandshake({
        clientPrologue: prologue,
        serverPrologue: prologue,
      });
      expect(client.getHandshakeHash()).toEqual(server.getHandshakeHash());
    });

    it('encrypt/decrypt with various payload sizes', () => {
      const { client, server } = completeNKHandshake();
      for (const size of [0, 1, 15, 16, 17, 255, 1000, 65000]) {
        const pt = randomBytes(size);
        const ct = client.encrypt(pt);
        const result = server.decrypt(ct);
        expect(result).toEqual(pt);
      }
    });

    it('messages in wrong direction fail to decrypt', () => {
      const { client, server } = completeNKHandshake();

      // Client encrypts with c1 (initiator→responder)
      const ct = client.encrypt(new Uint8Array([1, 2, 3]));

      // Client trying to decrypt its own message (wrong cipher) should fail
      expect(() => client.decrypt(ct)).toThrow();
    });
  });

  describe('XX pattern', () => {
    it('handshake hashes match between parties', () => {
      const { client, server } = completeXXHandshake();
      expect(client.getHandshakeHash()).toEqual(server.getHandshakeHash());
    });

    it('transport encryption works bidirectionally', () => {
      const { client, server } = completeXXHandshake();

      const pt1 = new TextEncoder().encode('client→server');
      const ct1 = client.encrypt(pt1);
      expect(server.decrypt(ct1)).toEqual(pt1);

      const pt2 = new TextEncoder().encode('server→client');
      const ct2 = server.encrypt(pt2);
      expect(client.decrypt(ct2)).toEqual(pt2);
    });
  });

  describe('NK vs XX produce different handshake hashes', () => {
    it('using same keys, NK and XX yield different hashes', () => {
      const clientKeys = generateKeypair();
      const serverKeys = generateKeypair();

      // NK session
      const nkClient = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
      });
      const nkServer = NoiseSession.create({
        pattern: 'NK',
        role: 'responder',
        staticKeypair: serverKeys,
      });
      const nk1 = nkClient.writeHandshake();
      nkServer.readHandshake(nk1);
      const nk2 = nkServer.writeHandshake();
      nkClient.readHandshake(nk2);

      // XX session
      const xxClient = NoiseSession.create({
        pattern: 'XX',
        role: 'initiator',
        staticKeypair: clientKeys,
      });
      const xxServer = NoiseSession.create({
        pattern: 'XX',
        role: 'responder',
        staticKeypair: serverKeys,
      });
      const xx1 = xxClient.writeHandshake();
      xxServer.readHandshake(xx1);
      const xx2 = xxServer.writeHandshake();
      xxClient.readHandshake(xx2);
      const xx3 = xxClient.writeHandshake();
      xxServer.readHandshake(xx3);

      expect(nkClient.getHandshakeHash()).not.toEqual(
        xxClient.getHandshakeHash(),
      );
    });
  });

  describe('rekey', () => {
    it('rekeySend + rekeyRecv keeps transport working', () => {
      const { client, server } = completeNKHandshake();

      // Before rekey
      const pt1 = new TextEncoder().encode('before');
      expect(server.decrypt(client.encrypt(pt1))).toEqual(pt1);

      // Rekey client→server direction
      client.rekeySend();
      server.rekeyRecv();

      // After rekey
      const pt2 = new TextEncoder().encode('after');
      expect(server.decrypt(client.encrypt(pt2))).toEqual(pt2);

      // Rekey server→client direction
      server.rekeySend();
      client.rekeyRecv();

      const pt3 = new TextEncoder().encode('both rekeyed');
      expect(client.decrypt(server.encrypt(pt3))).toEqual(pt3);
    });

    it('one-sided rekey breaks decryption', () => {
      const { client, server } = completeNKHandshake();
      client.rekeySend(); // only client rekeys
      const ct = client.encrypt(new Uint8Array([1]));
      expect(() => server.decrypt(ct)).toThrow();
    });

    it('rekey in wrong state throws', () => {
      const serverKeys = generateKeypair();
      const client = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
      });
      expect(() => client.rekeySend()).toThrow();
      expect(() => client.rekeyRecv()).toThrow();
    });
  });

  describe('state machine enforcement', () => {
    it('getHandshakeHash before transport throws', () => {
      const serverKeys = generateKeypair();
      const client = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
      });
      expect(() => client.getHandshakeHash()).toThrow();
    });

    it('encrypt/decrypt before transport throws', () => {
      const serverKeys = generateKeypair();
      const client = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
      });
      expect(() => client.encrypt(new Uint8Array([1]))).toThrow();
      expect(() => client.decrypt(new Uint8Array(17))).toThrow();
    });

    it('encryptFramed/decryptFramed before transport throws', () => {
      const serverKeys = generateKeypair();
      const client = NoiseSession.create({
        pattern: 'NK',
        role: 'initiator',
        remoteStaticKey: serverKeys.publicKey,
      });
      expect(() => client.encryptFramed(new Uint8Array([1]))).toThrow();
      expect(() => client.decryptFramed(new Uint8Array([0, 0]))).toThrow();
    });

    it('writeHandshake after transport throws', () => {
      const { client } = completeNKHandshake();
      expect(() => client.writeHandshake()).toThrow();
    });

    it('readHandshake after transport throws', () => {
      const { client } = completeNKHandshake();
      expect(() => client.readHandshake(new Uint8Array(100))).toThrow();
    });
  });

  describe('framed transport via session', () => {
    it('roundtrips various sizes through framing', () => {
      const { client, server } = completeNKHandshake();
      for (const size of [0, 1, 100, 10_000]) {
        const pt = randomBytes(size);
        const framed = client.encryptFramed(pt);
        const result = server.decryptFramed(framed);
        expect(result).toEqual(pt);
      }
    });

    it('framed transport works in both directions', () => {
      const { client, server } = completeNKHandshake();

      const f1 = client.encryptFramed(new TextEncoder().encode('c→s framed'));
      expect(new TextDecoder().decode(server.decryptFramed(f1))).toBe(
        'c→s framed',
      );

      const f2 = server.encryptFramed(new TextEncoder().encode('s→c framed'));
      expect(new TextDecoder().decode(client.decryptFramed(f2))).toBe(
        's→c framed',
      );
    });
  });

  describe('session independence', () => {
    it('two independent NK sessions do not interfere', () => {
      const { client: c1, server: s1 } = completeNKHandshake();
      const { client: c2, server: s2 } = completeNKHandshake();

      const pt = new TextEncoder().encode('session 1');
      const ct1 = c1.encrypt(pt);
      const ct2 = c2.encrypt(pt);

      // Each session's ciphertext is different (different keys)
      expect(ct1).not.toEqual(ct2);

      // Cross-session decryption fails
      expect(() => s2.decrypt(ct1)).toThrow();
      expect(() => s1.decrypt(ct2)).toThrow();

      // Same-session decryption works
      expect(s1.decrypt(ct1)).toEqual(pt);
      expect(s2.decrypt(ct2)).toEqual(pt);
    });
  });
});
