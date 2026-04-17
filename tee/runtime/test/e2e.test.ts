/**
 * End-to-end test: a Noise NK client drives the real createNoiseServer
 * over a real WebSocket, with a fake vLLM behind it.
 *
 * Covers:
 *   - GET /v1/keys returns a valid base64 X25519 public key
 *   - NK handshake completes (one frame each way)
 *   - Non-streaming request → single RESPONSE_DONE with full body
 *   - Streaming request → multiple RESPONSE_CHUNK frames, then RESPONSE_DONE
 *   - Upstream vLLM 500 → ERROR frame with forwarded status
 *   - Second request on same connection works (serialized)
 *   - Two concurrent requests on same connection → second gets 'busy' error
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import WebSocket from 'ws';
import { NoiseSession } from '@tacet/noise';
import { createNoiseServer, type RunningServer } from '../src/index.js';
import { resetStaticKeypair } from '../src/keys.js';
import { FRAME, encodeFrame, decodeFrame } from '../src/framing.js';
import { startFakeVllm, type FakeVllm } from './fake-vllm.js';

interface Rx {
  tag: number;
  payload: Uint8Array;
}

describe('Noise endpoint E2E', () => {
  let vllm: FakeVllm;
  let server: RunningServer;
  let baseHttp: string;
  let baseWs: string;
  let serverPubKey: Uint8Array;

  beforeEach(async () => {
    resetStaticKeypair();
    vllm = await startFakeVllm({
      streamChunks: ['Hel', 'lo', ',', ' world'],
    });
    server = await createNoiseServer({
      host: '127.0.0.1',
      port: 0,
      vllmBaseUrl: vllm.url,
    });
    baseHttp = `http://127.0.0.1:${server.address.port}`;
    baseWs = `ws://127.0.0.1:${server.address.port}`;

    const keysRes = await fetch(`${baseHttp}/v1/keys`);
    expect(keysRes.status).toBe(200);
    const { public_key } = (await keysRes.json()) as { public_key: string };
    serverPubKey = new Uint8Array(Buffer.from(public_key, 'base64'));
    expect(serverPubKey.length).toBe(32);
  });

  afterEach(async () => {
    await server.close();
    await vllm.close();
  });

  it('completes handshake and returns a non-streaming response', async () => {
    const { client } = await connectAndHandshake(baseWs, serverPubKey);

    try {
      const req = JSON.stringify({
        model: 'test',
        messages: [{ role: 'user', content: 'hi' }],
        max_tokens: 10,
      });
      client.send(
        encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req))),
      );

      const done = await client.waitFor(FRAME.RESPONSE_DONE);
      const body = new TextDecoder().decode(client.session.decryptFramed(done.payload));
      const parsed = JSON.parse(body);
      expect(parsed.choices[0].message.content).toBe('Hello from fake vLLM');
    } finally {
      client.close();
    }
  });

  it('streams chunks then a DONE marker', async () => {
    const { client } = await connectAndHandshake(baseWs, serverPubKey);

    try {
      const req = JSON.stringify({
        model: 'test',
        messages: [{ role: 'user', content: 'stream' }],
        stream: true,
      });
      client.send(
        encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req))),
      );

      const chunks: string[] = [];
      while (true) {
        const frame = await client.waitForAny();
        if (frame.tag === FRAME.RESPONSE_CHUNK) {
          const line = new TextDecoder().decode(client.session.decrypt(frame.payload));
          chunks.push(line);
          continue;
        }
        if (frame.tag === FRAME.RESPONSE_DONE) {
          const marker = new TextDecoder().decode(client.session.decrypt(frame.payload));
          expect(marker).toBe('[DONE]');
          break;
        }
        throw new Error(`Unexpected tag during streaming: ${frame.tag.toString(16)}`);
      }
      expect(chunks).toHaveLength(4);
      const joined = chunks.map((l) => JSON.parse(l).choices[0].delta.content).join('');
      expect(joined).toBe('Hello, world');
    } finally {
      client.close();
    }
  });

  it('forwards vLLM errors as encrypted ERROR frames', async () => {
    const { client } = await connectAndHandshake(baseWs, serverPubKey);

    try {
      const req = JSON.stringify({
        model: 'test',
        messages: [{ role: 'user', content: 'fail' }],
        __force_error: true,
      });
      client.send(
        encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req))),
      );

      const err = await client.waitFor(FRAME.ERROR);
      const body = new TextDecoder().decode(client.session.decrypt(err.payload));
      const parsed = JSON.parse(body);
      expect(parsed.error.type).toBe('vllm_error');
      expect(parsed.error.status).toBe(500);
    } finally {
      client.close();
    }
  });

  it('handles two sequential requests on one connection', async () => {
    const { client } = await connectAndHandshake(baseWs, serverPubKey);

    try {
      for (let i = 0; i < 2; i++) {
        const req = JSON.stringify({
          model: 'test',
          messages: [{ role: 'user', content: `call ${i}` }],
        });
        client.send(
          encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req))),
        );
        const done = await client.waitFor(FRAME.RESPONSE_DONE);
        const body = new TextDecoder().decode(client.session.decryptFramed(done.payload));
        const parsed = JSON.parse(body);
        expect(parsed.choices[0].message.content).toBe('Hello from fake vLLM');
      }
      expect(vllm.requests.filter((r) => r.path === '/v1/chat/completions')).toHaveLength(2);
    } finally {
      client.close();
    }
  });

  it('rejects an overlapping second request with a busy error', async () => {
    // Slow stream so we can fire a second request while the first is in flight.
    await server.close();
    await vllm.close();
    vllm = await startFakeVllm({
      streamChunks: ['a', 'b', 'c', 'd'],
      streamDelayMs: 30,
    });
    server = await createNoiseServer({
      host: '127.0.0.1',
      port: 0,
      vllmBaseUrl: vllm.url,
    });
    baseHttp = `http://127.0.0.1:${server.address.port}`;
    baseWs = `ws://127.0.0.1:${server.address.port}`;
    const keysRes = await fetch(`${baseHttp}/v1/keys`);
    const { public_key } = (await keysRes.json()) as { public_key: string };
    serverPubKey = new Uint8Array(Buffer.from(public_key, 'base64'));

    const { client } = await connectAndHandshake(baseWs, serverPubKey);

    try {
      // First (slow) request
      const req1 = JSON.stringify({
        model: 'test',
        messages: [{ role: 'user', content: 'slow' }],
        stream: true,
      });
      client.send(
        encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req1))),
      );

      // Give the server a moment to start processing
      await new Promise((r) => setTimeout(r, 10));

      // Second request before the first completes
      const req2 = JSON.stringify({
        model: 'test',
        messages: [{ role: 'user', content: 'racing' }],
      });
      client.send(
        encodeFrame(FRAME.REQUEST, client.session.encryptFramed(Buffer.from(req2))),
      );

      // Drain: expect to see an ERROR (busy) and then the first request's DONE.
      // Every encrypted frame must be decrypted in order to keep the Noise
      // receive-nonce in sync, even if we only inspect the ERROR payload.
      let sawBusy = false;
      let sawDone = false;
      while (!sawDone) {
        const frame = await client.waitForAny();
        const plaintext = client.session.decrypt(frame.payload);
        if (frame.tag === FRAME.ERROR) {
          const body = JSON.parse(new TextDecoder().decode(plaintext));
          expect(body.error.type).toBe('busy');
          sawBusy = true;
        } else if (frame.tag === FRAME.RESPONSE_DONE) {
          sawDone = true;
        }
      }
      expect(sawBusy).toBe(true);
    } finally {
      client.close();
    }
  });
});

// ── Test helpers ─────────────────────────────────────────────────────────────

interface NoiseClient {
  ws: WebSocket;
  session: NoiseSession;
  send: (data: Uint8Array) => void;
  close: () => void;
  waitFor: (tag: number) => Promise<Rx>;
  waitForAny: () => Promise<Rx>;
}

async function connectAndHandshake(
  url: string,
  serverPubKey: Uint8Array,
): Promise<{ client: NoiseClient }> {
  const ws = new WebSocket(`${url}/v1/ws`);
  const queue: Rx[] = [];
  const pending: ((rx: Rx) => void)[] = [];

  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const bytes = toUint8(data);
    const rx = decodeFrame(bytes);
    if (pending.length > 0) pending.shift()!(rx);
    else queue.push(rx);
  });

  await new Promise<void>((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });

  const session = NoiseSession.create({
    pattern: 'NK',
    role: 'initiator',
    remoteStaticKey: serverPubKey as never,
  });

  const msg1 = session.writeHandshake();
  ws.send(encodeFrame(FRAME.HANDSHAKE, msg1));

  const client: NoiseClient = {
    ws,
    session,
    send: (data: Uint8Array) => ws.send(data),
    close: () => ws.close(),
    waitForAny: () =>
      new Promise((resolve) => {
        if (queue.length > 0) resolve(queue.shift()!);
        else pending.push(resolve);
      }),
    waitFor: async (tag: number) => {
      while (true) {
        const frame = await client.waitForAny();
        if (frame.tag === tag) return frame;
        throw new Error(
          `Expected frame 0x${tag.toString(16)}, got 0x${frame.tag.toString(16)}`,
        );
      }
    },
  };

  const hs2 = await client.waitFor(FRAME.HANDSHAKE);
  session.readHandshake(hs2.payload);
  if (session.state !== 'transport') {
    throw new Error(`Expected transport state, got ${session.state}`);
  }

  return { client };
}

function toUint8(data: unknown): Uint8Array {
  if (data instanceof Buffer) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (Array.isArray(data)) {
    return new Uint8Array(Buffer.concat(data as Buffer[]));
  }
  throw new Error('Unknown WS message type');
}
