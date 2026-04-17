/**
 * Full-stack E2E for the gateway: browser SDK analogue ↔ gateway (relay) ↔
 * @tacet/tee-runtime Noise endpoint ↔ fake vLLM.
 *
 * The client speaks real Noise NK against the TEE through the gateway, which
 * never decrypts anything. This verifies the relay is actually a transparent
 * pipe: handshake, streaming, non-streaming, and error frames all traverse
 * the gateway unchanged.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import WebSocket from 'ws';
import { NoiseSession } from '@tacet/noise';
import {
  createNoiseServer,
  resetStaticKeypair,
  FRAME,
  encodeFrame,
  decodeFrame,
  type RunningServer,
} from '@tacet/tee-runtime';
import { createGateway, type RunningGateway } from '../src/server.js';
import { ConfigRegistry, type Config } from '../src/configs.js';
import { startFakeVllm, type FakeVllm } from './fake-vllm.js';

const CONFIG_ID = '00000000-0000-4000-8000-000000000001';

interface Rx {
  tag: number;
  payload: Uint8Array;
}

describe('gateway relay E2E', () => {
  let vllm: FakeVllm;
  let tee: RunningServer;
  let gateway: RunningGateway;
  let config: Config;
  let gwHttp: string;
  let gwWs: string;

  beforeAll(async () => {
    resetStaticKeypair();
    vllm = await startFakeVllm({ streamChunks: ['Hel', 'lo', ',', ' world'] });
    tee = await createNoiseServer({
      host: '127.0.0.1',
      port: 0,
      vllmBaseUrl: vllm.url,
    });
    config = {
      id: CONFIG_ID,
      name: 'test',
      tee_url: `http://127.0.0.1:${tee.address.port}`,
      model_name: 'fake',
    };
    gateway = await createGateway({
      host: '127.0.0.1',
      port: 0,
      registry: new ConfigRegistry([config]),
    });
    gwHttp = `http://127.0.0.1:${gateway.address.port}`;
    gwWs = `ws://127.0.0.1:${gateway.address.port}`;
  });

  afterAll(async () => {
    await gateway.close();
    await tee.close();
    await vllm.close();
  });

  beforeEach(() => {
    // Nothing to reset per-test; the TEE's static keypair persists across
    // requests (the runtime rotates only on fresh boot).
  });

  describe('HTTP endpoints', () => {
    it('GET /healthz returns ok', async () => {
      const res = await fetch(`${gwHttp}/healthz`);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe('ok');
    });

    it('GET /v1/configs lists public metadata only', async () => {
      const res = await fetch(`${gwHttp}/v1/configs`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { configs: unknown[] };
      expect(body.configs).toEqual([
        { id: CONFIG_ID, name: 'test', model_name: 'fake' },
      ]);
    });

    it('GET /v1/keys?config_id=... proxies the TEE public key', async () => {
      const res = await fetch(`${gwHttp}/v1/keys?config_id=${CONFIG_ID}`);
      expect(res.status).toBe(200);
      const { public_key } = (await res.json()) as { public_key: string };
      const bytes = Buffer.from(public_key, 'base64');
      expect(bytes.length).toBe(32);
    });

    it('GET /v1/keys with missing config_id returns 400', async () => {
      const res = await fetch(`${gwHttp}/v1/keys`);
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { type: string } };
      expect(body.error.type).toBe('missing_config_id');
    });

    it('GET /v1/keys with unknown config_id returns 404', async () => {
      const res = await fetch(
        `${gwHttp}/v1/keys?config_id=00000000-0000-4000-8000-0000000000ff`,
      );
      expect(res.status).toBe(404);
      const body = (await res.json()) as { error: { type: string } };
      expect(body.error.type).toBe('unknown_config_id');
    });

    it('sets CORS headers', async () => {
      const res = await fetch(`${gwHttp}/v1/configs`);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
    });
  });

  describe('WebSocket relay', () => {
    it('rejects WS upgrade when config_id is unknown', async () => {
      const ws = new WebSocket(
        `${gwWs}/v1/ws?config_id=00000000-0000-4000-8000-0000000000ff`,
      );
      const err = await new Promise<Error>((resolve) => {
        ws.once('error', resolve);
      });
      expect(err.message).toMatch(/404|Unexpected server response/);
    });

    it('completes a full NK handshake and non-streaming request through the gateway', async () => {
      const client = await connectAndHandshake(gwWs, CONFIG_ID);
      try {
        const req = JSON.stringify({
          model: 'test',
          messages: [{ role: 'user', content: 'hi' }],
        });
        client.send(
          encodeFrame(FRAME.REQUEST, client.session.encryptFramed(utf8(req))),
        );
        const done = await client.waitFor(FRAME.RESPONSE_DONE);
        const body = new TextDecoder().decode(
          client.session.decryptFramed(done.payload),
        );
        const parsed = JSON.parse(body);
        expect(parsed.choices[0].message.content).toBe('Hello from fake vLLM');
      } finally {
        client.close();
      }
    });

    it('streams multiple chunks through the gateway', async () => {
      const client = await connectAndHandshake(gwWs, CONFIG_ID);
      try {
        const req = JSON.stringify({
          model: 'test',
          messages: [{ role: 'user', content: 'stream' }],
          stream: true,
        });
        client.send(
          encodeFrame(FRAME.REQUEST, client.session.encryptFramed(utf8(req))),
        );

        const deltas: string[] = [];
        while (true) {
          const frame = await client.waitForAny();
          if (frame.tag === FRAME.RESPONSE_CHUNK) {
            const line = new TextDecoder().decode(
              client.session.decrypt(frame.payload),
            );
            deltas.push(JSON.parse(line).choices[0].delta.content);
            continue;
          }
          if (frame.tag === FRAME.RESPONSE_DONE) break;
          throw new Error(`Unexpected tag 0x${frame.tag.toString(16)}`);
        }
        expect(deltas.join('')).toBe('Hello, world');
      } finally {
        client.close();
      }
    });

    it('buffers client frames sent before upstream WS is open', async () => {
      // The client fires REQUEST immediately after WS open; the gateway must
      // buffer it until the upstream handshake completes. We verify the full
      // handshake + request round-trip succeeds under that timing.
      const client = await connectAndHandshake(gwWs, CONFIG_ID);
      try {
        const req = JSON.stringify({
          model: 'test',
          messages: [{ role: 'user', content: 'buffered' }],
        });
        client.send(
          encodeFrame(FRAME.REQUEST, client.session.encryptFramed(utf8(req))),
        );
        const done = await client.waitFor(FRAME.RESPONSE_DONE);
        const body = new TextDecoder().decode(
          client.session.decryptFramed(done.payload),
        );
        expect(JSON.parse(body).choices[0].message.content).toBe(
          'Hello from fake vLLM',
        );
      } finally {
        client.close();
      }
    });
  });

  describe('relay errors', () => {
    it('emits a plaintext ERROR frame when the TEE is unreachable', async () => {
      // Separate gateway pointing at a dead TEE URL.
      const deadConfig: Config = {
        id: '00000000-0000-4000-8000-0000000000aa',
        name: 'dead',
        tee_url: 'http://127.0.0.1:1', // port 1 → connection refused
        model_name: 'none',
      };
      const gw2 = await createGateway({
        host: '127.0.0.1',
        port: 0,
        registry: new ConfigRegistry([deadConfig]),
      });
      try {
        const ws = new WebSocket(
          `ws://127.0.0.1:${gw2.address.port}/v1/ws?config_id=${deadConfig.id}`,
        );
        await new Promise<void>((ok, err) => {
          ws.once('open', ok);
          ws.once('error', err);
        });

        const frame = await new Promise<Rx>((resolve, reject) => {
          ws.once('message', (data, isBinary) => {
            if (!isBinary) return reject(new Error('expected binary'));
            resolve(decodeFrame(toUint8(data)));
          });
          ws.once('close', () => reject(new Error('closed before error frame')));
        });
        expect(frame.tag).toBe(FRAME.ERROR);
        const body = JSON.parse(new TextDecoder().decode(frame.payload));
        expect(body.error.type).toBe('upstream_connect_failed');
        ws.close();
      } finally {
        await gw2.close();
      }
    });
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
  gwWs: string,
  configId: string,
): Promise<NoiseClient> {
  // Fetch the TEE's public key via the gateway's key-proxy endpoint — this
  // is what the browser SDK will do.
  const gwHttp = gwWs.replace(/^ws/, 'http');
  const keysRes = await fetch(`${gwHttp}/v1/keys?config_id=${configId}`);
  if (!keysRes.ok) {
    throw new Error(`gateway /v1/keys returned ${keysRes.status}`);
  }
  const { public_key } = (await keysRes.json()) as { public_key: string };
  const remoteStaticKey = new Uint8Array(Buffer.from(public_key, 'base64'));

  const ws = new WebSocket(`${gwWs}/v1/ws?config_id=${configId}`);
  const queue: Rx[] = [];
  const pending: ((rx: Rx) => void)[] = [];

  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const rx = decodeFrame(toUint8(data));
    if (pending.length > 0) pending.shift()!(rx);
    else queue.push(rx);
  });

  await new Promise<void>((ok, err) => {
    ws.once('open', ok);
    ws.once('error', err);
  });

  const session = NoiseSession.create({
    pattern: 'NK',
    role: 'initiator',
    remoteStaticKey: remoteStaticKey as never,
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
      const frame = await client.waitForAny();
      if (frame.tag !== tag) {
        throw new Error(
          `Expected frame 0x${tag.toString(16)}, got 0x${frame.tag.toString(16)}`,
        );
      }
      return frame;
    },
  };

  const hs2 = await client.waitFor(FRAME.HANDSHAKE);
  session.readHandshake(hs2.payload);
  if (session.state !== 'transport') {
    throw new Error(`Expected transport state, got ${session.state}`);
  }
  return client;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function toUint8(data: unknown): Uint8Array {
  if (data instanceof Buffer) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data as Buffer[]));
  throw new Error('unknown ws data type');
}
