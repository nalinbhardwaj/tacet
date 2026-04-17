/**
 * End-to-end smoke test: client ↔ gateway ↔ TEE Noise endpoint ↔ vLLM.
 *
 * Runs a real Noise NK handshake against a deployed gateway + TEE and
 * exercises both non-streaming and streaming inference. The gateway only
 * sees opaque binary frames — decryption happens here.
 *
 * Usage:
 *   GATEWAY_URL=http://vast-host:8080 \
 *   CONFIG_ID=00000000-0000-4000-8000-000000000001 \
 *   MODEL_NAME=Qwen/Qwen2.5-0.5B-Instruct \
 *   pnpm --dir gateway exec tsx scripts/smoke.ts
 *
 * Env:
 *   GATEWAY_URL   http:// or https:// URL of the gateway (required)
 *   CONFIG_ID     UUID matching a row in configs.json (required)
 *   MODEL_NAME    model name to send to vLLM (default: /models/current)
 *   MAX_TOKENS    max tokens per completion (default: 40)
 */

import WebSocket from 'ws';
import { NoiseSession } from '@tacet/noise';
import { FRAME, encodeFrame, decodeFrame } from '@tacet/tee-runtime';

const GATEWAY_URL = requireEnv('GATEWAY_URL');
const CONFIG_ID = requireEnv('CONFIG_ID');
const MODEL_NAME = process.env.MODEL_NAME ?? '/models/current';
const MAX_TOKENS = Number(process.env.MAX_TOKENS ?? '40');
const WS_URL = GATEWAY_URL.replace(/^http/, 'ws');

interface Rx {
  tag: number;
  payload: Uint8Array;
}

async function main(): Promise<void> {
  console.log(`\nSmoke testing gateway at ${GATEWAY_URL}`);
  console.log(`Config: ${CONFIG_ID}, model: ${MODEL_NAME}\n`);

  await step('GET /healthz', async () => {
    const res = await fetch(`${GATEWAY_URL}/healthz`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const body = await res.text();
    if (body !== 'ok') throw new Error(`unexpected body: ${body}`);
  });

  await step('GET /v1/configs', async () => {
    const res = await fetch(`${GATEWAY_URL}/v1/configs`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const body = (await res.json()) as { configs: { id: string; name: string }[] };
    const found = body.configs.find((c) => c.id === CONFIG_ID);
    if (!found) throw new Error(`config ${CONFIG_ID} not listed`);
    console.log(`    found: ${found.name}`);
  });

  const pubKey = await step('GET /v1/keys (proxied from TEE)', async () => {
    const res = await fetch(`${GATEWAY_URL}/v1/keys?config_id=${CONFIG_ID}`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const { public_key } = (await res.json()) as { public_key: string };
    const bytes = new Uint8Array(Buffer.from(public_key, 'base64'));
    if (bytes.length !== 32) throw new Error(`expected 32B key, got ${bytes.length}`);
    console.log(`    key: ${public_key.slice(0, 16)}...`);
    return bytes;
  });

  // Open one WS connection per test to keep things simple — a fresh Noise
  // session per inference call. In production the SDK would reuse a session.

  await step('Non-streaming chat completion (encrypted)', async () => {
    const client = await connectAndHandshake(pubKey);
    try {
      const reqJson = JSON.stringify({
        model: MODEL_NAME,
        messages: [{ role: 'user', content: 'Say hello in one sentence.' }],
        max_tokens: MAX_TOKENS,
      });
      const t0 = Date.now();
      client.ws.send(
        encodeFrame(
          FRAME.REQUEST,
          client.session.encryptFramed(new TextEncoder().encode(reqJson)),
        ),
      );
      const done = await client.waitFor(FRAME.RESPONSE_DONE);
      const body = new TextDecoder().decode(
        client.session.decryptFramed(done.payload),
      );
      const parsed = JSON.parse(body) as {
        choices: { message: { content: string } }[];
        usage?: Record<string, number>;
      };
      const content = parsed.choices[0]?.message?.content ?? '';
      if (!content.trim()) throw new Error('empty completion');
      const dt = Date.now() - t0;
      console.log(`    response (${dt}ms): ${content}`);
      if (parsed.usage) console.log(`    usage: ${JSON.stringify(parsed.usage)}`);
    } finally {
      client.ws.close();
    }
  });

  await step('Streaming chat completion (encrypted)', async () => {
    const client = await connectAndHandshake(pubKey);
    try {
      const reqJson = JSON.stringify({
        model: MODEL_NAME,
        messages: [{ role: 'user', content: 'Count from 1 to 5.' }],
        max_tokens: MAX_TOKENS,
        stream: true,
      });
      const t0 = Date.now();
      client.ws.send(
        encodeFrame(
          FRAME.REQUEST,
          client.session.encryptFramed(new TextEncoder().encode(reqJson)),
        ),
      );

      let chunks = 0;
      let content = '';
      while (true) {
        const frame = await client.waitForAny();
        if (frame.tag === FRAME.RESPONSE_CHUNK) {
          const line = new TextDecoder().decode(
            client.session.decrypt(frame.payload),
          );
          chunks += 1;
          try {
            const parsed = JSON.parse(line) as {
              choices: { delta?: { content?: string } }[];
            };
            content += parsed.choices[0]?.delta?.content ?? '';
          } catch {
            // ignore non-JSON SSE lines
          }
          continue;
        }
        if (frame.tag === FRAME.RESPONSE_DONE) break;
        if (frame.tag === FRAME.ERROR) {
          const err = JSON.parse(
            new TextDecoder().decode(client.session.decrypt(frame.payload)),
          );
          throw new Error(`server error: ${JSON.stringify(err)}`);
        }
        throw new Error(`unexpected tag 0x${frame.tag.toString(16)}`);
      }
      if (chunks === 0) throw new Error('no chunks received');
      const dt = Date.now() - t0;
      console.log(`    chunks: ${chunks} (${dt}ms)`);
      console.log(`    content: ${content}`);
    } finally {
      client.ws.close();
    }
  });

  console.log('\nAll checks passed.\n');
}

// ── helpers ─────────────────────────────────────────────────────────────────

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required env: ${name}`);
    process.exit(2);
  }
  return v;
}

async function step<T>(label: string, fn: () => Promise<T>): Promise<T> {
  process.stdout.write(`→ ${label}\n`);
  try {
    const result = await fn();
    process.stdout.write(`  OK\n`);
    return result as T;
  } catch (err) {
    process.stdout.write(`  FAIL: ${(err as Error).message}\n`);
    throw err;
  }
}

interface Client {
  ws: WebSocket;
  session: NoiseSession;
  waitFor: (tag: number) => Promise<Rx>;
  waitForAny: () => Promise<Rx>;
}

async function connectAndHandshake(remoteStaticKey: Uint8Array): Promise<Client> {
  const ws = new WebSocket(`${WS_URL}/v1/ws?config_id=${CONFIG_ID}`);
  const queue: Rx[] = [];
  const pending: ((rx: Rx) => void)[] = [];

  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const bytes = toUint8(data);
    const rx = decodeFrame(bytes);
    if (pending.length > 0) pending.shift()!(rx);
    else queue.push(rx);
  });

  await new Promise<void>((ok, err) => {
    ws.once('open', () => ok());
    ws.once('error', err);
  });

  const session = NoiseSession.create({
    pattern: 'NK',
    role: 'initiator',
    remoteStaticKey: remoteStaticKey as never,
  });

  ws.send(encodeFrame(FRAME.HANDSHAKE, session.writeHandshake()));

  const waitForAny = (): Promise<Rx> =>
    new Promise((resolve) => {
      if (queue.length > 0) resolve(queue.shift()!);
      else pending.push(resolve);
    });
  const waitFor = async (tag: number): Promise<Rx> => {
    const frame = await waitForAny();
    if (frame.tag !== tag) {
      throw new Error(
        `expected tag 0x${tag.toString(16)}, got 0x${frame.tag.toString(16)}`,
      );
    }
    return frame;
  };

  const hs2 = await waitFor(FRAME.HANDSHAKE);
  session.readHandshake(hs2.payload);
  if (session.state !== 'transport') {
    throw new Error(`handshake stalled in state: ${session.state}`);
  }
  return { ws, session, waitFor, waitForAny };
}

function toUint8(data: unknown): Uint8Array {
  if (data instanceof Buffer) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data as Buffer[]));
  throw new Error('unknown ws data type');
}

main().catch((err) => {
  console.error(`\nFAILED: ${err.message}\n`);
  process.exit(1);
});
