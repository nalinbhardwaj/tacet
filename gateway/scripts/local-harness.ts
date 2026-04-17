/**
 * Local harness that mimics the cloud topology on loopback: fake vLLM +
 * @tacet/tee-runtime + gateway, all bound to 127.0.0.1 on deterministic
 * ports. Lets us dry-run scripts/smoke.ts before paying for GPU time.
 *
 * Usage:
 *   pnpm --dir gateway exec tsx scripts/local-harness.ts &
 *   GATEWAY_URL=http://127.0.0.1:18080 \
 *   CONFIG_ID=00000000-0000-4000-8000-000000000001 \
 *   MODEL_NAME=fake \
 *   pnpm --dir gateway smoke
 */

import { createServer, type Server, type ServerResponse } from 'node:http';
import { createNoiseServer } from '@tacet/tee-runtime';
import { createGateway } from '../src/server.js';
import { ConfigRegistry } from '../src/configs.js';

const CONFIG_ID = '00000000-0000-4000-8000-000000000001';
const VLLM_PORT = 18000;
const TEE_PORT = 18443;
const GW_PORT = 18080;

async function main(): Promise<void> {
  const vllm = await startFakeVllm(VLLM_PORT);
  const tee = await createNoiseServer({
    host: '127.0.0.1',
    port: TEE_PORT,
    vllmBaseUrl: `http://127.0.0.1:${VLLM_PORT}`,
    log: (e, d) => console.log(JSON.stringify({ src: 'tee', e, ...d })),
  });
  const gateway = await createGateway({
    host: '127.0.0.1',
    port: GW_PORT,
    registry: new ConfigRegistry([
      {
        id: CONFIG_ID,
        name: 'local',
        tee_url: `http://127.0.0.1:${TEE_PORT}`,
        model_name: 'fake',
      },
    ]),
    log: (e, d) => console.log(JSON.stringify({ src: 'gw', e, ...d })),
  });

  console.log(`\nHarness ready.`);
  console.log(`  fake vLLM:  http://127.0.0.1:${VLLM_PORT}`);
  console.log(`  tee-runtime: http://127.0.0.1:${TEE_PORT}`);
  console.log(`  gateway:     http://127.0.0.1:${GW_PORT}`);
  console.log(`\nRun smoke:`);
  console.log(
    `  GATEWAY_URL=http://127.0.0.1:${GW_PORT} CONFIG_ID=${CONFIG_ID} MODEL_NAME=fake pnpm --dir gateway smoke`,
  );
  console.log(`\nCtrl-C to stop.\n`);

  const shutdown = async () => {
    await gateway.close();
    await tee.close();
    vllm.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function startFakeVllm(port: number): Promise<{ close: () => void }> {
  return new Promise((resolve) => {
    const server: Server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks).toString('utf8');
      if (req.url !== '/v1/chat/completions' || req.method !== 'POST') {
        res.writeHead(404);
        res.end();
        return;
      }
      const parsed = JSON.parse(body) as { stream?: boolean };
      if (!parsed.stream) {
        nonStream(res);
      } else {
        stream(res);
      }
    });
    server.listen(port, '127.0.0.1', () => resolve({ close: () => server.close() }));
  });
}

function nonStream(res: ServerResponse): void {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      id: 'cmpl-local',
      object: 'chat.completion',
      created: 0,
      model: 'fake',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: 'hello from the local harness' },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 6, total_tokens: 7 },
    }),
  );
}

function stream(res: ServerResponse): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Transfer-Encoding': 'chunked',
  });
  for (const delta of ['one ', 'two ', 'three ', 'four ', 'five']) {
    res.write(
      `data: ${JSON.stringify({
        id: 'cmpl-local',
        choices: [{ index: 0, delta: { content: delta } }],
      })}\n\n`,
    );
  }
  res.write('data: [DONE]\n\n');
  res.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
