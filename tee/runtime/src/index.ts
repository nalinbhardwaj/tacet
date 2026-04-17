/**
 * @tacet/tee-runtime — Noise endpoint entrypoint.
 *
 * Environment:
 *   TACET_HOST           — bind host (default 0.0.0.0)
 *   TACET_PORT           — bind port (default 8443)
 *   TACET_VLLM_BASE_URL  — vLLM base URL (default http://127.0.0.1:8000)
 */

import { createNoiseServer } from './server.js';

export { createNoiseServer } from './server.js';
export { Connection } from './connection.js';
export { VllmClient, VllmError } from './vllm.js';
export { FRAME, encodeFrame, decodeFrame } from './framing.js';
export { getStaticKeypair, resetStaticKeypair, publicKeyBase64 } from './keys.js';

async function main(): Promise<void> {
  const host = process.env.TACET_HOST ?? '0.0.0.0';
  const port = Number(process.env.TACET_PORT ?? '8443');
  const vllmBaseUrl = process.env.TACET_VLLM_BASE_URL ?? 'http://127.0.0.1:8000';

  const log = (event: string, details?: Record<string, unknown>) => {
    const line = { t: new Date().toISOString(), event, ...(details ?? {}) };
    console.log(JSON.stringify(line));
  };

  log('boot', { host, port, vllm: vllmBaseUrl });
  const server = await createNoiseServer({ host, port, vllmBaseUrl, log });

  const shutdown = async (sig: string) => {
    log('shutdown', { signal: sig });
    await server.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

// Only run if invoked directly (not when imported from tests).
const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('/dist/server.mjs') === true ||
  process.argv[1]?.endsWith('/dist/index.js') === true;

if (isMain) {
  main().catch((err) => {
    console.error('fatal:', err);
    process.exit(1);
  });
}
