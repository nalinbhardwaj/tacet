/**
 * @tacet/gateway — untrusted WebSocket relay.
 *
 * Environment:
 *   TACET_GATEWAY_HOST       — bind host (default 0.0.0.0)
 *   TACET_GATEWAY_PORT       — bind port (default 8080)
 *   TACET_GATEWAY_CONFIGS    — path to configs.json (default ./configs.json)
 *   TACET_GATEWAY_KEYS_TTL   — key cache TTL in seconds (default 30)
 */

import { resolve } from 'node:path';
import { createGateway } from './server.js';
import { loadConfigsFromFile } from './configs.js';
import { KeyCache } from './keys.js';

export { createGateway } from './server.js';
export { loadConfigsFromFile, ConfigRegistry, ConfigSchema, type Config } from './configs.js';
export { KeyCache, KeyFetchError } from './keys.js';
export { startRelay } from './relay.js';
export { encodePlaintextError, FRAME_ERROR } from './framing.js';

async function main(): Promise<void> {
  const host = process.env.TACET_GATEWAY_HOST ?? '0.0.0.0';
  const port = Number(process.env.TACET_GATEWAY_PORT ?? '8080');
  const configsPath = resolve(
    process.cwd(),
    process.env.TACET_GATEWAY_CONFIGS ?? 'configs.json',
  );
  const ttlMs = Number(process.env.TACET_GATEWAY_KEYS_TTL ?? '30') * 1000;

  const log = (event: string, details?: Record<string, unknown>) => {
    const line = { t: new Date().toISOString(), event, ...(details ?? {}) };
    console.log(JSON.stringify(line));
  };

  log('boot', { host, port, configsPath, keysTtlMs: ttlMs });
  const registry = loadConfigsFromFile(configsPath);
  log('configs_loaded', { count: registry.size() });

  const server = await createGateway({
    host,
    port,
    registry,
    keyCache: new KeyCache({ ttlMs }),
    log,
  });

  const shutdown = async (sig: string) => {
    log('shutdown', { signal: sig });
    await server.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('/dist/index.js') === true;

if (isMain) {
  main().catch((err) => {
    console.error('fatal:', err);
    process.exit(1);
  });
}
