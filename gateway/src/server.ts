/**
 * HTTP + WebSocket server for the Tacet gateway.
 *
 * Exposes:
 *   GET  /v1/configs                → [{id, name, model_name}, ...]
 *   GET  /v1/keys?config_id=<uuid>  → raw JSON proxied from TEE's /v1/keys
 *   GET  /healthz                   → "ok"
 *   WS   /v1/ws?config_id=<uuid>    → opaque binary relay to the TEE's WS
 *
 * The gateway never reads or decrypts Noise traffic — WS frames are copied
 * between the client and upstream sockets byte-for-byte.
 */

import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import type { ConfigRegistry } from './configs.js';
import { KeyCache, KeyFetchError } from './keys.js';
import { startRelay } from './relay.js';
import { encodePlaintextError } from './framing.js';

type Logger = (event: string, details?: Record<string, unknown>) => void;

export interface GatewayOptions {
  host: string;
  port: number;
  registry: ConfigRegistry;
  keyCache?: KeyCache;
  log?: Logger;
}

export interface RunningGateway {
  http: Server;
  wss: WebSocketServer;
  address: { host: string; port: number };
  close(): Promise<void>;
}

export function createGateway(opts: GatewayOptions): Promise<RunningGateway> {
  const log = opts.log ?? (() => {});
  const keyCache = opts.keyCache ?? new KeyCache();
  const { registry } = opts;

  const http = createServer((req, res) => {
    handleHttp(req, res, registry, keyCache, log).catch((err: unknown) => {
      log('http_handler_failed', { message: (err as Error).message });
      if (!res.headersSent) {
        writeJson(res, 500, { error: { type: 'internal_error', message: 'gateway error' } });
      }
    });
  });

  const wss = new WebSocketServer({ noServer: true });

  http.on('upgrade', (req, socket, head) => {
    const parsed = parseUrl(req.url ?? '/');
    if (parsed.pathname !== '/v1/ws') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    const configId = parsed.query.get('config_id');
    if (!configId) {
      log('ws_missing_config_id');
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\nmissing config_id');
      socket.destroy();
      return;
    }
    const config = registry.get(configId);
    if (!config) {
      log('ws_unknown_config_id', { config_id: configId });
      socket.write('HTTP/1.1 404 Not Found\r\n\r\nunknown config_id');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleWs(ws, config, log);
    });
  });

  return new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(opts.port, opts.host, () => {
      http.off('error', reject);
      const addr = http.address();
      const bound =
        typeof addr === 'object' && addr
          ? { host: addr.address, port: addr.port }
          : { host: opts.host, port: opts.port };
      log('listening', { ...bound, configs: registry.size() });
      resolve({
        http,
        wss,
        address: bound,
        close: () =>
          new Promise<void>((ok) => {
            wss.close(() => http.close(() => ok()));
          }),
      });
    });
  });
}

async function handleHttp(
  req: IncomingMessage,
  res: ServerResponse,
  registry: ConfigRegistry,
  keyCache: KeyCache,
  log: Logger,
): Promise<void> {
  applyCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const { pathname, query } = parseUrl(req.url ?? '/');

  if (req.method === 'GET' && pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.method === 'GET' && pathname === '/v1/configs') {
    writeJson(res, 200, { configs: registry.list() });
    return;
  }

  if (req.method === 'GET' && pathname === '/v1/keys') {
    const configId = query.get('config_id');
    if (!configId) {
      writeJson(res, 400, {
        error: { type: 'missing_config_id', message: 'config_id query parameter is required' },
      });
      return;
    }
    const config = registry.get(configId);
    if (!config) {
      writeJson(res, 404, {
        error: { type: 'unknown_config_id', message: `No config matches ${configId}` },
      });
      return;
    }
    try {
      const body = await keyCache.get(config);
      res.writeHead(200, { 'Content-Type': 'application/json', ...corsHeaders });
      res.end(body);
    } catch (err) {
      if (err instanceof KeyFetchError) {
        log('keys_proxy_upstream_error', { config_id: configId, status: err.status });
        writeJson(res, 502, {
          error: { type: 'upstream_error', message: err.message, upstream_status: err.status },
        });
      } else {
        log('keys_proxy_failed', { config_id: configId, message: (err as Error).message });
        writeJson(res, 502, {
          error: { type: 'upstream_unreachable', message: (err as Error).message },
        });
      }
    }
    return;
  }

  log('http_not_found', { method: req.method, url: req.url });
  writeJson(res, 404, { error: { type: 'not_found', message: `${req.method} ${req.url}` } });
}

function handleWs(
  ws: WebSocket,
  config: import('./configs.js').Config,
  log: Logger,
): void {
  // Surface upstream errors on the client socket if upstream dies before
  // any message was exchanged. `startRelay` handles the rest.
  log('ws_open', { config_id: config.id });
  try {
    startRelay({ client: ws, config, log });
  } catch (err) {
    log('relay_setup_failed', { message: (err as Error).message });
    try {
      ws.send(encodePlaintextError('relay_setup_failed', (err as Error).message));
      ws.close(1011, 'relay_setup_failed');
    } catch {
      // ignore
    }
  }
}

function parseUrl(raw: string): { pathname: string; query: URLSearchParams } {
  // IncomingMessage.url is path-only, so give URL a dummy origin.
  const u = new URL(raw, 'http://gateway.local');
  return { pathname: u.pathname, query: u.searchParams };
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function applyCors(res: ServerResponse): void {
  for (const [k, v] of Object.entries(corsHeaders)) res.setHeader(k, v);
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders });
  res.end(JSON.stringify(body));
}
