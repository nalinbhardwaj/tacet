/**
 * HTTP + WebSocket server for the Tacet Noise endpoint.
 *
 * Exposes:
 *   GET  /v1/keys    → { public_key: <base64 X25519> }
 *   GET  /healthz    → "ok"
 *   WS   /v1/ws      → Noise NK channel to vLLM
 *
 * Binds a single port. In Step 9 we add attestation to /v1/keys and
 * add dm-verity/attestation-quote payloads.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { getStaticKeypair, publicKeyBase64 } from './keys.js';
import { Connection } from './connection.js';
import { VllmClient } from './vllm.js';

export interface ServerOptions {
  host: string;
  port: number;
  vllmBaseUrl: string;
  log?: (event: string, details?: Record<string, unknown>) => void;
}

export interface RunningServer {
  http: Server;
  wss: WebSocketServer;
  address: { host: string; port: number };
  close(): Promise<void>;
}

export function createNoiseServer(opts: ServerOptions): Promise<RunningServer> {
  const log = opts.log ?? (() => {});
  const vllm = new VllmClient({ baseUrl: opts.vllmBaseUrl });

  const http = createServer((req, res) => handleHttp(req, res, log));
  const wss = new WebSocketServer({ noServer: true });

  http.on('upgrade', (req, socket, head) => {
    if (req.url !== '/v1/ws' && !req.url?.startsWith('/v1/ws?')) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });

  wss.on('connection', (ws) => handleWs(ws, vllm, log));

  return new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(opts.port, opts.host, () => {
      http.off('error', reject);
      const addr = http.address();
      const bound =
        typeof addr === 'object' && addr
          ? { host: addr.address, port: addr.port }
          : { host: opts.host, port: opts.port };
      log('listening', bound);
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

function handleHttp(
  req: IncomingMessage,
  res: ServerResponse,
  log: (event: string, details?: Record<string, unknown>) => void,
): void {
  const url = req.url ?? '/';
  if (req.method === 'GET' && url === '/v1/keys') {
    // Warm up the keypair cache (generate on first request).
    getStaticKeypair();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ public_key: publicKeyBase64() }));
    return;
  }
  if (req.method === 'GET' && url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  log('http_not_found', { method: req.method, url });
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: { type: 'not_found', message: `${req.method} ${url}` } }));
}

function handleWs(
  ws: WebSocket,
  vllm: VllmClient,
  log: (event: string, details?: Record<string, unknown>) => void,
): void {
  const conn = new Connection({
    staticKeypair: getStaticKeypair(),
    vllm,
    send: (data) => {
      if (ws.readyState === ws.OPEN) ws.send(data);
    },
    close: (code, reason) => {
      try {
        ws.close(code, reason);
      } catch {
        // ignore
      }
    },
    log,
  });

  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      log('ws_text_frame_ignored');
      try {
        ws.close(1003, 'binary_only');
      } catch {
        // ignore
      }
      return;
    }
    const bytes =
      data instanceof Buffer
        ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
        : Array.isArray(data)
          ? new Uint8Array(Buffer.concat(data))
          : new Uint8Array(data as ArrayBuffer);
    conn.onFrame(bytes).catch((err: unknown) => {
      log('connection_error', { message: (err as Error).message });
    });
  });

  ws.on('close', () => log('ws_close'));
  ws.on('error', (err) => log('ws_error', { message: err.message }));
}
