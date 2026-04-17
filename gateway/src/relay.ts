/**
 * Bidirectional binary relay between a browser WebSocket and the TEE's WS.
 *
 * The gateway is untrusted: we do not parse, decrypt, or inspect frames in
 * the transport direction. The Noise handshake and all subsequent traffic
 * flow through as opaque binary buffers.
 *
 * Lifecycle:
 *   1. Resolve config_id → TEE url.
 *   2. Open a WS to `{tee_url}/v1/ws`.
 *   3. While upstream is CONNECTING, buffer client→TEE frames. Reject
 *      upstream→client frames during this window (there shouldn't be any).
 *   4. Once OPEN, flush buffered frames and relay 1:1.
 *   5. If either side closes/errors, close the other with a matching code.
 *
 * Pre-handshake errors (invalid config_id, TEE unreachable) are emitted as
 * plaintext ERROR frames (tag 0x05) on the client socket before close.
 */

import WebSocket, { type RawData } from 'ws';
import type { Config } from './configs.js';
import { encodePlaintextError } from './framing.js';

type Logger = (event: string, details?: Record<string, unknown>) => void;

export interface ClientSocket {
  readyState: number;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  on(event: 'message', listener: (data: RawData, isBinary: boolean) => void): void;
  on(event: 'close', listener: () => void): void;
  on(event: 'error', listener: (err: Error) => void): void;
}

export interface StartRelayOptions {
  client: ClientSocket;
  config: Config;
  /** Override WebSocket constructor (tests). */
  wsFactory?: (url: string) => WebSocket;
  log?: Logger;
}

/**
 * Wire up a client WebSocket to a fresh upstream WebSocket pointing at the
 * config's TEE. Returns once both sockets have been wired up; the relay
 * itself runs until one side closes.
 */
export function startRelay(opts: StartRelayOptions): void {
  const { client, config } = opts;
  const log = opts.log ?? (() => {});

  const upstreamUrl = toWsUrl(config.tee_url) + '/v1/ws';
  const factory = opts.wsFactory ?? ((u: string) => new WebSocket(u));

  let upstream: WebSocket;
  try {
    upstream = factory(upstreamUrl);
  } catch (err) {
    sendPlaintextErrorAndClose(
      client,
      'upstream_connect_failed',
      (err as Error).message,
      log,
    );
    return;
  }

  // Force binary-as-Buffer so we can forward without re-encoding.
  (upstream as { binaryType?: string }).binaryType = 'nodebuffer';

  /** Frames received from client before upstream is OPEN. */
  const pending: Uint8Array[] = [];
  let upstreamOpen = false;
  let closed = false;

  const closeBoth = (code: number, reason: string) => {
    if (closed) return;
    closed = true;
    try {
      client.close(code, reason);
    } catch {
      // ignore
    }
    try {
      upstream.close(code, reason);
    } catch {
      // ignore
    }
  };

  upstream.on('open', () => {
    upstreamOpen = true;
    log('upstream_open', { config_id: config.id, url: upstreamUrl });
    for (const frame of pending) {
      try {
        upstream.send(frame, { binary: true });
      } catch (err) {
        log('upstream_send_failed', { message: (err as Error).message });
        closeBoth(1011, 'upstream_send_failed');
        return;
      }
    }
    pending.length = 0;
  });

  upstream.on('message', (data, isBinary) => {
    if (!isBinary) {
      log('upstream_text_frame_ignored');
      return;
    }
    if (client.readyState !== WebSocket.OPEN) return;
    try {
      client.send(toUint8(data));
    } catch (err) {
      log('client_send_failed', { message: (err as Error).message });
      closeBoth(1011, 'client_send_failed');
    }
  });

  upstream.on('close', (code, reason) => {
    log('upstream_close', { code, reason: reason?.toString() });
    // Sanitize close codes we can't re-emit (e.g. 1006 is reserved).
    const safeCode = isValidWsCloseCode(code) ? code : 1011;
    closeBoth(safeCode, reason?.toString() || 'upstream_closed');
  });

  upstream.on('error', (err) => {
    log('upstream_error', { message: err.message });
    if (!upstreamOpen) {
      // Still CONNECTING — the SDK hasn't seen any bytes yet, so we can send
      // a plaintext gateway-level error frame before closing.
      sendPlaintextErrorAndClose(client, 'upstream_connect_failed', err.message, log);
      closed = true;
      return;
    }
    closeBoth(1011, 'upstream_error');
  });

  client.on('message', (data, isBinary) => {
    if (!isBinary) {
      log('client_text_frame_ignored');
      closeBoth(1003, 'binary_only');
      return;
    }
    const bytes = toUint8(data);
    if (!upstreamOpen) {
      pending.push(bytes);
      return;
    }
    try {
      upstream.send(bytes, { binary: true });
    } catch (err) {
      log('upstream_send_failed', { message: (err as Error).message });
      closeBoth(1011, 'upstream_send_failed');
    }
  });

  client.on('close', () => {
    log('client_close', { config_id: config.id });
    closeBoth(1000, 'client_closed');
  });

  client.on('error', (err) => {
    log('client_error', { message: err.message });
    closeBoth(1011, 'client_error');
  });
}

function toWsUrl(httpUrl: string): string {
  if (httpUrl.startsWith('https://')) return 'wss://' + httpUrl.slice('https://'.length);
  if (httpUrl.startsWith('http://')) return 'ws://' + httpUrl.slice('http://'.length);
  if (httpUrl.startsWith('wss://') || httpUrl.startsWith('ws://')) return httpUrl;
  throw new Error(`Cannot derive WebSocket URL from ${httpUrl}`);
}

function toUint8(data: RawData): Uint8Array {
  if (data instanceof Buffer) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (Array.isArray(data)) {
    return new Uint8Array(Buffer.concat(data));
  }
  return new Uint8Array(data as ArrayBuffer);
}

function sendPlaintextErrorAndClose(
  client: ClientSocket,
  code: string,
  message: string,
  log: Logger,
): void {
  try {
    if (client.readyState === WebSocket.OPEN) {
      client.send(encodePlaintextError(code, message));
    }
  } catch (err) {
    log('client_error_send_failed', { message: (err as Error).message });
  }
  try {
    client.close(1011, code);
  } catch {
    // ignore
  }
}

function isValidWsCloseCode(code: number): boolean {
  // Per RFC 6455: 1000-2999 registered, 3000-4999 application. 1005/1006 are
  // reserved and must not be sent on the wire.
  if (code === 1005 || code === 1006) return false;
  return code >= 1000 && code <= 4999;
}
