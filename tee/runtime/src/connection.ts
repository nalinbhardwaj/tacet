/**
 * Per-WebSocket-connection state machine.
 *
 * Lifecycle:
 *   1. Handshake phase — client and server exchange two NK messages
 *      (tag 0x01 in both directions). On this first-pass we send an empty
 *      payload in each direction; the first request flows as a transport
 *      message after the handshake completes.
 *   2. Transport phase — client sends REQUEST (0x02), server forwards to
 *      vLLM, streams RESPONSE_CHUNK (0x03) frames, terminates with
 *      RESPONSE_DONE (0x04). Requests are serialized per connection.
 *
 * Any error after handshake is sent as an encrypted ERROR (0x05) frame.
 * Pre-handshake errors are sent as plaintext JSON ERROR frames (no keys
 * available).
 */

import { NoiseSession, type KeyPair, type NoiseSessionConfig } from '@tacet/noise';
import { FRAME, encodeFrame, decodeFrame } from './framing.js';
import { VllmClient, VllmError } from './vllm.js';

type Phase = 'handshake' | 'transport' | 'closed';

export interface ConnectionOptions {
  staticKeypair: KeyPair;
  vllm: VllmClient;
  /** Called when the connection should write a frame to the underlying WS. */
  send: (data: Uint8Array) => void;
  /** Called when the connection should close the underlying WS. */
  close: (code: number, reason: string) => void;
  /** Optional logger for structured events. */
  log?: (event: string, details?: Record<string, unknown>) => void;
}

export class Connection {
  private readonly opts: ConnectionOptions;
  private readonly session: NoiseSession;
  private phase: Phase = 'handshake';
  /** One-at-a-time request serialization. */
  private inFlight = false;

  constructor(opts: ConnectionOptions) {
    this.opts = opts;
    this.session = NoiseSession.create({
      pattern: 'NK',
      role: 'responder',
      staticKeypair: opts.staticKeypair as NoiseSessionConfig['staticKeypair'],
    });
  }

  /** Entry point: feed a raw WS binary frame into the state machine. */
  async onFrame(raw: Uint8Array): Promise<void> {
    if (this.phase === 'closed') return;

    let frame;
    try {
      frame = decodeFrame(raw);
    } catch (err) {
      this.fatal('invalid_frame', (err as Error).message);
      return;
    }

    if (this.phase === 'handshake') {
      if (frame.tag !== FRAME.HANDSHAKE) {
        this.fatal('expected_handshake', `got tag 0x${frame.tag.toString(16)}`);
        return;
      }
      await this.handleHandshake(frame.payload);
      return;
    }

    // transport phase
    if (frame.tag !== FRAME.REQUEST) {
      this.fatal('unexpected_frame', `tag 0x${frame.tag.toString(16)} in transport phase`);
      return;
    }
    if (this.inFlight) {
      this.sendError('busy', 'Another request is already in flight on this connection');
      return;
    }
    this.inFlight = true;
    try {
      await this.handleRequest(frame.payload);
    } finally {
      this.inFlight = false;
    }
  }

  private async handleHandshake(payload: Uint8Array): Promise<void> {
    try {
      this.session.readHandshake(payload);
    } catch (err) {
      this.fatal('handshake_read_failed', (err as Error).message);
      return;
    }
    let reply: Uint8Array;
    try {
      reply = this.session.writeHandshake();
    } catch (err) {
      this.fatal('handshake_write_failed', (err as Error).message);
      return;
    }
    this.opts.send(encodeFrame(FRAME.HANDSHAKE, reply));
    this.phase = 'transport';
    this.opts.log?.('handshake_complete');
  }

  private async handleRequest(payload: Uint8Array): Promise<void> {
    let requestJson: string;
    try {
      const plaintext = this.session.decryptFramed(payload);
      requestJson = new TextDecoder().decode(plaintext);
    } catch (err) {
      this.sendError('decrypt_failed', (err as Error).message);
      return;
    }

    let result;
    try {
      result = await this.opts.vllm.chatCompletions(requestJson);
    } catch (err) {
      if (err instanceof VllmError) {
        this.sendError('vllm_error', err.message, err.status);
      } else {
        this.sendError('vllm_unreachable', (err as Error).message);
      }
      return;
    }

    if (!result.streaming) {
      const bodyBytes = new TextEncoder().encode(result.body!);
      this.sendEncrypted(FRAME.RESPONSE_DONE, bodyBytes, { framed: true });
      return;
    }

    const encoder = new TextEncoder();
    try {
      for await (const chunk of result.stream!) {
        if (chunk.data === '[DONE]') {
          this.sendEncrypted(FRAME.RESPONSE_DONE, encoder.encode('[DONE]'));
          return;
        }
        this.sendEncrypted(FRAME.RESPONSE_CHUNK, encoder.encode(chunk.data));
      }
      // vLLM stream ended without an explicit [DONE]; signal end anyway.
      this.sendEncrypted(FRAME.RESPONSE_DONE, encoder.encode('[DONE]'));
    } catch (err) {
      this.sendError('stream_failed', (err as Error).message);
    }
  }

  private sendEncrypted(
    tag: typeof FRAME.RESPONSE_CHUNK | typeof FRAME.RESPONSE_DONE | typeof FRAME.ERROR,
    plaintext: Uint8Array,
    opts: { framed?: boolean } = {},
  ): void {
    try {
      const ct = opts.framed
        ? this.session.encryptFramed(plaintext)
        : this.session.encrypt(plaintext);
      this.opts.send(encodeFrame(tag, ct));
    } catch (err) {
      this.fatal('encrypt_failed', (err as Error).message);
    }
  }

  /**
   * Send an OpenAI-style error object. If we have transport keys, encrypt
   * it; otherwise send it as plaintext JSON so the client can still
   * surface a meaningful message before the handshake completes.
   */
  private sendError(code: string, message: string, status?: number): void {
    const payload = JSON.stringify({
      error: { type: code, message, ...(status !== undefined ? { status } : {}) },
    });
    const bytes = new TextEncoder().encode(payload);
    if (this.session.state === 'transport') {
      this.sendEncrypted(FRAME.ERROR, bytes);
    } else {
      this.opts.send(encodeFrame(FRAME.ERROR, bytes));
    }
    this.opts.log?.('sent_error', { code, message });
  }

  private fatal(code: string, message: string): void {
    this.sendError(code, message);
    this.phase = 'closed';
    this.opts.close(1011, code);
  }
}
