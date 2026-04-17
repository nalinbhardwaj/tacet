/**
 * WebSocket frame format for the Tacet Noise endpoint.
 *
 * Every binary frame is:
 *   [1-byte tag][payload bytes]
 *
 * Payload bytes meaning depends on tag:
 *
 *   HANDSHAKE      (0x01) — raw Noise handshake message bytes
 *   REQUEST        (0x02) — Noise transport ciphertext (chunked-framed),
 *                           plaintext is the OpenAI /v1/chat/completions body
 *   RESPONSE_CHUNK (0x03) — Noise transport ciphertext (single message),
 *                           plaintext is one SSE `data:` line from vLLM
 *   RESPONSE_DONE  (0x04) — Noise transport ciphertext (single message),
 *                           plaintext is either the full non-streaming JSON
 *                           or the `[DONE]` marker for streaming
 *   ERROR          (0x05) — Noise transport ciphertext (single message),
 *                           plaintext is a JSON `{error: {...}}` object.
 *                           Before handshake completes, payload is raw UTF-8 JSON
 *                           (no encryption possible without keys).
 */

export const FRAME = {
  HANDSHAKE: 0x01,
  REQUEST: 0x02,
  RESPONSE_CHUNK: 0x03,
  RESPONSE_DONE: 0x04,
  ERROR: 0x05,
} as const;

export type FrameTag = (typeof FRAME)[keyof typeof FRAME];

const VALID_TAGS = new Set<number>(Object.values(FRAME));

export interface Frame {
  tag: FrameTag;
  payload: Uint8Array;
}

export function encodeFrame(tag: FrameTag, payload: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = tag;
  buf.set(payload, 1);
  return buf;
}

export function decodeFrame(data: Uint8Array): Frame {
  if (data.length < 1) {
    throw new Error('Frame too short: missing tag byte');
  }
  const tag = data[0]!;
  if (!VALID_TAGS.has(tag)) {
    throw new Error(`Unknown frame tag: 0x${tag.toString(16).padStart(2, '0')}`);
  }
  return { tag: tag as FrameTag, payload: data.slice(1) };
}
