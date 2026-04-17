/**
 * Minimal subset of the TEE frame protocol, used only to emit gateway-level
 * errors before a Noise handshake has completed. The gateway never parses
 * post-handshake frames — those are opaque ciphertext relayed 1:1.
 *
 * Frame: [1-byte tag][payload bytes]. Tag 0x05 = ERROR; payload is raw UTF-8
 * JSON `{error: {...}}` (plaintext because no session keys exist).
 */

export const FRAME_ERROR = 0x05 as const;

export function encodePlaintextError(code: string, message: string): Uint8Array {
  const json = JSON.stringify({ error: { type: code, message } });
  const body = new TextEncoder().encode(json);
  const buf = new Uint8Array(1 + body.length);
  buf[0] = FRAME_ERROR;
  buf.set(body, 1);
  return buf;
}
