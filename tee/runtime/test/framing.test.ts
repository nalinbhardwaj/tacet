import { describe, it, expect } from 'vitest';
import { FRAME, encodeFrame, decodeFrame } from '../src/framing.js';

describe('framing', () => {
  it('round-trips a handshake frame', () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = encodeFrame(FRAME.HANDSHAKE, payload);
    expect(encoded[0]).toBe(FRAME.HANDSHAKE);
    expect(encoded.length).toBe(6);

    const { tag, payload: decoded } = decodeFrame(encoded);
    expect(tag).toBe(FRAME.HANDSHAKE);
    expect(Array.from(decoded)).toEqual([1, 2, 3, 4, 5]);
  });

  it('handles empty payload', () => {
    const encoded = encodeFrame(FRAME.RESPONSE_DONE, new Uint8Array(0));
    expect(encoded.length).toBe(1);
    expect(encoded[0]).toBe(FRAME.RESPONSE_DONE);
    const { tag, payload } = decodeFrame(encoded);
    expect(tag).toBe(FRAME.RESPONSE_DONE);
    expect(payload.length).toBe(0);
  });

  it('rejects empty input', () => {
    expect(() => decodeFrame(new Uint8Array(0))).toThrow(/too short/);
  });

  it('rejects unknown tag', () => {
    expect(() => decodeFrame(new Uint8Array([0xff, 0x00]))).toThrow(/Unknown frame tag/);
  });
});
