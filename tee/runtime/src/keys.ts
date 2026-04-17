/**
 * Static keypair for the Noise endpoint.
 *
 * Generated fresh on each process start (no persistence across restarts).
 * This matches the Phase 3+ model where TEE keys rotate on every boot —
 * clients re-fetch the public key via `GET /v1/keys` at the start of each
 * session.
 */

import { generateKeypair, type KeyPair } from '@tacet/noise';

let cached: KeyPair | null = null;

export function getStaticKeypair(): KeyPair {
  if (!cached) {
    cached = generateKeypair();
  }
  return cached;
}

export function resetStaticKeypair(): void {
  cached = null;
}

export function publicKeyBase64(): string {
  const { publicKey } = getStaticKeypair();
  return Buffer.from(publicKey).toString('base64');
}
