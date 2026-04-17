/**
 * Per-config TEE public-key cache.
 *
 * The gateway never holds a static keypair of its own — it simply fetches
 * `GET {tee_url}/v1/keys` whenever the browser SDK asks for one. To avoid
 * hammering TEEs on every page load we cache each response for a short TTL
 * (default 30s). The gateway does not inspect the payload; it proxies the
 * raw JSON through so any future attestation fields (Step 9) flow through
 * untouched.
 */

import type { Config } from './configs.js';

export interface KeyCacheOptions {
  /** Cache TTL in milliseconds. Default 30_000. */
  ttlMs?: number;
  /** Override for the fetch function (tests). */
  fetcher?: (url: string) => Promise<Response>;
}

interface Entry {
  body: string;
  expiresAt: number;
}

export class KeyCache {
  private readonly ttlMs: number;
  private readonly fetcher: (url: string) => Promise<Response>;
  private readonly entries = new Map<string, Entry>();
  /** De-dup concurrent in-flight fetches for the same config. */
  private readonly inFlight = new Map<string, Promise<string>>();

  constructor(opts: KeyCacheOptions = {}) {
    this.ttlMs = opts.ttlMs ?? 30_000;
    this.fetcher = opts.fetcher ?? ((url) => fetch(url));
  }

  async get(config: Config): Promise<string> {
    const now = Date.now();
    const cached = this.entries.get(config.id);
    if (cached && cached.expiresAt > now) return cached.body;

    const existing = this.inFlight.get(config.id);
    if (existing) return existing;

    const p = this.fetchAndStore(config);
    this.inFlight.set(config.id, p);
    try {
      return await p;
    } finally {
      this.inFlight.delete(config.id);
    }
  }

  invalidate(configId: string): void {
    this.entries.delete(configId);
  }

  private async fetchAndStore(config: Config): Promise<string> {
    const url = `${config.tee_url.replace(/\/$/, '')}/v1/keys`;
    const res = await this.fetcher(url);
    if (!res.ok) {
      throw new KeyFetchError(res.status, `${config.tee_url} returned ${res.status}`);
    }
    const body = await res.text();
    this.entries.set(config.id, { body, expiresAt: Date.now() + this.ttlMs });
    return body;
  }
}

export class KeyFetchError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'KeyFetchError';
  }
}
