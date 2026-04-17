import { describe, it, expect, vi } from 'vitest';
import { KeyCache, KeyFetchError } from '../src/keys.js';
import type { Config } from '../src/configs.js';

const config: Config = {
  id: '00000000-0000-4000-8000-000000000001',
  name: 'c',
  tee_url: 'http://tee.local:8443/',
  model_name: 'm',
};

function mockResponse(status: number, body: string): Response {
  return new Response(body, { status });
}

describe('KeyCache', () => {
  it('fetches and returns the raw response body', async () => {
    const fetcher = vi.fn().mockResolvedValue(mockResponse(200, '{"public_key":"abc"}'));
    const cache = new KeyCache({ fetcher });
    const body = await cache.get(config);
    expect(body).toBe('{"public_key":"abc"}');
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith('http://tee.local:8443/v1/keys');
  });

  it('caches until TTL expires', async () => {
    let call = 0;
    const fetcher = vi.fn(async () => mockResponse(200, `{"n":${++call}}`));
    const cache = new KeyCache({ fetcher, ttlMs: 50 });
    expect(await cache.get(config)).toBe('{"n":1}');
    expect(await cache.get(config)).toBe('{"n":1}');
    await new Promise((r) => setTimeout(r, 75));
    expect(await cache.get(config)).toBe('{"n":2}');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('dedupes concurrent misses to one fetch', async () => {
    let resolveFetch!: (r: Response) => void;
    const fetcher = vi.fn(
      () => new Promise<Response>((ok) => (resolveFetch = ok)),
    );
    const cache = new KeyCache({ fetcher });
    const a = cache.get(config);
    const b = cache.get(config);
    resolveFetch(mockResponse(200, '{"public_key":"x"}'));
    const [ra, rb] = await Promise.all([a, b]);
    expect(ra).toBe('{"public_key":"x"}');
    expect(rb).toBe('{"public_key":"x"}');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('throws KeyFetchError on non-2xx', async () => {
    const fetcher = vi.fn().mockResolvedValue(mockResponse(503, 'down'));
    const cache = new KeyCache({ fetcher });
    await expect(cache.get(config)).rejects.toBeInstanceOf(KeyFetchError);
  });

  it('invalidate() forces a refetch', async () => {
    let call = 0;
    const fetcher = vi.fn(async () => mockResponse(200, `{"n":${++call}}`));
    const cache = new KeyCache({ fetcher, ttlMs: 60_000 });
    await cache.get(config);
    cache.invalidate(config.id);
    await cache.get(config);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
