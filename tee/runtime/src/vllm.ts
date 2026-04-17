/**
 * HTTP client for the local vLLM backend.
 *
 * Forwards an OpenAI-compatible chat-completions request to vLLM and yields
 * the response body:
 *   - non-streaming: a single JSON string (the response body)
 *   - streaming: an async iterable of SSE `data:` line payloads, terminated
 *     by the string `[DONE]`.
 *
 * We do not parse the JSON inside the endpoint — the Noise tunnel transmits
 * exactly what vLLM produces. The client decides how to consume it.
 */

export interface VllmChunk {
  /** The raw text after `data: ` for one SSE event (no trailing newline). */
  data: string;
}

export interface VllmResult {
  /** True if the response was streamed (vLLM returned SSE). */
  streaming: boolean;
  /** For non-streaming responses: the full JSON body as a string. */
  body?: string;
  /** For streaming responses: an async iterator over SSE data lines. */
  stream?: AsyncIterable<VllmChunk>;
}

export interface VllmClientOptions {
  /** Base URL, e.g. "http://127.0.0.1:8000". */
  baseUrl: string;
  /** Per-request timeout in ms. Default: 5 minutes. */
  timeoutMs?: number;
}

export class VllmClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(opts: VllmClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.timeoutMs = opts.timeoutMs ?? 5 * 60_000;
  }

  async chatCompletions(requestJson: string): Promise<VllmResult> {
    const parsed = JSON.parse(requestJson) as { stream?: boolean };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: requestJson,
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }

    if (!res.ok) {
      clearTimeout(timer);
      const text = await res.text().catch(() => '');
      throw new VllmError(res.status, text || res.statusText);
    }

    if (!parsed.stream) {
      const body = await res.text();
      clearTimeout(timer);
      return { streaming: false, body };
    }

    if (!res.body) {
      clearTimeout(timer);
      throw new Error('vLLM streaming response has no body');
    }
    return {
      streaming: true,
      stream: sseLines(res.body, () => clearTimeout(timer)),
    };
  }
}

export class VllmError extends Error {
  constructor(public readonly status: number, message: string) {
    super(`vLLM ${status}: ${message}`);
    this.name = 'VllmError';
  }
}

async function* sseLines(
  body: ReadableStream<Uint8Array>,
  onDone: () => void,
): AsyncIterable<VllmChunk> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // Split on \n; hold the final (possibly partial) line in the buffer.
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data: ')) continue;
        yield { data: trimmed.slice(6) };
      }
    }
    // Flush any trailing data line (no terminating newline).
    const trimmed = buffer.trim();
    if (trimmed.startsWith('data: ')) {
      yield { data: trimmed.slice(6) };
    }
  } finally {
    onDone();
    reader.releaseLock();
  }
}
