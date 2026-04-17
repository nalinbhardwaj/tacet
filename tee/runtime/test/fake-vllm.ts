/**
 * Fake vLLM HTTP server for tests.
 *
 * Implements just enough of the vLLM /v1/chat/completions surface for our
 * endpoint tests:
 *   - stream=false → returns a single canned JSON body
 *   - stream=true  → emits N SSE `data: {...}` chunks, then `data: [DONE]`
 *   - request body triggering { "__force_error": true } → 500 response
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

export interface FakeVllmOptions {
  /** Text content returned for non-streaming requests. */
  nonStreamContent?: string;
  /** Per-chunk delta contents for streaming requests. */
  streamChunks?: string[];
  /** Inter-chunk delay in ms (default: 0). */
  streamDelayMs?: number;
}

export interface FakeVllm {
  url: string;
  close(): Promise<void>;
  /** Requests observed (method, path, raw body). */
  requests: { method: string; path: string; body: string }[];
}

export async function startFakeVllm(opts: FakeVllmOptions = {}): Promise<FakeVllm> {
  const nonStreamContent = opts.nonStreamContent ?? 'Hello from fake vLLM';
  const streamChunks = opts.streamChunks ?? ['Hel', 'lo', '!'];
  const streamDelayMs = opts.streamDelayMs ?? 0;

  const requests: FakeVllm['requests'] = [];

  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: req.method ?? '', path: req.url ?? '', body });

    if (req.url !== '/v1/chat/completions' || req.method !== 'POST') {
      res.writeHead(404);
      res.end();
      return;
    }

    let parsed: { stream?: boolean; __force_error?: boolean; __hang?: boolean };
    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'bad json' }));
      return;
    }

    if (parsed.__force_error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'forced' }));
      return;
    }

    if (!parsed.stream) {
      respondNonStreaming(res, nonStreamContent);
      return;
    }

    respondStreaming(res, streamChunks, streamDelayMs);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (typeof addr !== 'object' || !addr) throw new Error('no address');
  const url = `http://127.0.0.1:${addr.port}`;

  return {
    url,
    requests,
    close: () =>
      new Promise<void>((ok) => {
        server.close(() => ok());
      }),
  };
}

function respondNonStreaming(res: ServerResponse, content: string): void {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      id: 'chatcmpl-fake',
      object: 'chat.completion',
      created: 1_700_000_000,
      model: 'fake',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }),
  );
}

function respondStreaming(res: ServerResponse, chunks: string[], delayMs: number): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Transfer-Encoding': 'chunked',
  });

  let i = 0;
  const writeNext = () => {
    if (i >= chunks.length) {
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    }
    const delta = chunks[i]!;
    res.write(
      `data: ${JSON.stringify({
        id: 'chatcmpl-fake',
        object: 'chat.completion.chunk',
        choices: [{ index: 0, delta: { content: delta } }],
      })}\n\n`,
    );
    i += 1;
    if (delayMs > 0) setTimeout(writeNext, delayMs);
    else writeNext();
  };
  writeNext();
}
