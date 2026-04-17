/**
 * Minimal fake vLLM HTTP server for gateway E2E tests. Mirrors the fake used
 * by tee-runtime, kept local so we don't cross a package boundary for test
 * helpers.
 */

import { createServer, type Server, type ServerResponse } from 'node:http';

export interface FakeVllmOptions {
  nonStreamContent?: string;
  streamChunks?: string[];
}

export interface FakeVllm {
  url: string;
  close(): Promise<void>;
  requests: { method: string; path: string; body: string }[];
}

export async function startFakeVllm(opts: FakeVllmOptions = {}): Promise<FakeVllm> {
  const nonStreamContent = opts.nonStreamContent ?? 'Hello from fake vLLM';
  const streamChunks = opts.streamChunks ?? ['Hel', 'lo', '!'];
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
    const parsed = JSON.parse(body) as { stream?: boolean };
    if (!parsed.stream) {
      respondNonStreaming(res, nonStreamContent);
      return;
    }
    respondStreaming(res, streamChunks);
  });

  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const addr = server.address();
  if (typeof addr !== 'object' || !addr) throw new Error('no address');
  return {
    url: `http://127.0.0.1:${addr.port}`,
    requests,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
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
        { index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }),
  );
}

function respondStreaming(res: ServerResponse, chunks: string[]): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Transfer-Encoding': 'chunked',
  });
  for (const delta of chunks) {
    res.write(
      `data: ${JSON.stringify({
        id: 'chatcmpl-fake',
        object: 'chat.completion.chunk',
        choices: [{ index: 0, delta: { content: delta } }],
      })}\n\n`,
    );
  }
  res.write('data: [DONE]\n\n');
  res.end();
}
