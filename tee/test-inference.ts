/**
 * Test script for vLLM inference endpoint.
 * Tests the vLLM OpenAI-compatible API directly (no gateway, no encryption).
 *
 * Usage:
 *   VLLM_URL=http://localhost:8000 npx tsx tee/test-inference.ts
 */

const BASE_URL = process.env.VLLM_URL || "http://localhost:8000";

async function testModels(): Promise<string> {
  console.log("--- Testing GET /v1/models ---");
  const res = await fetch(`${BASE_URL}/v1/models`);
  if (!res.ok) throw new Error(`/v1/models failed: ${res.status} ${res.statusText}`);
  const data = await res.json();
  const models = data.data.map((m: { id: string }) => m.id);
  console.log(`  Models available: ${models.join(", ")}`);
  console.log(`  OK\n`);
  return models[0];
}

async function testCompletion(model: string): Promise<void> {
  console.log("--- Testing POST /v1/chat/completions (non-streaming) ---");
  const res = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Say hello in one sentence." }],
      max_tokens: 50,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Chat completions failed: ${res.status} ${text}`);
  }
  const data = await res.json();

  const content = data.choices?.[0]?.message?.content;
  const finishReason = data.choices?.[0]?.finish_reason;
  const usage = data.usage;

  if (!content) throw new Error("No content in response");

  console.log(`  Response: ${content}`);
  console.log(`  Finish reason: ${finishReason}`);
  console.log(`  Usage: ${JSON.stringify(usage)}`);
  console.log(`  OK\n`);
}

async function testStreaming(model: string): Promise<void> {
  console.log("--- Testing POST /v1/chat/completions (streaming) ---");
  const res = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Count from 1 to 5." }],
      max_tokens: 100,
      stream: true,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Streaming failed: ${res.status} ${text}`);
  }

  let chunks = 0;
  let content = "";
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.startsWith("data: ")) continue;
      const payload = trimmed.slice(6);
      if (payload === "[DONE]") continue;

      const chunk = JSON.parse(payload);
      const delta = chunk.choices?.[0]?.delta?.content || "";
      content += delta;
      chunks++;
    }
  }

  if (chunks === 0) throw new Error("No streaming chunks received");

  console.log(`  Chunks received: ${chunks}`);
  console.log(`  Content: ${content}`);
  console.log(`  OK\n`);
}

async function main() {
  console.log(`\nTesting vLLM at ${BASE_URL}\n`);

  const model = await testModels();
  await testCompletion(model);
  await testStreaming(model);

  console.log("All tests passed.\n");
}

main().catch((err) => {
  console.error(`\nFAILED: ${err.message}\n`);
  process.exit(1);
});
