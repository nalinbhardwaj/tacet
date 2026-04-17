# Tacet - End-to-End Encrypted AI API Gateway

> **This project is under active development.** Everything below is a living design doc / implementation plan — expect rough edges and incomplete features.

> "tacet" (Latin: "it is silent") — An OpenAI-compatible API gateway with
> end-to-end encrypted inference, inspired by confer.to's architecture.

## Vision

Tacet is an OpenRouter-style API gateway that hosts AI models behind
OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/responses`, etc.)
with an end-to-end encryption layer. A browser-based JS SDK handles all
cryptography client-side — prompts and responses are never visible to the
infrastructure operator.

---

## Background & Research Summary

### How Confer.to Works

Confer.to (by Moxie Marlinspike / ConferLabs) provides E2E encrypted AI chat.
Their architecture has **two independent encryption systems** serving different
purposes:

#### 1. Passkey Encryption (Data at Rest)

Purpose: Encrypt stored data (conversations, folders, memory, OAuth tokens) so
the server only ever holds opaque ciphertext.

- Uses WebAuthn PRF extension to derive a 32-byte root secret from the user's
  passkey. The PRF takes a salt + the authenticator's hardware-backed HMAC
  secret and produces deterministic output.
- Client calls `navigator.credentials.get()` with
  `extensions: { prf: { eval: { first: new Uint8Array(salt) } } }`
- The 32-byte PRF output is fed through HKDF (via WebCrypto API) to derive
  subkeys for different purposes (e.g., conversation encryption key, folder
  encryption key, memory encryption key).
- All encryption/decryption happens client-side using AES-GCM via WebCrypto.
- The server never sees the PRF output or any derived keys.
- PRF supports two salts (`first` and `second`) enabling key rotation.
- This system has **nothing to do with the Noise Protocol** — it's purely for
  encrypting data before storing it on the server.

#### 2. Noise Protocol (Data in Transit to TEE)

Purpose: Create an encrypted tunnel from the client directly into the TEE so
that prompts and responses are never visible to the host infrastructure.

- Models run inside Confidential VMs (AMD SEV-SNP / NVIDIA H100 CC).
- Client initiates a Noise handshake with the inference endpoint inside the TEE.
- The TEE embeds its **attestation quote** in the Noise handshake response
  payload. The attestation quote contains the TEE's public key + hardware
  signature + measurements.
- Client verifies: (a) genuine TEE hardware signature, (b) public key in quote
  matches the Noise handshake key, (c) measurements match published releases in
  the transparency log.
- After handshake, ephemeral session keys provide forward secrecy.
- Each streaming token is a separate Noise transport message.
- Confer calls this "Noise Pipes" — likely IK pattern with XXfallback for key
  rotation resilience.

#### How the Two Systems Interact

They don't directly. They serve different purposes:
```
                     ┌─────────────────────┐
                     │    User's Browser    │
                     └──────────┬──────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                  │
              ▼                 ▼                  ▼
   ┌──────────────────┐ ┌────────────┐ ┌──────────────────┐
   │  Passkey-derived  │ │   Noise    │ │  Passkey-derived  │
   │  keys encrypt     │ │   session  │ │  keys encrypt     │
   │  data BEFORE      │ │   encrypts │ │  response BEFORE  │
   │  storing on       │ │   prompts  │ │  storing on       │
   │  server           │ │   in       │ │  server           │
   │                   │ │   transit  │ │                   │
   │  (at-rest)        │ │   to TEE   │ │  (at-rest)        │
   └──────────────────┘ │  (in-      │ └──────────────────┘
                        │   transit)  │
                        └────────────┘
```

When a user sends a message:
1. Client encrypts the prompt with Noise session keys → sends to TEE via gateway
2. TEE decrypts, runs inference, encrypts response with Noise session keys → sends back
3. Client decrypts the response (now has plaintext prompt + response)
4. Client encrypts both with passkey-derived keys → stores as ciphertext on server

Open source repos: `ConferLabs/confer-proxy` (Java, 68 stars) and
`ConferLabs/confer-image` (Shell/Nix/mkosi, 72 stars).

### Noise Protocol — Technical Details

The Noise Protocol Framework (by Trevor Perrin) is a framework for building
crypto protocols based on Diffie-Hellman key agreement. A Noise protocol is
named like `Noise_NK_25519_ChaChaPoly_BLAKE2b` = pattern + DH + cipher + hash.

#### Two Phases

1. **Handshake phase**: Parties exchange DH public keys and perform DH
   operations to derive shared secrets.
2. **Transport phase**: Parties exchange encrypted application data using
   symmetric keys derived from the handshake.

#### Key Patterns (Relevant to Tacet)

Pattern names encode what each party knows: N=no static key, K=key known to
peer, X=key transmitted encrypted, I=key transmitted immediately.

**NK (our primary pattern)** — client knows server's static key, server doesn't
know client:
```
<- s                          (pre-message: server's static key known out-of-band)
...
-> e, es                      (client: ephemeral key + DH(ephemeral, server_static))
<- e, ee                      (server: ephemeral key + DH(server_ephemeral, client_ephemeral))
```
- **1 round trip** to complete handshake
- Message 1 payload is encrypted to server's static key (no forward secrecy yet)
- After message 2, both directions have **full forward secrecy** (ee DH)
- Client is anonymous (no static key)

**IK (Noise Pipes first-try)** — mutual auth, 0-RTT:
```
<- s
...
-> e, es, s, ss               (client: ephemeral + DH + encrypted static + DH)
<- e, ee, se                  (server: ephemeral + DH + DH)
```
- 1 round trip, first payload already encrypted
- Client identity transmitted (encrypted)
- Falls back to XXfallback if server key has rotated

**XX (most general)** — no pre-knowledge:
```
-> e
<- e, ee, s, es
-> s, se
```
- 1.5 round trips (3 messages)
- Neither party needs prior knowledge of the other

#### Transport Messages (Post-Handshake)

After handshake, `Split()` derives two CipherState objects:
- `c1` (initiator→responder) and `c2` (responder→initiator)
- Each encrypts with AEAD (ChaCha20-Poly1305 or AES-256-GCM)
- Nonce is a 64-bit counter, incremented per message (no reuse, no coordination)
- **Max message size: 65535 bytes** (including 16-byte AEAD tag)
- Max plaintext per message: 65519 bytes
- Application must frame messages (typically 2-byte big-endian length prefix)

#### Forward Secrecy

- Comes from ephemeral-ephemeral DH (`ee`)
- After handshake, both parties discard ephemeral private keys
- Even if static keys are later compromised, past sessions are safe
- **Exception**: In NK/IK, the *first* message payload is encrypted only to the
  server's static key (no forward secrecy). All subsequent transport messages
  have full forward secrecy.

#### Rekeying

- `REKEY(k)` derives a new key from the old one (one-way)
- Nonce counter is NOT reset
- Provides post-compromise forward secrecy for transport messages
- Application decides when to rekey (every N messages, every N bytes, on timer)
- Both parties must rekey in sync

### OpenAI-Compatible API (What We Must Implement)

The standard that OpenRouter, vLLM, LiteLLM, and others implement:

**Core Endpoints:**
- `POST /v1/chat/completions` — Chat-style inference (messages array)
- `POST /v1/completions` — Raw text completion (legacy)
- `POST /v1/responses` — Newer Responses API (items, previous_response_id)
- `GET /v1/models` — List available models

**Chat Completions Request Format:**
```json
{
  "model": "meta-llama/llama-3.1-70b",
  "messages": [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 0.7,
  "max_tokens": 1024,
  "stream": true,
  "tools": [...],
  "tool_choice": "auto"
}
```

**Chat Completions Response Format:**
```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "meta-llama/llama-3.1-70b",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "Hi!"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}
}
```

**Streaming**: SSE with `data: {chunk}\n\n` lines, terminated by `data: [DONE]`.
Each chunk has `delta` instead of `message` in choices.

**OpenRouter Extensions**: Extra headers (`HTTP-Referer`, `X-OpenRouter-Title`),
provider preferences, cost tracking in usage, model routing/fallback.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     USER'S BROWSER                              │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Tacet JS SDK (@tacet/sdk)                │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │ OpenAI-compat│  │ Noise State  │  │ Passkey / Key   │  │  │
│  │  │ API surface  │  │ Machine      │  │ Manager         │  │  │
│  │  │              │  │              │  │                  │  │  │
│  │  │ .chat        │  │ Handshake    │  │ PRF derivation  │  │  │
│  │  │ .completions │  │ Session keys │  │ HKDF subkeys    │  │  │
│  │  │ .create()    │  │ Encrypt/     │  │ At-rest encrypt │  │  │
│  │  │              │  │ Decrypt      │  │                  │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └─────────────────┘  │  │
│  │         │                 │                                │  │
│  │         └────────┬────────┘                                │  │
│  │                  │                                         │  │
│  └──────────────────┼─────────────────────────────────────────┘  │
│                     │                                            │
└─────────────────────┼────────────────────────────────────────────┘
                      │ HTTPS (body is Noise ciphertext)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     TACET GATEWAY (Untrusted)                   │
│                                                                 │
│  ┌──────────────────────────┐  ┌─────────────────────────────┐  │
│  │  HTTP Router             │  │  Session Router              │  │
│  │  /v1/chat/completions    │  │  Maps session IDs to TEE    │  │
│  │  /v1/models              │  │  backends                   │  │
│  │  /v1/sessions (handshake)│  │  Load balancing             │  │
│  └────────────┬─────────────┘  └──────────────┬──────────────┘  │
│               │  Forwards opaque blobs         │                │
└───────────────┼────────────────────────────────┼────────────────┘
                │                                │
                ▼                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              TEE INFERENCE BACKEND (Confidential VM)            │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Noise Endpoint                                          │   │
│  │  - Holds TEE static keypair (private key never leaves)   │   │
│  │  - Terminates Noise handshakes                           │   │
│  │  - Decrypts request payloads → plaintext JSON            │   │
│  │  - Passes to vLLM for inference                          │   │
│  │  - Encrypts response tokens → Noise transport messages   │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  vLLM inference engine + model weights                   │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  Attestation: dm-verity filesystem, signed measurements  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Host sees: encrypted blobs, timing, sizes (not content)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Transport: WebSocket

All client↔gateway communication uses **WebSocket**, not HTTP request/response.
This simplifies the entire stack:

- **Connection = session**: No session ID headers. The WS connection itself is
  the session. The Noise handshake is the first messages on the WS.
- **Bidirectional**: Tool calls and results flow naturally without awkward
  request/response patterns.
- **Binary frames**: Noise messages are binary. WS supports binary natively —
  no base64 encoding overhead (unlike SSE which is text-based).
- **Streaming is natural**: Each model token is a WS message. No SSE parsing.
- **Simplified concurrency**: Requests are serialized per WS connection. No
  nonce race conditions. (If concurrency is needed later, open multiple WS
  connections.)

The gateway translates WS↔HTTP when talking to backend inference engines
(Ollama/vLLM speak HTTP). In the TEE phase, gateway↔TEE also uses WS.

### WS Message Protocol

Messages on the WS connection use a simple framing:

```typescript
// Client → Gateway/TEE
type ClientMessage =
  | { type: "handshake"; data: Uint8Array }        // Noise handshake msg
  | { type: "request"; data: Uint8Array | object }  // Encrypted (Phase 3+) or plaintext (Phase 1)

// Gateway/TEE → Client
type ServerMessage =
  | { type: "handshake"; session_id: string; data: Uint8Array }
  | { type: "response.start"; request_id: string }
  | { type: "response.chunk"; data: Uint8Array | object }  // One per streaming token
  | { type: "response.done"; data: Uint8Array | object }    // Final/non-streaming response
  | { type: "error"; code: string; message: string }        // Connection-level errors
```

In Phase 1 (no encryption), `data` is plaintext JSON. In Phase 3+, `data` is
an opaque Noise ciphertext blob that the gateway forwards without reading.

### WS Connection Flow (Phase 1, Unencrypted)

```
Browser (Tacet SDK)              Gateway              Ollama/vLLM
       │                           │                       │
       │  1. Open WebSocket        │                       │
       │  ws://gateway/v1/ws       │                       │
       │  ?config_id=<uuid>           │                       │
       │══════════════════════════▶│                       │
       │  Connection established   │                       │
       │  Gateway assigns          │                       │
       │  session_id, looks up     │                       │
       │  config_id → backend URL     │                       │
       │                           │                       │
       │  2. Send request          │                       │
       │  { type: "request",       │                       │
       │    data: {                 │  3. Gateway translates│
       │      messages: [...],     │  to HTTP POST         │
       │      stream: true         │  /v1/chat/completions │
       │    }                      │──────────────────────▶│
       │  }                        │                       │
       │─────────────────────────▶│                       │
       │                           │                       │
       │                           │  4. SSE stream back   │
       │  5. WS messages           │◀──────────────────────│
       │  { type: "response.chunk",│                       │
       │    data: {delta...} }     │                       │
       │◀─────────────────────────│                       │
       │  { type: "response.chunk",│                       │
       │    data: {delta...} }     │                       │
       │◀─────────────────────────│                       │
       │  { type: "response.done", │                       │
       │    data: {full response}} │                       │
       │◀─────────────────────────│                       │
```

The `config_id` is an opaque UUID passed as a query parameter when opening the WS.
In Phase 1 it maps to a model backend URL. In later phases it maps to a full
developer app config (model + system prompt + tools + code).

---

## Encryption Protocol: Detailed Session Flow

### NK Pattern (Phase 3)

The client already knows the server/TEE's static public key (fetched from
`GET /v1/keys` or transparency log). The Noise handshake happens as the
**first messages on the WebSocket connection**.

```
Browser (Tacet SDK)              Gateway              TEE Backend
       │                           │                       │
       │  0. Fetch server's static public key (HTTP)       │
       │  GET /v1/keys             │                       │
       │──────────────────────────▶│                       │
       │  { "public_key": "...",   │                       │
       │    "attestation": "..." } │                       │
       │◀──────────────────────────│                       │
       │  SDK verifies attestation │                       │
       │                           │                       │
       │  1. Open WebSocket        │                       │
       │  ws://gateway/v1/ws       │                       │
       │  ?config_id=<uuid>           │                       │
       │══════════════════════════▶│══════════════════════▶│
       │                           │  (Gateway opens WS    │
       │                           │   to TEE backend      │
       │                           │   based on config_id)    │
       │                           │                       │
       │  2. NK Handshake Message 1 + Encrypted Request    │
       │  { type: "handshake",     │                       │
       │    data: <32B ephemeral   │  Gateway forwards     │
       │     + encrypted payload>  │  opaque binary blob   │
       │  }                        │─────────────────────▶ │
       │─────────────────────────▶│                       │
       │                           │  TEE decrypts with    │
       │                           │  static key, generates│
       │                           │  ephemeral, DH → keys │
       │                           │  Runs inference...    │
       │                           │                       │
       │  3. NK Handshake Message 2 + Encrypted Response   │
       │  { type: "handshake",     │                       │
       │    session_id: "<uuid>",  │                       │
       │    data: <32B server      │                       │
       │     ephemeral + encrypted │◀─────────────────────│
       │     response> }           │                       │
       │◀─────────────────────────│                       │
       │                           │                       │
       │  Client: ee DH → session  │                       │
       │  keys (forward secrecy)   │                       │
       │                           │                       │
       │  ═══════ SESSION ESTABLISHED ═══════               │
       │  Gateway records session_id → backend mapping.    │
       │  All subsequent WS messages are Noise transport.  │
       │                           │                       │
       │  4. Subsequent requests (transport encryption)    │
       │  { type: "request",       │                       │
       │    data: <Noise transport │  Forward opaque blob  │
       │     ciphertext> }         │─────────────────────▶│
       │─────────────────────────▶│                       │
       │                           │                       │
       │  5. Streaming response    │                       │
       │  { type: "response.chunk",│                       │
       │    data: <Noise transport │                       │
       │     ciphertext> }         │◀─────────────────────│
       │◀─────────────────────────│                       │
       │  (repeat per token)       │                       │
       │                           │                       │
       │  { type: "response.done", │                       │
       │    data: <Noise transport │                       │
       │     ciphertext> }         │◀─────────────────────│
       │◀─────────────────────────│                       │
```

**Key points:**
- Handshake + first request happen in the first WS message (1 round trip).
- First payload is encrypted to server's static key (no forward secrecy).
- After message 2, all traffic has full forward secrecy.
- Gateway assigns a `session_id` UUID and records `session_id → TEE backend`
  in Postgres. This session_id is returned to the client for logging/debugging
  but is NOT needed for routing (the WS connection handles that).
- Each streaming token is a binary WS frame containing one Noise transport
  message (AEAD encrypted, nonce auto-increments). No base64. No SSE parsing.

### XX Pattern (Phase 4, with TEE attestation)

When the client does NOT yet know the server's key (first contact, or key
rotated), the attestation is embedded in the Noise handshake payload itself:

```
Browser                          Gateway              TEE Backend
       │                           │                       │
       │  1. Open WS + NK msg 1   │                       │
       │  (same as above)          │─────────────────────▶│
       │─────────────────────────▶│                       │
       │                           │                       │
       │  2. TEE detects stale key │                       │
       │  → responds with XX msg 2 │                       │
       │  (server ephemeral +      │                       │
       │   encrypted static key +  │                       │
       │   attestation quote in    │                       │
       │   handshake payload)      │◀─────────────────────│
       │◀─────────────────────────│                       │
       │                           │                       │
       │  3. Client verifies:      │                       │
       │  - TEE hardware signature │                       │
       │  - Pubkey = handshake key │                       │
       │  - Measurements match log │                       │
       │  → caches new server key  │                       │
       │                           │                       │
       │  4. XX msg 3 + request    │                       │
       │─────────────────────────▶│─────────────────────▶│
       │                           │                       │
       │  SESSION ESTABLISHED      │                       │
```

### Noise Pipes (Production, Phase 5)

1. **First contact**: XX handshake (client learns + verifies TEE key)
2. **Subsequent sessions**: IK handshake (0-RTT, client already knows key)
3. **Key rotation fallback**: If IK fails (TEE rebooted, new key), automatically
   fall back to XXfallback. SDK handles this transparently.

TEE static keypairs rotate on restart (not persisted). The SDK must be resilient
to this — on handshake failure, fall back to XX, re-cache the new key, continue.

### Message Framing for Large Payloads

Noise transport messages max out at 65535 bytes (65519 plaintext). Requests
with long conversation history or large responses can exceed this. We use a
simple chunked framing protocol:

```
Encrypted payload format:
  [2-byte big-endian length][Noise AEAD ciphertext (up to 65535 bytes)]
  [2-byte big-endian length][Noise AEAD ciphertext]
  ...
  [0x00 0x00]  (zero-length = end of payload)

Each chunk is a separate Noise transport message with its own AEAD tag and
incrementing nonce. The receiver decrypts each chunk and concatenates the
plaintext to reconstruct the full JSON payload.
```

For streaming responses, each token chunk is small (well under 65535 bytes) so
it's always a single Noise message per WS frame. The framing protocol is mainly
needed for large requests (long conversation context).

### Session Lifecycle & Failure Recovery

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│   No       │     │ Handshake  │     │  Active    │
│   Session  │────▶│ (first WS  │────▶│  Session   │
│            │open │  messages) │     │            │
└────────────┘ WS  └────────────┘     └─────┬──────┘
                                            │
                         ┌──────────────────┤
                         │                  │
                         ▼                  ▼
                  ┌────────────┐     ┌────────────┐
                  │  Error /   │     │  Expired / │
                  │  WS closed │     │  Rekeyed   │
                  └──────┬─────┘     └────────────┘
                         │
                         │ SDK auto-reconnects:
                         │ new WS + new handshake
                         ▼
                  ┌────────────┐
                  │  New       │
                  │  Session   │
                  └────────────┘
```

- Sessions have a TTL (configurable, e.g., 1 hour or N messages)
- **On any transport failure** (WS close, network error, timeout): the session
  is considered broken. Noise nonces may be desynchronized. The SDK opens a new
  WS connection and performs a fresh handshake. This is cheap (NK = 1 round
  trip). The SDK does this transparently — the application code sees a brief
  interruption, not a crash.
- Rekey() can extend a session without a full new handshake
- **Requests are serialized** per WS connection. The SDK queues concurrent
  `.create()` calls and sends them one at a time. This avoids Noise nonce race
  conditions. If true concurrency is needed in the future, the SDK can open
  multiple WS connections (each with its own Noise session).
- Gateway records session metadata in Postgres but doesn't need it for routing
  (the WS connection itself routes to the right backend)

### Error Handling

The gateway always returns well-formed WS messages. Model errors (context too
long, content filter, etc.) are encrypted inside the Noise tunnel — the gateway
can't distinguish success from error. From the gateway's perspective, it just
forwards blobs.

The SDK decrypts the response and checks for OpenAI-format error objects:
```json
{ "error": { "type": "invalid_request_error", "message": "Context too long" } }
```

Connection-level errors (gateway can't reach backend, invalid session) use the
`{ type: "error" }` WS message type in plaintext.

---

## Component Breakdown

### Component 1: API Gateway Server

**What**: A server that accepts WebSocket connections from clients and bridges
them to backend inference engines. It is **untrusted** in the encrypted phases
— it sees only opaque binary blobs and routes them.

**Endpoints**:
- `WS /v1/ws?config_id=<uuid>` — Primary interface (all requests over WS)
- `GET /v1/keys` — Fetch TEE static public keys + attestation (Phase 3+)
- `GET /v1/configs` — List available configs (public metadata)

**Responsibilities**:
- Accept WS connections, look up `config_id` → backend config in Postgres
- Bridge WS messages to backend (HTTP to Ollama/vLLM in Phase 1, WS to TEE
  in Phase 4+)
- Record session metadata in Postgres (session_id, config_id, api_key, timestamps)
- Record usage metrics reported by TEE (prompt_tokens, completion_tokens)
- Handle API key auth for billing/rate limiting (orthogonal to E2E encryption)
- Serve app listing and TEE public keys over plain HTTP

**Tech**: TypeScript + Hono (HTTP endpoints) + ws (WebSocket). Postgres for
session state and metrics.

### Component 2: Browser JS SDK (@tacet/sdk)

**What**: An in-browser TypeScript SDK that provides an OpenAI-compatible API
surface with transparent E2E encryption underneath.

```typescript
import { TacetClient } from '@tacet/sdk';

// Initialize — opens WS, (Phase 3+: fetches server key, Noise handshake)
const client = await TacetClient.create({
  configId: 'abc-123-...',  // opaque UUID — maps to model backend (Phase 1)
                              // or full developer app config (Phase 8)
  baseUrl: 'wss://api.tacet.dev',
  apiKey: 'tk-...',           // for billing/rate limiting
});
// Under the hood (Phase 1): opened WS to /v1/ws?config_id=abc-123-...
// Under the hood (Phase 3+): fetched /v1/keys, opened WS, Noise NK handshake

// Non-streaming request
const response = await client.chat.completions.create({
  messages: [{ role: 'user', content: 'Hello' }],
});
// Under the hood:
//   Phase 1: sends JSON over WS, receives JSON response
//   Phase 3+: encrypts JSON as Noise message, sends binary WS frame,
//             receives encrypted response, decrypts

// Streaming request
const stream = await client.chat.completions.create({
  messages: [{ role: 'user', content: 'Tell me more' }],
  stream: true,
});
// Under the hood:
//   Phase 1: sends JSON over WS, receives WS messages per token
//   Phase 3+: each WS message is a Noise transport message (binary frame),
//             SDK decrypts each, yields standard OpenAI delta objects
for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta?.content || '');
}
```

**Responsibilities**:
- Noise Protocol state machine (handshake + transport)
- Attestation verification (TEE quote signature, measurements, transparency log)
- Encrypt requests / decrypt responses (including streaming)
- Session lifecycle management (create, reuse, rekey, re-handshake)
- OpenAI-compatible API surface (same interface as `openai` npm package)
- Passkey-derived key management for at-rest encryption (Phase 6)

**Tech**: TypeScript, built on `@noble/curves` (Curve25519) + `@noble/ciphers`
(ChaCha20-Poly1305) + `@noble/hashes` (BLAKE2b/SHA256). These are pure
TypeScript, audited, work in browser. The Noise state machine itself is ~500
lines given the spec's precise pseudocode.

**No Python SDK, no server-side SDK.** The entire point is that the user's
browser is the trust boundary. A server-side SDK would defeat the purpose.

### Component 3: TEE Inference Runtime

**What**: A confidential VM image running Noise endpoint + vLLM inside
hardware-isolated environment. One TEE per model. Multiple developer apps share
the TEE (isolated via V8 isolates or similar).

**Responsibilities**:
- Boot with measured, reproducible image (dm-verity verified root filesystem)
- Hash model weights at boot, include hash in kernel cmdline (attested)
- Hold TEE static keypair (generated on boot, rotates on restart)
- Accept WS connections from gateway
- Terminate Noise handshakes, provide attestation quotes in handshake payloads
- Load developer app configs (system prompt, tools, code) from Postgres via
  gateway at boot time. Run each app in an isolated V8 context.
- Decrypt incoming request payloads → plaintext OpenAI JSON
- Apply developer's app logic (system prompt injection, beforeInference, tools)
- Run inference via vLLM (localhost HTTP within the TEE)
- Encrypt response payloads (including per-token streaming chunks)
- Report usage metrics (prompt_tokens, completion_tokens) to gateway as
  plaintext metadata alongside encrypted responses. Gateway logs these for
  billing. Metrics contain no user content.
- Never expose plaintext user data outside the TEE boundary

**Tech**: Based on ConferLabs/confer-image approach:
- Nix flakes + mkosi for reproducible image builds
- Ubuntu base + NVIDIA drivers + vLLM
- dm-verity merkle tree over root filesystem (root hash in kernel cmdline)
- Model weight hash in kernel cmdline (verified at boot)
- Noise Protocol implementation in TypeScript
- V8 isolates for developer app sandboxing (Phase 8)

### Component 4: Attestation & Transparency

**What**: Infrastructure for publishing and verifying TEE measurements.

- Build pipeline produces measurements (hashes of kernel, initrd, cmdline)
- Since dm-verity root hash is in cmdline, this transitively covers every file
- Measurements published to append-only transparency log
- Client SDK fetches and caches known-good measurements
- Prevents operator from silently publishing different builds to different clients

**Tech**: Sigstore/Rekor-style transparency log, or custom append-only log.

### Component 5: Noise Protocol Library (@tacet/noise)

**What**: A standalone, browser-compatible Noise Protocol implementation.

Built on top of audited `@noble/*` crypto primitives:
- `@noble/curves` — Curve25519 ECDH
- `@noble/ciphers` — ChaCha20-Poly1305 AEAD
- `@noble/hashes` — BLAKE2b, SHA256, HMAC, HKDF

Implements:
- CipherState (key + nonce + encrypt/decrypt/rekey)
- SymmetricState (chaining key + handshake hash + MixKey/MixHash)
- HandshakeState (pattern execution: NK, XX, IK, XXfallback)
- Transport message framing (2-byte length prefix + AEAD ciphertext)
- Protocol: `Noise_NK_25519_ChaChaPoly_BLAKE2b` (primary)

Separate package so it can be tested and audited independently.

### Component 6: Key Management

**Two independent systems**:

1. **Noise session keys** (ephemeral, in-transit encryption):
   - Generated during Noise handshake from ephemeral DH
   - Live only in memory for the duration of a session
   - Provide forward secrecy
   - Managed entirely by the Noise state machine

2. **Passkey-derived keys** (persistent, at-rest encryption, Phase 6):
   - Root: 32 bytes from WebAuthn PRF extension
   - Derived via HKDF into purpose-specific subkeys
   - Used to encrypt: conversation history, settings, any data stored server-side
   - Never sent to server
   - Enables cross-device access (same passkey → same keys)

These two systems are orthogonal. You can use Noise sessions without passkeys
(no persistence), or add passkeys later for encrypted storage.

---

## Phased Implementation Plan

### Phase 0: Project Scaffolding
- Initialize monorepo structure (gateway/ + sdk/ + packages/noise/)
- Set up TypeScript tooling (tsconfig, build, test)
- Set up Postgres schema (configs, sessions, usage tables)
- Basic CI

### Phase 1: Unencrypted WebSocket Gateway
- Gateway: accept WS connections on `/v1/ws?config_id=<uuid>`
- Gateway: look up `config_id` in Postgres → get backend URL
- Gateway: bridge WS messages to Ollama/vLLM HTTP backend
- Gateway: `GET /v1/configs` listing available configs
- SDK: `TacetClient.create({ configId, baseUrl })` opens WS
- SDK: `.chat.completions.create()` sends request over WS, receives
  streaming chunks as WS messages
- Record session metadata + usage metrics in Postgres
- Validate: SDK in browser → WS → gateway → Ollama → response in browser
- **Goal**: Working end-to-end over WebSocket, no encryption yet

### Phase 2: Multi-Backend Routing & Auth
- Support multiple configs pointing to different backends
- API key authentication and rate limiting (gateway level)
- Health checking for backends
- Usage dashboard (query Postgres metrics)
- **Goal**: Multi-model gateway with auth and billing, still unencrypted

### Phase 3: Noise NK Encryption (Server Still Trusted)
- Build `@tacet/noise` library (NK pattern, transport, framing)
- Server generates a static keypair, publishes public key at `GET /v1/keys`
- SDK fetches key, performs NK handshake as first WS messages
- First request payload encrypted (to server's static key)
- Response + subsequent traffic encrypted with forward secrecy
- Streaming: each token = one Noise transport message (binary WS frame)
- Large payloads: chunked framing (2-byte length prefix per Noise message)
- Server decrypts at its end (still trusted — no TEE yet)
- SDK auto-reconnects on WS failure (new connection + fresh NK handshake)
- **Goal**: Protocol works end-to-end, encryption is real but server is trusted

### Phase 4: TEE Integration
- Build reproducible confidential VM image (Nix + mkosi)
- Hash model weights at boot, include in kernel cmdline (attested)
- Move Noise endpoint + vLLM into TEE
- TEE generates static keypair on boot (rotates on restart)
- Implement attestation: TEE embeds attestation quote in handshake payload
- Gateway becomes untrusted WS relay (forwards opaque binary blobs)
- TEE reports usage metrics to gateway as plaintext metadata
- SDK verifies attestation before completing handshake
- Upgrade to XX pattern for first-contact (attestation in handshake)
- Cache server key for subsequent NK handshakes
- **Goal**: True E2E encryption — operator cannot see prompts/responses

### Phase 5: Attestation Transparency & Noise Pipes
- Set up transparency log for TEE measurements
- SDK verifies measurements against transparency log
- Reproducible build pipeline (anyone can rebuild and verify)
- Implement full Noise Pipes: IK (0-RTT) + XXfallback
- SDK handles key rotation gracefully (IK fails → XXfallback → re-cache key)
- **Goal**: Verifiable trust + optimal handshake performance

### Phase 6: Passkey Encryption & Persistent Storage
- Implement WebAuthn PRF key derivation in SDK
- HKDF subkey derivation for different storage purposes
- Encrypted conversation history (stored server-side as ciphertext)
- Cross-device access via passkey
- **Goal**: Full confer.to-level privacy with API interface

### Phase 7: Client-Side Tool Execution
- Support OpenAI `tools` / `tool_calls` over WS (bidirectional flow is natural)
- When TEE returns a `tool_calls` response, SDK exposes it to the developer's
  application code running in the browser
- Developer registers tool handlers:
  `client.tools.register("search_email", async (args) => { ... })`
- SDK handles the multi-turn loop over WS: prompt → tool_call → execute
  locally → tool_result → final response
- For OAuth-based tools (Gmail, Calendar, etc.): user authenticates via OAuth
  PKCE directly with the provider (browser↔Google, no server involvement).
  Refresh tokens encrypted with passkey-derived keys at rest.
- Developer never sees user's OAuth tokens or tool outputs — only the TEE
  and the user's browser see plaintext.
- **Goal**: Agents that can act on user data without the developer or operator
  ever accessing that data

### Phase 8: TEE-Side Developer Runtime & Tool Execution

The TEE becomes a full server-side runtime where developers deploy arbitrary
code (system prompts, tool implementations, pre/post processing, any npm
packages). This is the "use server" equivalent — the developer's code runs in
the TEE alongside the model, hidden from the user and opaque to the operator.

**The three-party trust model:**

```
Developer                              User
    │                                   │
    │ Uploads app config via            │ Sends prompts + credentials
    │ platform HTTPS API               │ (via Noise tunnel to TEE)
    │ (system prompt, tools,            │
    │  code bundle, API keys)           │
    │                                   │
    │ Platform stores config            │ User verifies TEE
    │ in Postgres. Platform CAN         │ attestation. User data
    │ see developer config              │ encrypted to TEE only.
    │ (no user data here).              │
    │                                   │
    ▼                                   ▼
┌──────────────────────────────────────────┐
│                  TEE                      │
│                                          │
│  Platform loads developer config at boot │
│  from Postgres. Config hash is attested. │
│                                          │
│  Developer's code + User's data meet     │
│  here and ONLY here.                     │
│                                          │
│  Developer CAN'T see runtime user data   │
│  (no access to TEE internals at runtime) │
│                                          │
│  User CAN'T see developer's code/secrets │
│  (code runs in TEE, not in browser)      │
│                                          │
│  Operator CAN'T see user data            │
│  (TEE hardware isolation)                │
│  Operator CAN see developer config       │
│  (stored in platform DB — acceptable)    │
│                                          │
│  Config hash is attested — users can     │
│  verify WHICH code is running.           │
└──────────────────────────────────────────┘
```

**Key insight: the TEE doesn't constrain what developer code can do — it makes
it auditable.** The developer has a full runtime (like Cloudflare Workers or
Next.js server actions) — arbitrary JS/TS, any npm packages, full network
access. The security comes from:

- **Attestation**: The config bundle hash is part of the TEE measurement. Users
  or auditors can verify which code is running.
- **Credible commitment**: The developer *chose* to put their code in the TEE
  rather than running it on their own server. This is a voluntary, provable
  commitment that they can't peek at runtime data.
- **Same trust model as today, but better**: Users already trust the developer
  enough to use their app. The developer could always build a normal backend
  that logs everything. Choosing the TEE makes their privacy claims verifiable
  rather than just policy.

**Developer config is stored by the platform (not secret from us):**
- Developer uploads config (system prompt, tools, code bundle, API keys) via a
  normal HTTPS API to the Tacet platform.
- Platform stores it in Postgres alongside the config row.
- On TEE boot, platform loads all app configs into the TEE.
- This means the platform CAN see developer configs (system prompts, API keys).
  This is acceptable because developer config is not user data. The developer
  already trusts the platform enough to use it.
- The config bundle hash is included in the TEE attestation, so users can verify
  the code hasn't been tampered with after upload.
- This avoids the complexity of a separate developer↔TEE encrypted channel and
  solves the persistence problem (configs survive TEE restarts).

**Developer experience (example: Gmail email assistant):**

```typescript
// server.ts — uploaded to platform, loaded into TEE at boot

import { google } from 'googleapis';
import { defineApp } from '@tacet/runtime';

export default defineApp({
  model: "llama-3.1-70b",

  // Hidden from the user (but platform can see it)
  systemPrompt: "You are Acme Corp's email assistant. Never reveal...",

  tools: [
    {
      name: "search_email",
      description: "Search the user's Gmail",
      parameters: { query: { type: "string" } },

      // Full SDK usage — normal code, runs in TEE
      execute: async (args, ctx) => {
        // ctx.userCredentials: OAuth token sent by user via Noise tunnel
        const auth = new google.auth.OAuth2();
        auth.setCredentials({ access_token: ctx.userCredentials.gmail });

        const gmail = google.gmail({ version: 'v1', auth });
        const res = await gmail.users.messages.list({
          userId: 'me', q: args.query, maxResults: 10,
        });
        return res.data.messages;
      }
    }
  ],

  // Pre-process: RAG augmentation, hidden from user
  beforeInference: async (messages, ctx) => {
    const docs = await ragLookup(messages, ctx.env.VECTOR_DB_URL);
    return [{ role: "system", content: docs }, ...messages];
  },
});
```

**Credential flow for OAuth tools in this model:**
1. User connects Gmail via OAuth PKCE in browser (browser ↔ Google directly)
2. Refresh token encrypted with passkey-derived key for at-rest storage
3. On use: browser decrypts token, sends into TEE via Noise tunnel
4. TEE-side code (developer's `execute` function) uses token to call Gmail API
5. Token existed in exactly two places: user's browser and the TEE
6. Developer's own servers never saw it. Operator never saw it.

**Implementation:**
- TEE runs a Node.js-like runtime (V8 isolate or full Node)
- One vLLM instance per TEE, multiple developer apps share it (isolated V8
  contexts per app — no data leakage between apps)
- Platform loads developer configs into TEE at boot from Postgres
- Config bundle hash is part of the attestation measurement
- `@tacet/runtime` provides the framework: `defineApp()`, `ctx.userCredentials`,
  `ctx.env` (developer's API keys from config), model access
- Each developer app runs in its own isolated context within the TEE

- **Goal**: Full "use server" runtime for developers — system prompts, tools,
  business logic hidden from users, with user data hidden from developers.
  The TEE is the neutral ground where both parties' secrets meet.

---

## Data Model (Postgres)

### `configs` — What the client connects to (model backend, later full app config)

```sql
CREATE TABLE configs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,              -- human-readable label
  -- Phase 1: just a model backend
  backend_url   TEXT NOT NULL,              -- e.g. "http://localhost:11434"
  model_name    TEXT NOT NULL,              -- e.g. "llama3.1:70b" (Ollama format)
  -- Phase 8: developer app config (nullable until then)
  developer_id  UUID REFERENCES developers(id),
  system_prompt TEXT,                       -- hidden from user
  code_bundle   BYTEA,                     -- JS/TS bundle for TEE runtime
  bundle_hash   TEXT,                       -- SHA-256 of code_bundle (attested)
  env_vars      JSONB,                     -- developer's API keys, secrets
  -- Metadata
  status        TEXT NOT NULL DEFAULT 'active',  -- active, disabled
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

In Phase 1, `config_id` maps to a model + backend URL. In Phase 8, the same
row includes system prompt, tools, code bundle, and developer secrets. The
client always uses the same opaque `config_id` UUID — the meaning expands
over time without changing the interface.

### `api_keys` — Authentication for billing/rate limiting

```sql
CREATE TABLE api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash      TEXT NOT NULL UNIQUE,       -- SHA-256 of the actual key
  developer_id  UUID REFERENCES developers(id),
  label         TEXT,
  rate_limit    INT DEFAULT 60,             -- requests per minute
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at    TIMESTAMPTZ
);
```

### `sessions` — Active WebSocket sessions

```sql
CREATE TABLE sessions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_id     UUID NOT NULL REFERENCES configs(id),
  api_key_id    UUID REFERENCES api_keys(id),
  backend_url   TEXT NOT NULL,              -- resolved backend for this session
  status        TEXT NOT NULL DEFAULT 'active',  -- active, closed, error
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at     TIMESTAMPTZ,
  last_active   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### `usage` — Per-request metrics (for billing)

```sql
CREATE TABLE usage (
  id                BIGSERIAL PRIMARY KEY,
  session_id        UUID NOT NULL REFERENCES sessions(id),
  config_id         UUID NOT NULL REFERENCES configs(id),
  api_key_id        UUID REFERENCES api_keys(id),
  prompt_tokens     INT NOT NULL,
  completion_tokens INT NOT NULL,
  total_tokens      INT NOT NULL,
  latency_ms        INT,                    -- time to first token
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- In Phase 1-2: gateway reads token counts from backend response.
-- In Phase 4+: TEE reports token counts as plaintext metadata alongside
-- encrypted response. Gateway logs them. No user content is exposed.
```

### `developers` — Developer accounts (Phase 8)

```sql
CREATE TABLE developers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  name          TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| API Gateway | TypeScript + Hono + ws | HTTP endpoints + WebSocket |
| Database | PostgreSQL | Simple, reliable, handles all our data needs |
| Browser SDK | TypeScript | Only client is the browser |
| Noise Protocol | Custom on @noble/* | Pure TS, audited, browser-compatible |
| Crypto: DH | @noble/curves (x25519) | Audited, pure JS, fast |
| Crypto: AEAD | @noble/ciphers (ChaCha20-Poly1305) | Audited, pure JS |
| Crypto: Hash | @noble/hashes (BLAKE2b) | Audited, pure JS |
| TEE Image | Nix + mkosi | Reproducible (proven by confer-image) |
| Inference | vLLM | Best OSS engine, OpenAI-compatible |
| Transparency | Sigstore Rekor or custom | Proven append-only log |
| TEE Hardware | AMD SEV-SNP + NVIDIA H100 CC | Most mature CVM + GPU support |

---

## Directory Structure (Planned)

```
tacet/
├── PLAN.md
├── packages/
│   └── noise/                 # @tacet/noise — standalone Noise Protocol lib
│       ├── src/
│       │   ├── cipher-state.ts
│       │   ├── symmetric-state.ts
│       │   ├── handshake-state.ts
│       │   ├── patterns.ts    # NK, XX, IK pattern definitions
│       │   └── transport.ts   # Message framing (chunked large payloads)
│       └── package.json
├── sdk/                       # @tacet/sdk — browser JS SDK
│   ├── src/
│   │   ├── client.ts          # TacetClient (OpenAI-compatible surface)
│   │   ├── session.ts         # WS connection + Noise session lifecycle
│   │   ├── attestation.ts     # TEE attestation verification
│   │   ├── streaming.ts       # WS message → streaming response adapter
│   │   └── passkey.ts         # WebAuthn PRF key management (Phase 6)
│   └── package.json
├── gateway/                   # API gateway server
│   ├── src/
│   │   ├── ws/
│   │   │   ├── handler.ts     # WS connection handler
│   │   │   └── bridge.ts      # WS↔HTTP bridge to Ollama/vLLM backends
│   │   ├── routes/
│   │   │   ├── configs.ts     # GET /v1/configs
│   │   │   └── keys.ts        # GET /v1/keys (Phase 3+)
│   │   ├── db/
│   │   │   ├── schema.ts      # Postgres schema + queries
│   │   │   └── migrate.ts     # Migrations
│   │   └── middleware/        # Auth, rate limiting
│   └── package.json
├── tee/                       # TEE image & runtime (Phase 4+)
│   ├── image/                 # Nix + mkosi image build
│   └── runtime/               # Noise endpoint + app isolates + vLLM bridge
└── docs/
```

---

## Implementation Steps (Detailed)

Build order: start from the core (TEE + inference) and work outward.

```
Step 1:  TEE image + model inference     ← the heart, prove it works
Step 2:  @tacet/noise library            ← can start in parallel with 1
Step 3:  Simple test script → image      ← prove we can talk to it
Step 4:  Noise endpoint in image         ← encrypted requests to model
Step 5:  Gateway (WS relay)              ← route encrypted blobs
Step 6:  Browser SDK (WS + Noise)        ← client-side crypto
Step 7:  End-to-end encrypted test       ← browser → gateway → TEE → model
Step 8:  Postgres + configs + metrics    ← persistence, billing
Step 9:  Attestation + dm-verity         ← verifiable trust
Step 10: Passkey encryption              ← at-rest storage
Step 11: Client-side tools               ← tool calling over WS
Step 12: Developer runtime               ← Phase 8, code in TEE
```

Steps 1 and 2 can be done in parallel (independent). Everything else sequential.

---

### Step 1: Core TEE Image + Model Inference

**Status**: Steps 1a–1e and 1g complete. Image builds reproducibly (validated on
macOS + vast.ai Ubuntu 22.04 hosts). Step 1f (boot the image on real GPU hardware)
is still deferred to Step 9 — vast.ai VMs don't expose IOMMU/VFIO for nested GPU
passthrough, so proving that property needs a cloud that lets us boot custom images
with a GPU attached (confidential VM, bare-metal, or similar).

**Goal**: A reproducible VM image (built with Nix + mkosi) that boots, loads
vLLM, serves a model over HTTP. Testable locally in QEMU (CPU, tiny model) and
on cloud hardware (GPU, real model).

**What this proves:**
- We can build reproducible VM images with Nix + mkosi
- vLLM boots and serves inside the image
- Inference works (CPU locally, GPU on cloud)
- We have a baseline to compare against as we add encryption layers

**What this does NOT include yet:**
- No dm-verity (step 9)
- No Noise encryption (step 4)
- No attestation (step 9)
- No gateway or SDK (steps 5-6)
- No weight hashing in cmdline (step 9)

**Platform note**: We're developing on macOS. mkosi builds Linux images and
requires a Linux environment (systemd-nspawn). Options:
- OrbStack / Docker: run the build inside a Linux container
- Cloud dev machine: build on a remote Linux box
- Linux VM locally: UTM or similar

For *running* the image with GPU inference, we need cloud hardware (AMD SEV-SNP
+ NVIDIA GPU). For local testing, we can boot in QEMU (CPU only, very slow,
tiny model — just to prove the image boots and serves).

#### Step 1a: Study the reference implementation

Clone and study `ConferLabs/confer-image` to understand their patterns before
building our own.

```bash
gh repo clone ConferLabs/confer-image /tmp/confer-image
```

Read and understand:
- `flake.nix` — Nix flake structure, dev shell definition, pinned nixpkgs
- `mkosi.conf` — Image configuration (distribution, packages, partitions,
  filesystem layout)
- `mkosi.postinst` or equivalent — Post-install scripts (how vLLM is installed,
  how NVIDIA drivers are set up)
- `Makefile` — Build flow, output artifacts
- Any `.service` files — How vLLM is started as a systemd service
- How dm-verity is configured (we won't use it yet but need to understand the
  structure so we don't paint ourselves into a corner)
- How the kernel cmdline is constructed (where the dm-verity root hash goes,
  where model weight hash could go)

Document key findings/patterns we'll reuse in our own image.

#### Step 1b: Set up Nix flake for the project

Create the Nix flake at the project root. This provides a reproducible dev
shell with all build tools.

```
tacet/
├── flake.nix              # Nix flake definition
├── flake.lock             # Pinned dependencies
├── PLAN.md
└── tee/
    └── image/             # Image build directory (step 1c)
```

**flake.nix** should provide a dev shell containing:
- `mkosi` — image builder
- `qemu` — for local VM testing
- `systemd` — needed by mkosi for systemd-nspawn
- Standard build tools (make, coreutils, etc.)

```nix
# Sketch of flake.nix structure
{
  description = "Tacet - E2E encrypted AI inference";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";  # or appropriate version
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            mkosi
            qemu
            # other build tools as needed
          ];
        };
      }
    );
}
```

Verify: `nix develop` enters the shell, `mkosi --version` works.

#### Step 1c: Create mkosi image configuration

```
tacet/tee/image/
├── mkosi.conf                    # Base image config
├── mkosi.extra/                  # Files overlaid into the image filesystem
│   └── etc/
│       └── systemd/
│           └── system/
│               └── vllm.service  # Systemd unit to start vLLM on boot
├── mkosi.postinst.chroot         # Post-install script (runs inside chroot)
├── mkosi.build                   # Build script (if needed)
└── Makefile                      # Convenience build commands
```

**mkosi.conf** — minimal image configuration:
```ini
[Distribution]
Distribution=ubuntu
Release=noble

[Output]
Format=disk
ImageId=tacet
SplitArtifacts=yes
# Produces: tacet.vmlinuz, tacet.initrd, tacet.raw (or .qcow2)

[Content]
Packages=
    python3
    python3-pip
    python3-venv
    systemd
    systemd-sysv
    dbus
    networkd-dispatcher
    iproute2
    # GPU packages added conditionally for cloud builds:
    # nvidia-driver-550
    # cuda-toolkit-12-4
```

**mkosi.postinst.chroot** — install vLLM inside the image:
```bash
#!/bin/bash
set -e

# Create a Python venv for vLLM
python3 -m venv /opt/vllm
/opt/vllm/bin/pip install --upgrade pip
/opt/vllm/bin/pip install vllm

# Enable the vLLM service
systemctl enable vllm.service

# Create the model mount point
mkdir -p /models
```

**vllm.service** — systemd unit to start inference on boot:
```ini
[Unit]
Description=vLLM OpenAI-Compatible Inference Server
After=network.target

[Service]
Type=simple
Environment=HOME=/root
ExecStart=/opt/vllm/bin/python -m vllm.entrypoints.openai.api_server \
    --model /models/current \
    --host 0.0.0.0 \
    --port 8000 \
    --dtype auto
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Makefile**:
```makefile
.PHONY: build clean

build:
	mkosi build

clean:
	mkosi clean

run-qemu:
	qemu-system-x86_64 \
		-kernel tacet.vmlinuz \
		-initrd tacet.initrd \
		-drive file=tacet.raw,format=raw \
		-append "$$(cat tacet.cmdline) console=ttyS0 root=/dev/sda" \
		-m 8G \
		-smp 4 \
		-nographic \
		-nic user,hostfwd=tcp::8000-:8000
```

#### Step 1d: Build the image

```bash
cd tacet/tee/image
nix develop          # Enter dev shell with mkosi + qemu
make build           # Run mkosi build

# Expected outputs:
# tacet.vmlinuz   — kernel
# tacet.initrd    — initial ramdisk
# tacet.raw       — root filesystem disk image
# tacet.cmdline   — kernel command line parameters
```

If the build succeeds, we have a bootable Linux image with vLLM installed.

#### Step 1e: Test locally in QEMU (CPU, tiny model)

Download a tiny model for CPU testing. TinyLlama 1.1B or Qwen2-0.5B are small
enough for CPU inference (slow but functional):

```bash
# Option 1: Use huggingface-cli
pip install huggingface-hub
huggingface-cli download TinyLlama/TinyLlama-1.1B-Chat-v1.0 \
    --local-dir /tmp/models/current

# Option 2: Manual download from HuggingFace
```

Boot the image in QEMU with the model directory accessible:

```bash
# Create a secondary disk image containing the model files
# (or use virtio-9p / virtiofs to share a host directory)
make run-qemu
# Wait for boot messages...
# Watch for: "vLLM server started" or similar
```

Once booted, test from the host:

```bash
curl -s http://localhost:8000/v1/models | jq .

curl -s http://localhost:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{
      "model": "/models/current",
      "messages": [{"role": "user", "content": "Say hello in one sentence."}],
      "max_tokens": 50
    }' | jq .
```

**Success criteria**: We get a valid OpenAI-format JSON response with generated
text. The response has `choices[0].message.content` with actual model output.

Also test streaming:

```bash
curl -s http://localhost:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{
      "model": "/models/current",
      "messages": [{"role": "user", "content": "Count to 5."}],
      "max_tokens": 50,
      "stream": true
    }'
# Should see: data: {"choices":[{"delta":{"content":"..."}}]}\n\n lines
# Ending with: data: [DONE]
```

**Success criteria**: SSE chunks arrive incrementally with delta content.

Note: CPU inference on TinyLlama will be very slow (seconds per token). That's
fine — we're testing the image pipeline, not performance.

#### Step 1f: Test on cloud with GPU (Deferred until Step 9)

Deploy to a cloud instance. Two options:

**Option A: Regular cloud VM with GPU (test inference only, no TEE)**
- Any cloud provider with NVIDIA GPUs (AWS p3/p4, GCP A100, Azure NC-series)
- Upload our image, boot from it
- Load a real model (Llama 3.1 8B or 70B)
- Verify inference performance is acceptable

**Option B: Confidential VM with GPU (test TEE + inference)**
- Azure DCas_v5 / DCads_v5 with NVIDIA H100 (confidential computing)
- Or GCP N2D with AMD SEV (CPU only, no GPU CC yet)
- This proves the image boots in a real TEE environment

Start with Option A (simpler, more available), move to Option B once we need
attestation (step 9).

```bash
# Upload image to cloud (method varies by provider)
# Example for Azure:
az vm create \
    --name tacet-test \
    --image tacet.vhd \
    --size Standard_NC6s_v3 \
    --admin-username tacet

# SSH in and verify
ssh tacet@<ip>
systemctl status vllm
curl localhost:8000/v1/models

# Test with a real model
curl localhost:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{
      "model": "meta-llama/Llama-3.1-8B-Instruct",
      "messages": [{"role": "user", "content": "Explain E2E encryption briefly."}],
      "max_tokens": 200
    }'
```

**Success criteria**: Real model inference at reasonable speed (tokens/sec).
Streaming works. Response format matches OpenAI spec exactly.

#### Step 1g: Write test script

Create `tee/test-inference.ts` (or `.sh`) that automates the verification:

```typescript
// tee/test-inference.ts
// Tests the vLLM endpoint directly (no gateway, no encryption)

const BASE_URL = process.env.VLLM_URL || "http://localhost:8000";

async function testModels() {
  const res = await fetch(`${BASE_URL}/v1/models`);
  const data = await res.json();
  console.log("✓ /v1/models:", data.data.length, "models available");
  return data.data[0].id;  // return first model name
}

async function testCompletion(model: string) {
  const res = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Say hello in one sentence." }],
      max_tokens: 50,
    }),
  });
  const data = await res.json();
  console.log("✓ Non-streaming:", data.choices[0].message.content);
  console.log("  Tokens:", data.usage);
}

async function testStreaming(model: string) {
  const res = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Count to 5." }],
      max_tokens: 50,
      stream: true,
    }),
  });

  let chunks = 0;
  let content = "";
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value);
    for (const line of text.split("\n")) {
      if (line.startsWith("data: ") && line !== "data: [DONE]") {
        const chunk = JSON.parse(line.slice(6));
        const delta = chunk.choices[0]?.delta?.content || "";
        content += delta;
        chunks++;
      }
    }
  }

  console.log("✓ Streaming:", chunks, "chunks received");
  console.log("  Content:", content);
}

async function main() {
  console.log(`Testing vLLM at ${BASE_URL}\n`);
  const model = await testModels();
  await testCompletion(model);
  await testStreaming(model);
  console.log("\n✓ All tests passed");
}

main().catch(console.error);
```

Run: `npx tsx tee/test-inference.ts`

This script becomes our regression test — we re-run it after every change to
make sure inference still works through whatever layers we've added.

---

### Step 2: @tacet/noise Library

**Status**: Complete. NK + XX patterns implemented, 94 tests passing
(6 external vectors from cacophony/snow/noise-c, 11 session API tests,
77 property/edge-case tests covering every layer).

(Can start in parallel with Step 1)

**Goal**: A standalone, browser-compatible Noise Protocol implementation with
tests. Implements NK pattern, transport messages, and chunked framing.

Details to be planned when we start this step. High-level:
- Implement CipherState, SymmetricState, HandshakeState per Noise spec
- Built on @noble/curves + @noble/ciphers + @noble/hashes
- NK and XX patterns (IK and XXfallback deferred to Step 9 / Phase 5: Noise Pipes)
- Transport message encrypt/decrypt with auto-incrementing nonce
- Chunked framing for large payloads (2-byte length prefix)
- Comprehensive test suite (cacophony test vectors from Noise spec)
- Pure TypeScript, works in browser + Node.js
- Zod schemas for message/config validation

### Step 3: Simple Test Script → Image

**Status**: Complete. `tee/test-inference.ts` validated on 2026-04-17 against
a live vLLM 0.19.0 + Qwen2.5-0.5B-Instruct serving on an RTX 5090 (Blackwell
sm_120). All three test cases pass: `/v1/models`, non-streaming
`/v1/chat/completions`, and streaming `/v1/chat/completions`.

Caveat: the test was run against vLLM running *natively* on the vast.ai host
(same `tacet-vllm` systemd unit, same vLLM pin), not against vLLM running
*inside* our mkosi image. Proving the inside-the-image path awaits Step 1f
at Step 9.

**Goal**: A standalone script (not the full gateway/SDK yet) that talks to the
vLLM endpoint inside the image. Just proves we have a working target to point
the rest of the stack at. (This is essentially Step 1g extended.)

### Step 4: Noise Endpoint in Image

**Goal**: Add a Noise-aware server to the VM image that sits in front of vLLM.
Accepts Noise-encrypted requests over WebSocket, decrypts them, forwards to
vLLM over localhost HTTP, encrypts the response, returns over WS.

```
Client ──WS──▶ Noise Endpoint (port 443) ──HTTP──▶ vLLM (port 8000, localhost)
                   │
                   ├── Noise handshake (NK or XX)
                   ├── Decrypt request → plaintext JSON
                   ├── Forward to vLLM localhost:8000
                   ├── Read vLLM response/SSE stream
                   ├── Encrypt response → Noise transport messages
                   └── Send encrypted WS frames back to client
```

This is a TypeScript/Node.js server included in the image. Uses @tacet/noise
from Step 2. Generates a static keypair on boot.

### Step 5: Gateway (WS Relay)

**Goal**: The untrusted gateway that accepts WS connections from clients and
relays opaque encrypted blobs to/from the TEE backend.

- Accept WS at `/v1/ws?config_id=<uuid>`
- Look up config_id → TEE backend address
- Open WS to TEE backend
- Forward all messages bidirectionally (can't read them — encrypted)
- Also serves `GET /v1/keys` (TEE public key) and `GET /v1/configs`

### Step 6: Browser SDK (WS + Noise)

**Goal**: @tacet/sdk — browser JS SDK with OpenAI-compatible API surface.

- `TacetClient.create({ configId, baseUrl })` — opens WS to gateway
- Performs NK handshake as first WS messages
- `.chat.completions.create()` — encrypts request, sends over WS, decrypts
  streaming response chunks
- Auto-reconnect + re-handshake on WS failure
- Serialized requests per connection

### Step 7: End-to-End Encrypted Test

**Goal**: Full pipeline test. Browser SDK → WS → Gateway → TEE → vLLM → back.

- Run the test-inference.ts equivalent but through the full encrypted stack
- Verify: gateway sees only encrypted blobs (log/inspect at gateway level)
- Verify: response decrypted by SDK matches what vLLM would return directly

### Step 8: Postgres + Configs + Metrics

**Goal**: Add persistence. Configs, sessions, usage tables in Postgres.

- Gateway reads config_id → backend mapping from Postgres
- Sessions recorded on WS open/close
- Usage metrics: TEE reports token counts alongside encrypted response
- Gateway logs usage to Postgres
- API key auth + rate limiting

### Step 9: Attestation + dm-verity

**Goal**: Make the TEE verifiable.

- Add dm-verity to image build (merkle tree over rootfs, hash in cmdline)
- Hash model weights at boot, include in cmdline
- TEE generates attestation quote containing measurements + public key
- Embed attestation in Noise handshake payload (XX pattern)
- SDK verifies attestation: hardware signature, pubkey binding, measurements
  match transparency log
- Set up transparency log for publishing measurements
- Reproducible build pipeline (anyone can rebuild, verify same hash)

### Step 10: Passkey Encryption

**Goal**: At-rest encryption using WebAuthn PRF.

- SDK: `navigator.credentials.get()` with PRF extension
- HKDF subkey derivation from 32-byte PRF output
- Encrypted conversation storage on server
- Cross-device access via same passkey

### Step 11: Client-Side Tools

**Goal**: Tool calling over WebSocket.

- SDK exposes tool_calls to developer's browser code
- Developer registers handlers: `client.tools.register(...)`
- Multi-turn loop over WS: prompt → tool_call → execute → tool_result → response
- OAuth PKCE for service connections (Gmail, Calendar, etc.)

### Step 12: Developer Runtime (Phase 8)

**Goal**: Full "use server" runtime in TEE.

- Developer uploads app config (system prompt, tools, code bundle) via HTTPS API
- Platform stores in Postgres (configs table: code_bundle, env_vars, etc.)
- TEE loads configs at boot, runs each app in isolated V8 context
- Config bundle hash included in attestation
- `@tacet/runtime` framework: `defineApp()`, `ctx.userCredentials`, `ctx.env`
- One vLLM per TEE, multiple apps sharing it (isolated V8 contexts)
