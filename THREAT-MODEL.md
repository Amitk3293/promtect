# Promtect threat model

What Promtect protects, what it does not, and the assumptions it rests on. A security
tool earns trust by stating its boundaries, so here they are, plainly.

## The threat

You run an AI coding tool (Claude Code, Cursor, Codex, Ollama, …). It reads your repo,
your `.env`, a connection string, a pasted snippet, and ships them to a model
provider. If a secret rides along, it now lives on a third party's servers: in logs,
in abuse-review queues a human may read, in subprocessors you never chose, in the next
breach. The provider's own guidance treats an exposed credential as compromised:
OpenAI says rotate a leaked key immediately. You can rotate; you cannot un-send.

Promtect is the control that runs **outside the model's loop**: it masks known-format
secrets out of the request before it leaves your machine, then restores them in the
streamed reply so the answer stays useful.

## What Promtect protects

- **Known-format secrets in the request body**: provider API keys/tokens with a
  recognizable shape, `KEY=value` credential pairs, database-URL passwords, JWTs, and
  PEM/OpenSSH/PGP private-key blocks. See [`src/detect.rs`](src/detect.rs).
- **UTF-8 text request bodies** of tools that honor a base-URL override (the JSON
  bodies the supported tools actually send).
- **The streamed response**: secrets the proxy masked on the way out are restored
  token-by-token on the way back (or kept masked in strict mode).

## What Promtect does NOT protect (by design, today)

- **Unknown-format / high-entropy secrets.** Detection is pattern-based. A custom or
  internal token with no recognizable prefix is **not** caught. (Entropy-based
  detection is a planned, separate capability.)
- **The model's response is not scanned for secrets.** Restore only re-inserts
  sentinels minted for *this* request; a secret the model itself emits is not detected.
- **Non-text bodies.** Binary, multipart, base64-encoded, or compressed request bodies
  are forwarded unscanned (a secret encoded before it reaches Promtect is not matched).
- **Tools without a base-URL override.** VS Code Copilot and browser/web chat
  (chatgpt.com, claude.ai) cannot be proxied without a root CA, which Promtect
  deliberately does not install.
- **Auth headers.** The API key in `Authorization` / `x-api-key` is forwarded
  verbatim, never masked, that is the tool's own credential to the provider, and
  masking it would break auth.

## Trust assumptions

- **Loopback only.** Promtect binds `127.0.0.1` by default; it is not a network service.
- **No TLS interception, no root CA.** It never touches your system trust store.
- **The tool's API-key flow is trusted.** Promtect masks request *bodies*; it assumes
  the tool sends its provider key in the auth header (which is forwarded untouched).
- **Memory-only.** Secrets live in RAM, zeroized on drop; a per-request vault makes
  cross-request restore impossible by construction.
- **Value-free audit.** The audit log records detector kind, sentinel ID, and counts,
  never the secret value or any body content.

## Residual risk & recommended practice

- Promtect is **defense-in-depth**, not a guarantee that no secret ever leaves. Pair it
  with: keeping secrets out of prompts (runtime retrieval), least-privilege keys, and
  rotation on a schedule.
- **If a secret was exposed before Promtect caught it, rotate it.** Promtect's value is
  preventing the exposure that forces a rotation, not licensing you to skip one.
- **Where you send matters.** Promtect classifies the upstream and warns when it is
  high-risk (e.g. DeepSeek: trains on input, China jurisdiction). `PROMTECT_BLOCK_RISKY=true`
  refuses high-risk or unverified upstreams outright.

## Reporting

Security issues: see [SECURITY.md](SECURITY.md), do not open a public issue.
