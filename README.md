# Promtect

### Your AI coding tool just saw your secrets. Promtect makes sure the model never does.

**One file with a key in it, handed to an AI tool, is a key you no longer control. You
can rotate it. You can't un-send it.**

Promtect is a local proxy that catches every API key, token, and password, **71
kinds**, before your AI tool can send them. Each secret is masked on the way out,
then restored in the reply (or kept masked in strict mode, your call). The model
does its job on your real code; your secrets stay on your machine.

**Open source. Runs entirely on your machine. No cloud, no telemetry, no root
certificate. Secrets are never written to disk.**

![Promtect masks every secret, keys, tokens, DB passwords, before the model sees it, and restores them in the reply](docs/demo.gif)

<sub>Recorded with [`vhs`](https://github.com/charmbracelet/vhs) from [`docs/demo.tape`](docs/demo.tape), rebuild with `cargo build --release && vhs docs/demo.tape`.</sub>

```sh
brew install Amitk3293/tap/promtect            # or: cargo install --path .

promtect guard claude                          # one command: proxy up, claude pointed at it, secrets masked
echo "ship it with $AWS_KEY" | promtect mask   # or just see what would get masked
```

---

## Why

You pasted a `.env` into Claude to debug it. You asked Cursor to "fix the S3
upload", and the file had your access key in it. You let an agent read your
config.

That key is now in a request log on a server you don't own, in a country you
didn't choose, under a retention policy you never read.

**Once a key reaches an AI provider, the advice is the same: rotate it, and treat
anything you sent as compromised.** The tools most developers already use have leaked:

- Shared **ChatGPT** conversations, some with proprietary code,
  [showed up in Google Search](https://www.malwarebytes.com/blog/news/2025/08/openai-kills-short-lived-experiment-where-chatgpt-chats-could-be-found-on-google)
  in 2025; OpenAI pulled the feature and called it a "short-lived experiment."
- **GitHub Copilot** was shown to
  [emit real secrets from its training data](https://blog.gitguardian.com/yes-github-copilot-can-leak-secrets/),
  and once a key is baked in, scrubbing it from your repo no longer removes it.
- **Samsung** engineers pasted source code and secrets into ChatGPT; Samsung banned it
  company-wide.

**Promtect keeps it from ever arriving.**

**What one slip costs you:** rotate every key in that file, force a redeploy, and write
the note explaining why production credentials went to a third party, and the secret is
already sitting in a log you'll never reach. **What it costs with Promtect:** nothing.
`promtect guard claude`, and the key never leaves your laptop. Nothing to rotate, because
nothing leaked.

**Switched to a cheap Chinese model to save on tokens?** DeepSeek, Kimi (Moonshot), and
GLM (Zhipu) [now lead coding traffic on OpenRouter](https://www.techtimes.com/articles/317352/20260529/chinese-ai-models-lead-openrouter-traffic-coding-gains-come-china-data-risk.htm),
and every request runs under Chinese jurisdiction, where the National Intelligence Law can
compel access no matter where the server sits. DeepSeek already trained on user input and
[left a database of prompts and API keys exposed](https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak).
Promtect masks before any of them see it, and `PROMTECT_BLOCK_RISKY=true` refuses them
outright.

---

## How it works

```
Your AI tool ──http──▶ Promtect :8787 ──https──▶ api.anthropic.com
                        │ detect + mask               │
                        └────────── restore ◀─────────┘
```

1. Your tool sends a plaintext HTTP request to Promtect on loopback.
2. Promtect scans the body and replaces each detected secret with an opaque
   sentinel (`«promtect:aws_key:0001»`).
3. Promtect re-originates the request as HTTPS to the upstream API.
4. As the response **streams back**, every sentinel is swapped for the real
   value before your tool reads it, token by token, no buffering, no hang.

No TLS interception. No root certificate. The auth header (`x-api-key`,
`Authorization`) is forwarded verbatim, only the body is ever touched.

---

## A local dashboard, value-free

`promtect dashboard` serves an offline view of what Promtect has caught: secrets
masked, the per-detector breakdown (every detector, counted live, nothing
hard-coded), the clean rate (share of requests carrying no secret), recent requests, and bytes processed. It reads only
the audit log, so it shows counts and detector names, never a secret value,
never request/response bodies.

![Promtect's local dashboard: secrets masked, per-detector breakdown, clean rate, and recent value-free request summaries](docs/dashboard.png)

## How Promtect compares

|  | **Promtect** | Veil | LiteLLM masking |
|---|:---:|:---:|:---:|
| **Restore secrets in the response** | ✅ yes, or keep masked (`PROMTECT_RESTORE=false`) | ❌ cannot | ❌ cannot |
| Detect secrets in transit | ✅ 71 detectors | ⚠️ limited | ✅ |
| Real-time restore as the answer streams in | ✅ per-token | ❌ | ❌ |
| No root certificate to install | ✅ | ❌ installs a CA | n/a |
| Secrets wiped from memory (Rust + zeroize) | ✅ | ❌ | ❌ |
| Value-free audit log | ✅ | ❌ logs to SQLite | ❌ |
| Runs locally / no cloud | ✅ | ✅ | ❌ server-side |
| Open source | ✅ Apache-2.0 | ✅ | ✅ |

**The gap no one else fills:** other tools hand the model `[REDACTED]` and you
get useless code back. Promtect is the only one that can restore, and it lets
you choose: transparent restore for usable answers, or strict mode where the
secret never comes back at all. And unlike Veil, Promtect installs no root
certificate, it never touches your system trust store, so there's no new
interception layer to trust.

---

## Run it in one command

`promtect guard <tool>` starts the proxy, points your tool at it, runs the tool,
and tears it down on exit, no manual env-var wiring:

```sh
promtect guard claude                     # Claude Code, secrets masked → Anthropic
promtect guard codex "fix the s3 upload"   # Codex → OpenAI
promtect guard ollama run deepseek-r1      # Ollama CLI → masked → local Ollama server
promtect guard aider --model openai/gpt-4o  # Aider → masked → OpenAI-compatible
promtect guard claude --headroom           # chain Headroom: mask → compress → Anthropic
promtect guard codex --strict              # never re-insert secrets in the response
promtect guard --exec <tool> --base-var OPENAI_API_BASE --base-path /v1   # wrap any tool
```

Your API keys (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) flow through untouched,
Promtect only masks the request body. The base URL each tool needs is set for you
(`ANTHROPIC_BASE_URL` for Claude, `OPENAI_BASE_URL` for Codex, `OLLAMA_HOST` for
Ollama). Combine with [Headroom](https://github.com/chopratejas/headroom) for
secrets-safe **and** ~90% cheaper sessions.

---

## Quickstart (manual)

### Native

```sh
cargo run            # binds 127.0.0.1:8787, upstream → api.anthropic.com
# in another shell:
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

### Docker

```sh
docker compose up --build
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

> **Security:** publish the port to `127.0.0.1:8787:8787`, never `8787:8787`.
> The bundled `docker-compose.yml` does this correctly by default.

### Prove it works (no network needed)

```sh
promtect selftest    # masks a canary secret, confirms it never leaks, restores it
```

---

## Works with your whole stack

Promtect protects more than Claude Code. Pick a provider with `PROMTECT_MODE`, or
point `PROMTECT_UPSTREAM` at anything (the **chaining knob**).

| Tool | Setup |
|------|-------|
| **Claude Code** | `promtect` then `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` |
| **Cursor** | `PROMTECT_MODE=openai promtect`; set Cursor's OpenAI base URL to `http://127.0.0.1:8787/v1` |
| **OpenAI Codex CLI** | `PROMTECT_MODE=openai promtect`; `OPENAI_BASE_URL=http://127.0.0.1:8787/v1` |
| **Ollama** (local/Chinese models) | `PROMTECT_MODE=ollama promtect`; `OPENAI_BASE_URL=http://127.0.0.1:8787/v1` |
| **OpenRouter** | `PROMTECT_MODE=openrouter promtect`; `OPENAI_BASE_URL=http://127.0.0.1:8787/api/v1` |
| **Agent harnesses** (OpenCode, Crush, Goose, Pi) | set the harness's provider `baseUrl` to `http://127.0.0.1:8787` ([guide](docs/integrations/harnesses.md)) |
| **Aider** | `promtect guard aider --model openai/gpt-5.5` |
| **OpenClaw / NanoClaw** | point the gateway's provider base URL (or `ANTHROPIC_BASE_URL`) at Promtect ([OpenClaw](docs/integrations/openclaw.md), [NanoClaw](docs/integrations/nanoclaw.md)) |
| **Headroom / LiteLLM / corp proxy** | `PROMTECT_UPSTREAM=<their-url> promtect` (Promtect goes first) |
| **VS Code Copilot** | not yet, it needs a root CA, which Promtect deliberately avoids ([why](docs/integrations/vscode-copilot.md)) |

Full guides: [`docs/integrations/`](docs/integrations/README.md). It doesn't
matter whether you're using Claude, GPT, DeepSeek, or a local model, Promtect
masks your secrets before any of them see them.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PROMTECT_PORT` | `8787` | Local port to bind (loopback) |
| `PROMTECT_MODE` | `anthropic` | Upstream preset: `anthropic` / `openai` / `ollama` / `openrouter` |
| `PROMTECT_UPSTREAM` |, | Explicit upstream URL; overrides mode (chaining) |
| `PROMTECT_RESTORE` | `true` | `false` = strict mode: secrets are never re-inserted |
| `PROMTECT_BLOCK_RISKY` | `false` | `true` = refuse to proxy to a high-risk/unverified upstream (e.g. DeepSeek) |
| `PROMTECT_AUDIT` | `promtect-audit.jsonl` | Value-free audit log path |
| `PROMTECT_BIND` | `127.0.0.1` | Bind address (loopback by default) |
| `PROMTECT_MAX_BODY_BYTES` | `33554432` | Request-body cap (32 MiB) before a 413 |
| `PROMTECT_DASHBOARD_PORT` | `8799` | Dashboard port (`promtect dashboard`) |

---

## Two modes, you choose

- **Transparent (default):** secret masked outbound, real value restored
  in the answer → AI output is directly usable.
- **Strict (`PROMTECT_RESTORE=false`):** secret masked and *never* restored,
  provably never touches the response, logs, or terminal. Maximum paranoia for
  security-strict teams.

---

## What it detects

**71 detectors** ship with Promtect, covering known credential formats across ~70 providers:

- **AI/LLM:** Anthropic, OpenAI, Groq, OpenRouter, Replicate, Perplexity,
  Fireworks, NVIDIA, HuggingFace, Google AI
- **Cloud/infra:** AWS (keys + secret), GCP, Azure Storage, DigitalOcean,
  Doppler, HashiCorp Vault, Terraform, Databricks, PlanetScale, Tailscale
- **Dev tools:** GitHub, GitLab, npm, PyPI, Docker Hub, Shopify, Linear,
  Atlassian, Figma, Notion, Airtable, RubyGems, Postman, SonarQube, CircleCI
- **SaaS/pay:** Slack, Discord, Twilio, SendGrid, Mailgun, Stripe, Square,
  Razorpay
- **AI infra:** Pinecone, LangSmith, MCP-style bearer tokens
- **Structural:** JWTs, PEM / OpenSSH / PGP private keys, DB-URL passwords,
  `.env`-style `KEY=value` pairs (with a placeholder + code-expression guard)

Adding a detector is ~one line in `src/detect.rs`, see
[CONTRIBUTING.md](CONTRIBUTING.md).

The test suite asserts every detector masks a synthetic secret and that prose, code
expressions, and placeholders are **never** masked, the benchmark in
[`tests/corpus.rs`](tests/corpus.rs) catches 20/20 representative formats with 0 false
positives on the negative corpus.

---

## What it catches, and what it doesn't (yet)

Promtect is a focused control, not a catch-everything. It's honest about its edges:

| Catches | Doesn't catch (yet) |
|---|---|
| Known-format secrets in the request body (keys, tokens, DB-URL passwords, JWTs, PEM keys) | Unknown-format / high-entropy secrets with no recognizable shape |
| UTF-8 text bodies of tools with a base-URL override (Claude Code, Cursor, Codex, Ollama, OpenRouter) | The model's **response** (restore only re-inserts what it masked) |
| The streamed response (real-time restore, or strict mode) | Binary / multipart / base64 / compressed bodies |
| | Tools without a base-URL override (VS Code Copilot, browser chat) |

Full scope and trust assumptions: **[THREAT-MODEL.md](THREAT-MODEL.md)**.

## Know where you're sending

Masking is half the story, *where* the request goes still matters. Promtect classifies
the upstream and prints a one-line risk note at startup:

```
upstream risk: Anthropic API: an exposed key still means rotate it; Promtect keeps
               it from arriving.
upstream risk: DeepSeek: HIGH RISK: trains on your input, China jurisdiction
               (National Intelligence Law can compel access), no zero-retention.
upstream risk: Kimi (Moonshot AI): HIGH RISK: data processed in China; the National
               Intelligence Law can compel access regardless of server.
```

Set `PROMTECT_BLOCK_RISKY=true` to refuse high-risk or unverified upstreams (DeepSeek,
Kimi, GLM, or any host Promtect can't vouch for) outright. Fail-closed.

---

## Trust model

- **Memory-only.** Secrets exist only in RAM and are zeroized on drop via the
  `zeroize` crate.
- **Per-request vault.** Each request gets a fresh vault; a sentinel minted for
  request A cannot restore a secret from request B, cross-request bleed is
  impossible by construction.
- **Round-trip proven.** `restore(mask(x)) == x` is a property test, and the
  streaming restorer is proven byte-for-byte identical to whole-buffer restore at
  every chunk boundary.
- **Headers untouched.** Auth headers are forwarded verbatim; Promtect scans
  request bodies only.
- **No telemetry.** Exactly one outbound connection per proxied request.

---

## Dashboard & audit

```sh
promtect dashboard      # http://127.0.0.1:8799, UI, /api/metrics (JSON), /metrics (Prometheus)
```

Every mask/unmask event is appended to `promtect-audit.jsonl`, timestamp,
action, detector kind, sentinel ID, request ID. **It never records the real
secret value**, only the opaque placeholder, a clean, value-free audit trail.

---

## Develop

```sh
make test     # cargo test, 126 unit + integration + property tests
make lint     # cargo fmt --check + clippy --all-targets -D warnings
make smoke    # build + run: prove masking + value-free audit
```

See [TESTING.md](TESTING.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
[SECURITY.md](SECURITY.md).

---

## Documentation

- **[Try it (FAQ & troubleshooting)](docs/faq.md)** — prove it's masking, multi-tool setup, strict mode, common gotchas.
- **[Detector reference](docs/detectors.md)** — every one of the 71 detectors, by provider.
- **[Architecture](docs/architecture.md)** — how a request flows through detect → vault → mask → streaming restore.
- **[Integrations](docs/integrations/README.md)** — Claude Code, Cursor, Codex, Ollama, OpenRouter, chaining.
- **[Threat model](THREAT-MODEL.md)** · **[Roadmap](ROADMAP.md)** · **[Security policy](SECURITY.md)**

Or run it locally with no setup: `promtect playground` narrates a full
mask → forward → restore round-trip against a mock upstream.

---

## License

Apache-2.0, open source, all of it.
