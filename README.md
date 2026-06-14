# Promtect

**Ship code, not secrets.** Promtect is a local proxy that intercepts every request
your AI coding tool sends to the cloud, masks credentials out of the body *before*
they reach the LLM, and restores them in the response. The model answers normally —
it just never sees your real secrets.

Free. Open-source. Runs entirely on your machine. No cloud, no telemetry, no root CA,
and secrets are never written to disk.

---

## The problem

Every AI coding tool — Claude Code, GitHub Copilot, Cursor — sends your full
conversation to a remote LLM. That conversation routinely contains secrets: API keys
pasted into prompts, tokens read from files, database passwords echoed by shell
commands. One careless paste and your credentials are in a cloud model's training
pipeline.

Promtect sits on the loopback interface and fixes this transparently. You use your AI
tool exactly as before. The secrets stay home.

---

## How it works

```
Your AI tool ──http──▶ Promtect :8787 ──https──▶ api.anthropic.com
                        │ detect + mask               │
                        └────────── restore ◀─────────┘
```

1. Your tool sends a plaintext HTTP request to Promtect on loopback.
2. Promtect scans the request body, replaces each detected secret with an opaque
   sentinel (`«promtect:aws_key:0001»`).
3. Promtect re-originates the request as HTTPS to the upstream API.
4. On the way back, every sentinel in the response is swapped for the real value
   before your tool reads it.

No TLS interception. No root certificate. The auth header (`x-api-key`,
`Authorization`) is forwarded verbatim — only the body is ever touched.

---

## Quickstart

### Docker — 30 seconds

```sh
docker-compose up --build
```

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude           # use Claude Code as normal — Promtect is transparent
```

> **Security:** Always publish the port to `127.0.0.1:8787:8787`, not `8787:8787`.
> The bundled `docker-compose.yml` does this correctly by default.

### Native (Rust)

```sh
cargo run        # binds 127.0.0.1:8787, upstream → api.anthropic.com
```

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

### Prove it works (no network needed)

```sh
cargo run -- selftest   # → promtect selftest: PASS — no leak
cargo test              # 55 unit + integration + property tests
```

---

## Works with any setup

By default Promtect connects directly to `https://api.anthropic.com` — no other
tools required. If you already have an intermediate proxy (for context compression,
rate limiting, corporate egress, etc.) just point `PROMTECT_UPSTREAM` at it:

```sh
# Default: straight to Anthropic — works for everyone out of the box
PROMTECT_UPSTREAM=https://api.anthropic.com          # default

# Chained through Headroom (context-compression proxy)
PROMTECT_UPSTREAM=http://127.0.0.1:8788

# Chained through LiteLLM or any OpenAI-compatible gateway
PROMTECT_UPSTREAM=http://localhost:4000

# Through a corporate HTTPS gateway
PROMTECT_UPSTREAM=https://ai-gateway.corp.internal
```

Promtect is upstream-agnostic: it forwards all headers (including auth) unchanged
and handles the HTTP↔HTTPS boundary regardless of what sits behind it.

### Full env-var reference

| Variable | Default | Description |
|---|---|---|
| `PROMTECT_PORT` | `8787` | Local port to bind |
| `PROMTECT_UPSTREAM` | `https://api.anthropic.com` | Upstream URL |
| `PROMTECT_AUDIT` | `promtect-audit.jsonl` | Audit log path |
| `PROMTECT_BIND` | `127.0.0.1` | Bind address (loopback by default) |
| `PROMTECT_DASHBOARD_PORT` | `8799` | Dashboard port (dashboard subcommand) |

---

## What it detects

18 detectors ship out of the box, grouped by pattern type:

**Provider tokens** (prefix-anchored): AWS access keys (`AKIA`/`ASIA`), Anthropic
`sk-ant-`, OpenAI `sk-`, Stripe live/test keys, GitHub PATs and fine-grained tokens,
GitLab PATs, Slack tokens (`xox*`), Google API keys (`AIza`), SendGrid, HuggingFace,
npm.

**Structural secrets**: JWTs, PEM private-key blocks, database URL passwords (Postgres,
MySQL, Redis).

**Context-keyed values**: `.env`-style `KEY=value` pairs where the key contains
`SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, or similar — with a placeholder guard that
ignores obvious defaults like `changeme`, `example`, `null`.

Adding a new detector is one line in `src/detect.rs`.

---

## How Promtect compares

Verified against primary sources (LiteLLM docs, Veil README, Velar README) in June 2025:

|  | **Promtect** | LiteLLM Enterprise | Veil | Velar |
|---|:---:|:---:|:---:|:---:|
| Detects secrets in transit | ✅ 18 detectors | ✅ | ⚠️ Bearer tokens only | ✅ |
| Masks before the LLM sees it | ✅ | ✅ (`[REDACTED]`) | ❌ | ✅ |
| **Restores real values in response** | ✅ | ❌ stays `[REDACTED]` | ❌ | ❌ streaming gap |
| Runs locally / no cloud | ✅ | ❌ server-side | ✅ | ✅ |
| Free & open-source | ✅ | ❌ Enterprise tier | ✅ | ✅ |
| Works with Claude Code out of the box | ✅ | ✅ | ⚠️ | ⚠️ |
| Streaming response restore | ⚠️ M1 | — | — | ❌ explicit gap¹ |
| No root CA required | ✅ | ✅ | ✅ | ✅ |

¹ Velar's README states: *"Streaming responses are forwarded but content is not modified."*
Since Claude Code, Copilot, and Cursor all default to streaming, this means Velar's masking
is bypassed for the primary use case.

**The key gap no competitor fills:** detect in transit + mask before the LLM + restore the
real value in the response. LiteLLM comes closest but permanently replaces secrets with
`[REDACTED]` — your output is broken, not protected.

---

## Dashboard

```sh
PROMTECT_DASHBOARD_PORT=8799 \
PROMTECT_AUDIT=promtect-audit.jsonl \
  cargo run -- dashboard
```

Opens `http://127.0.0.1:8799` with:
- **`/`** — browser UI: total requests, secrets caught, per-detector breakdown, recent events
- **`/api/metrics`** — JSON (same data, machine-readable)
- **`/metrics`** — Prometheus text exposition

---

## Audit log

Every mask and unmask event is appended to `promtect-audit.jsonl` as one JSON object
per line. The log records timestamps, action, detector kind, sentinel ID, and request
ID. **It never contains the real secret value** — only the opaque placeholder.

```jsonl
{"ts_ms":1781462180047,"action":"mask","detector":"aws_key","placeholder":"«promtect:aws_key:0001»","request_id":"f829fe7d"}
{"ts_ms":1781462180047,"action":"mask","detector":"stripe_key","placeholder":"«promtect:stripe_key:0002»","request_id":"f829fe7d"}
{"ts_ms":1781462180049,"action":"unmask","detector":"sentinel","placeholder":"«promtect:aws_key:0001»","request_id":"f829fe7d"}
```

---

## Trust model

- **Memory-only.** Secrets exist only in RAM and are zeroized on drop via the
  `zeroize` crate — no heap dump, no swap residue beyond what the OS guarantees.
- **Per-request vault.** Each request gets a fresh vault. A sentinel minted for
  request A cannot restore a secret from request B — cross-request bleed is
  impossible by construction.
- **Headers untouched.** Auth headers (`x-api-key`, `Authorization`) are forwarded
  verbatim. Promtect scans request bodies only.
- **Upstream TLS.** Outbound connections use rustls with the platform certificate
  verifier (OS trust store). No custom CA, no certificate pinning bypassed.
- **Loopback-only by default.** `PROMTECT_BIND` defaults to `127.0.0.1`. In Docker
  the container binds `0.0.0.0`, and the guarantee comes from publishing the port to
  `127.0.0.1:PORT:PORT` on the host — the bundled compose file does this.
- **No telemetry.** Exactly one outbound connection per proxied request. Nothing else
  leaves the machine.

---

## Develop

```sh
make test          # cargo test (55 tests: unit + integration + property)
make lint          # cargo fmt --check + clippy --all-targets -D warnings
make smoke         # compile + run binary: prove masking + value-free audit log
make coverage      # text coverage summary (needs: cargo install cargo-llvm-cov)
make docker-build  # build the distroless image
make up            # docker compose up -d
make down          # docker compose down
```

See [TESTING.md](TESTING.md) for the layered test strategy and the contract for
keeping tests aligned with every change.

---

## Limitations & roadmap

| Item | Status |
|---|---|
| **SSE streaming restore** | **M1** — responses are buffered; secrets in streamed tokens are restored after the full response arrives, not per-token |
| Linux native binary | Roadmap |
| Custom always-mask vault (user-defined secrets) | M2 |
| Entropy-based unknown-secret detection | M2 |
| DB URL password containing literal `@` | Truncated at first `@`; encode as `%40` to work around |

---

## License

MIT. Contributions welcome — open an issue before sending a large PR.
