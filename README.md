# Airlock AI

**Local-first privacy proxy for AI coding tools.** Airlock sits between your AI
tool and the cloud, masks secrets out of the outbound request **before** they
reach the LLM, and restores them in the response. The model gets a coherent
prompt and answers normally — it just never sees your real secrets. Everything
runs on your machine: no cloud, no telemetry, no root CA, and secrets are never
written to disk.

> **Status: M0 spike.** Works end-to-end for the Claude Code CLI on macOS.
> Private during development; open-source at the M1 release.

## How it works

```
Claude Code ──http──▶ Airlock (127.0.0.1) ──https──▶ api.anthropic.com
                       │  detect + mask                  │
                       └──────── restore ◀───────────────┘
```

You point Claude Code at a local loopback port via `ANTHROPIC_BASE_URL`. Airlock
reads the plaintext request on loopback, swaps detected secrets for opaque
sentinels (`«airlock:aws_key:0001»`), forwards its own HTTPS request upstream,
then restores the real values in the response. No TLS interception, no root
certificate.

## Run

```sh
cargo run            # listens on http://127.0.0.1:8787
```

In another shell:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude               # use Claude Code normally
```

Config via env vars: `AIRLOCK_PORT` (default 8787), `AIRLOCK_UPSTREAM`
(default `https://api.anthropic.com`), `AIRLOCK_AUDIT` (default
`airlock-audit.jsonl`).

## Prove it works (no network)

```sh
cargo run -- selftest        # -> "airlock selftest: PASS — no leak"
```

The automated test suite includes a canary test that asserts a planted AWS key
reaches a mock upstream **only** as a sentinel, and is restored on the way back:

```sh
cargo test
```

## What it detects (M0 precision pack)

Prefix-anchored provider tokens (AWS `AKIA`/`ASIA`, Anthropic `sk-ant-`, OpenAI
`sk-`, Stripe, GitHub/GitLab, Slack, Google, SendGrid, HuggingFace, npm), PEM
private-key blocks, JWTs, AWS secret keys, database-URL passwords, and
context-keyed `.env` values (guarded against config placeholders like
`changeme`). Adding a detector is one line in `src/detect.rs`.

## Audit log

Every mask/unmask is appended to `airlock-audit.jsonl` as one JSON object per
line — timestamp, action, detector, sentinel id, request id. **Never the secret
value.**

## Trust properties

- Secrets exist only in memory and are zeroized on drop.
- Loopback-only bind (`127.0.0.1`); the upstream auth header is forwarded
  untouched (Airlock masks request **bodies**, never headers).
- Exactly one outbound connection per request; no telemetry.

## Scope & limitations (M0)

- **macOS, Claude Code CLI, explicit-config (no CA).** Other tools, a local CA
  for zero-config transparency, and Linux are later milestones.
- **Responses are buffered**, not token-streamed — SSE-aware streaming restore
  is M1.
- Entropy/unknown-secret detection and a custom always-mask vault are M1/M2.
- Known gap: a database-URL password containing a literal `@` is truncated at
  the first `@` (uncommon; usually `%40`-encoded).
