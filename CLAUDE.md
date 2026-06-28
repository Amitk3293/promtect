# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is
Promtect: a local-first security proxy (Rust, Axum). It sits on loopback, masks secrets
(API keys, DB passwords, JWTs, PEM keys — ~75 detectors) in outbound AI-tool requests
before they reach a provider (Anthropic/OpenAI/Ollama/OpenRouter), then restores them in
the streamed response. No root CA, no cloud, no telemetry. Free core is under the
Sustainable Use License (fair-code, source-available);
`../promtect-pro` is a separate crate for paid detectors (entropy/PII-PHI/output-scan).

## Commands
Run from the crate root (this dir). Toolchain pinned via `rust-toolchain.toml`.

- Build: `cargo build` / `cargo build --release` (or `make build`)
- Test: `cargo test` (or `make test`)
- Single test: `cargo test <name>` (e.g. `cargo test same_secret_same_sentinel`)
- One test file: `cargo test --test proxy_integration`
- Lint: `cargo clippy --all-targets -- -D warnings` (or `make lint`, which also fmt-checks)
- Format: `cargo fmt` (CI gate: `cargo fmt --check`)
- Security audit: `cargo audit --deny warnings` (run before adding/bumping deps)
- Selftest (detector canary, no network): `cargo run -- selftest` / `make selftest`
- Smoke (end-to-end proxy + audit): `bash scripts/smoke.sh` / `make smoke`
- Coverage: `make coverage` (needs `cargo install cargo-llvm-cov`)
- Run proxy: `cargo run` → binds `127.0.0.1:8790`, then point a tool at it, e.g.
  `ANTHROPIC_BASE_URL=http://127.0.0.1:8790 claude`

## Architecture (src/)
Per-request pipeline; all secret state is request-scoped to prevent cross-request bleed.

`main.rs` dispatches subcommands by `args[1]`: default→proxy, `selftest`, `mask` (stdin→
stdout), `playground` (offline demo), `guard <tool>` (ephemeral proxy wrapping a tool),
`dashboard`. `lib.rs` exports the modules.

Request flow:
1. `proxy.rs` (`Ctx`, `app()`, `handle()`) — Axum router; buffers request body (32 MiB cap),
   orchestrates mask → forward → restore. Masking is decided by actual UTF-8 validity of the
   body bytes, NOT the client's Content-Type (a mislabelled body cannot bypass masking).
2. `detect.rs` — `detect(text) -> Vec<Match>`; static `DETECTORS` registry of `RegexDetector`s
   (compiled in, not runtime-pluggable). Has guards to skip placeholders ("changeme", `process.env`…).
   `regex` crate only (linear-time, no backrefs) — keep it that way (no ReDoS).
3. `mask.rs` — `mask_text()` swaps secrets for sentinels; single-pass `restore_scan()` expands
   them back (never cascades). Sentinel grammar: `«promtect:KIND:HEX»` (`SENTINEL_RE`).
4. `vault.rs` — per-request bidirectional secret↔sentinel map. Fresh instance per request;
   `zeroize` wipes the maps on drop.
5. `stream.rs` — `StreamRestorer` restores sentinels incrementally across chunked/SSE responses
   (holds back partial sentinels / partial UTF-8; carry bounded by `max_sentinel_len`).
6. `audit.rs` — append-only value-free JSONL (never logs secret values; 0600 on Unix).
   Fail-OPEN: an audit write failure must never block masking.

Supporting: `provider.rs` (`classify()` upstream risk, backs `PROMTECT_BLOCK_RISKY`),
`guard.rs` (`plan_guard()` pure parse + `guard()` I/O), `dashboard.rs`+`metrics.rs`
(audit → HTML/JSON/Prometheus on :8799), `playground.rs`, `net.rs` (client + loopback check).

Invariants worth preserving: fail-CLOSED on config (bad port/cap/blocked upstream → exit),
fail-OPEN on audit; per-request vault; no `unwrap`/`expect`/`panic!`/`unsafe` on a production
path (only `LazyLock` compile-time-constant regexes use `expect`).

Adding a detector: one regex entry in `src/detect.rs` (see CONTRIBUTING.md) + one positive and
one negative test. A false negative in a masking proxy is a leak — prefer over-masking in
high-context detectors.

## Config (env vars)
`PROMTECT_PORT`(8790) · `PROMTECT_MODE`(anthropic|openai|ollama|openrouter) ·
`PROMTECT_UPSTREAM`(explicit URL, overrides mode) · `PROMTECT_RESTORE`(true; `false`=strict,
secrets never reinserted) · `PROMTECT_OUTPUT_SCAN`(true; `false`=disabled; gates the
Pro response output scan, no-op in core) · `PROMTECT_BLOCK_RISKY`(false) · `PROMTECT_BIND`(127.0.0.1) ·
`PROMTECT_AUDIT`(promtect-audit.jsonl) · `PROMTECT_MAX_BODY_BYTES`(33554432) ·
`PROMTECT_DASHBOARD_PORT`(8799) · `PROMTECT_READ_TIMEOUT`(120s; per-chunk inter-read
timeout, safe for long SSE streams) · `PROMTECT_ALLOW_PUBLIC_BIND`(false; set truthy to
bind proxy/dashboard to a non-loopback address — off-loopback bind exits 1 without this).

## Workflow (non-obvious — read before committing)
- **Enable the version-bump hook once per clone:** `git config core.hooksPath .githooks`.
  The pre-commit hook auto-bumps the Cargo.toml patch version when code changes (src/, tests/,
  build.rs, Cargo.toml); docs-only commits don't bump. Bump major/minor by hand if warranted.
- **Branch flow:** `feature/*` → PR → `staging` (integration, CI must be green) → PR → `main`
  (released) → tag `vX.Y.Z`. Never push `main` directly. See BRANCHING.md / RELEASING.md.
- **Release:** tag on `main` triggers `release.yml` (binaries: macOS aarch64/x86_64, Linux
  x86_64/aarch64) + Homebrew tap update via `scripts/update-formula.sh`.
- CI (`.github/workflows/ci.yml`): fmt, clippy, test, smoke, cargo-audit on Linux + macOS.

## Reference docs
THREAT-MODEL.md (what Promtect does/doesn't protect; auth headers and response body are
out-of-scope by design) · TESTING.md (L1 unit / L2 integration / L3 property / L4 smoke /
L5 coverage) · CONTRIBUTING.md (add a detector) · SECURITY.md · ROADMAP.md.
