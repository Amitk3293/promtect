# Changelog

All notable changes to Promtect are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Per-release binaries
and auto-generated notes also live on the
[GitHub Releases](https://github.com/amitk3293/promtect/releases) page.

## [Unreleased]

### Added
- New detectors: `xai_key` (xAI / Grok), `supabase_key` (Supabase secret keys and
  personal access tokens), `render_key` (Render), `fly_token` (Fly.io).
- 21 more prefix-anchored detectors following GitHub secret-scanning's design:
  Jina, Anyscale, Vercel, Alibaba, Yandex, 1Password, Prefect, Flutterwave,
  EasyPost, Brevo, Typeform, Frame.io, Duffel, ReadMe, Buildkite, JFrog Artifactory,
  Clojars, Pulumi, Dynatrace, Honeycomb, Adobe.
- `db_password` now also matches `clickhouse://` and `cockroachdb://` connection URLs.
- `PROMTECT_OUTPUT_SCAN` environment variable: gates the Pro response output scan.
  Default-on when a scanner is present; a falsey value (`0`/`false`/`no`/`off`)
  disables it. No-op in the core, which ships no scanner.
- Response output-scan metrics: `promtect_output_secrets_total` and
  `promtect_output_secrets_by_detector` in the Prometheus export and the dashboard JSON.
- `promtect guard` prints a value-free end-of-session summary on exit (secrets masked
  this session, by detector, plus any output-scan findings), and stays quiet during
  the session so its notifications do not disturb a wrapped full-screen tool.
- `promtect guard claude` shows a Promtect-owned, value-free notice in Claude after
  a protected turn. The notice uses Claude's user-only Stop-hook `systemMessage`;
  it does not alter prompts, model context, or provider response bytes.

### Changed
- **Relicensed the core from Apache-2.0 to the Sustainable Use License (SUL v1.0)**,
  a fair-code, source-available license. Free for internal business, personal, and
  non-commercial use; no reselling or paid redistribution. Past Apache-2.0 releases
  (≤ v0.1.23) remain Apache-2.0. Licensor is AK DevOps Solutions SL. See `LICENSE`,
  `NOTICE`, `COMMERCIAL.md`, and `TRADEMARK.md`.

### Fixed
- CPU-bound detector, masking, and residual-scan work no longer starves Tokio's
  async workers. Scan admission is bounded before request-body retention; an
  overloaded proxy fails closed with a value-free HTTP 503, and a request that
  does not finish uploading within 30 seconds fails closed with a value-free
  HTTP 408. Neither rejection opens an upstream connection.
- `promtect --version`, `promtect -V`, and `promtect version` now print the version
  and exit, instead of starting the proxy.
- `promtect guard claude` now overrides persisted Claude base-URL settings and
  disables third-party provider selectors for the guarded session, preventing
  those settings from routing requests around Promtect. Authentication environment
  overrides are rejected; Claude guard supports only a verified, stored, unmanaged
  individual Claude Max credential. Credentials are never serialized into process
  arguments or temporary settings.
- Guard dashboards now fall back to a free loopback port when the preferred port
  is occupied and print the exact URL, instead of silently leaving users on a
  stale dashboard from another process.
- Claude guard removes inherited HTTP proxy routes, rejects detected managed or
  unsupported authentication profiles before bind, and scopes notices to the
  current guard session. A bounded process-local outcome ledger drives each
  value-free notice and degrades safely if a turn exceeds its metadata limits.
- Promtect no longer honors implicit system proxy variables for upstream traffic;
  gateways remain available through the explicit upstream/chaining configuration.
- Guarded tools now run inside an owned Unix process group with terminal job-control
  handoff. Normal exit and SIGINT/SIGTERM clean up helpers, restore the terminal,
  and drain proxy/dashboard connections; cancelled downstream response streams
  emit a value-free, audit-only `stream_cancelled` event.
- Concurrent guards serialize audit tail repair and complete JSONL appends through
  an owner-only pathname lock. Claude notices use a process-local outcome ledger,
  so same-inode copy-truncation cannot hide a protected turn.
- Named Claude guard is pinned to the reviewed Claude Code 2.1.209 contract. It
  rejects hidden managed settings, cloud/root commands, safe mode, alternate
  managed/remote settings sources, and persisted proxy routes before a prompt.

## [0.1.7]

### Security
- Updated `quinn-proto` 0.11.14 → 0.11.15 to address RUSTSEC-2026-0185.

### Added
- Integration guides for agent harnesses (OpenCode, Crush, Goose, Pi), Hermes
  Agent, OpenClaw (self-hosted gateway), and NanoClaw (Agents SDK / containers).
- `guard` now warns when a stale base-URL environment variable from a previous
  run is still set, so a tool's requests cannot silently bypass the proxy (#33).

### Fixed
- Release workflow cross-compilation: pinned the dtolnay toolchain to the
  channel declared in `rust-toolchain.toml`.

## [0.1.2]

### Security
- Audit log is created owner-only (`0600`) so other local users cannot read it.

### Changed
- Pinned the Rust toolchain for deterministic CI builds.
- Added a pre-commit hook that auto-bumps the patch version on code commits.
- Bumped `actions/checkout` to v7 (Node 24).

## [0.1.1]

### Added
- Provider-risk awareness and a published threat model, including recognition of
  Chinese coding models (Kimi, GLM) and the China-jurisdiction risk framing.
- `playground` subcommand and a detector reference doc.
- A detection benchmark.

### Fixed
- Closed `.env` secret-detection leak edges around `,`, `}`, and `()` in values.
- Hardened the proxy: upstream connect timeout, opaque 502 on failure, verbatim
  stream tail, and no panic in `guard`.

## [0.1.0]

First public release, renamed from Airlock to Promtect and relicensed Apache-2.0.

### Added
- Local masking proxy with streamed SSE responses and a restore toggle
  (`PROMTECT_RESTORE`); strict mode keeps secrets masked end to end.
- 71 known-format detectors with a false-positive gate.
- `promtect guard <tool>` for one-command protected sessions, and
  `promtect mask` to preview what would be masked.
- Multi-tool upstream modes and chaining (`PROMTECT_MODE`, `PROMTECT_UPSTREAM`).
- Value-free audit log, metrics aggregator (JSON + Prometheus), and an offline
  dashboard (`dashboard` subcommand).
- Body-size cap, binary content-type guard, and SHA-pinned CI.

[Unreleased]: https://github.com/amitk3293/promtect/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/amitk3293/promtect/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/amitk3293/promtect/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/amitk3293/promtect/releases/tag/v0.1.0
