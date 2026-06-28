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
- `db_password` now also matches `clickhouse://` and `cockroachdb://` connection URLs.
- `PROMTECT_OUTPUT_SCAN` environment variable: gates the Pro response output scan.
  Default-on when a scanner is present; a falsey value (`0`/`false`/`no`/`off`)
  disables it. No-op in the core, which ships no scanner.

### Changed
- **Relicensed the core from Apache-2.0 to the Sustainable Use License (SUL v1.0)**,
  a fair-code, source-available license. Free for internal business, personal, and
  non-commercial use; no reselling or paid redistribution. Past Apache-2.0 releases
  (≤ v0.1.23) remain Apache-2.0. Licensor is AK DevOps Solutions SL. See `LICENSE`,
  `NOTICE`, `COMMERCIAL.md`, and `TRADEMARK.md`.

### Fixed
- `promtect --version`, `promtect -V`, and `promtect version` now print the version
  and exit, instead of starting the proxy.

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
