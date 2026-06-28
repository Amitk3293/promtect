# Roadmap

Where Promtect is and where it's going. Dates are intentionally absent — this is
direction, not a delivery contract. Have a need that's not here? Open an issue.

## Principle

**The free core stays free.** Everything that ships in this repo — the proxy, the
96 known-format detectors, mask + restore, strict mode, the value-free audit log
and dashboard — is licensed under the Sustainable Use License (fair-code,
source-available), free to use, modify, and self-host, and always will be. Paid
work is a *different class*
of detection and team tooling built on top, never a paywall around what's here.

## Shipped (v0.1)

- Loopback masking proxy, no root CA, no telemetry.
- 96 known-format detectors ([detectors.md](docs/detectors.md)).
- Mask outbound + streaming restore inbound; strict mode (`PROMTECT_RESTORE=false`).
- Per-request vault, zeroized memory, single-pass restore.
- Upstream risk classification + `PROMTECT_BLOCK_RISKY` fail-closed.
- Value-free audit log + offline dashboard.
- One-command `promtect guard <tool>`; integrations for Claude Code, Cursor,
  Codex, Ollama, OpenRouter, and chaining.
- Local + in-browser (WASM) playgrounds.

## Next (free core)

- **More integrations** — broaden the `guard` tool list and the integration guides.
- **More detectors** — keep pace with new provider key formats (community PRs welcome).
- **VS Code Copilot (M3)** — blocked on tools that expose no base-URL override and
  require a local CA. Tracked, deliberately not done yet — see
  [integrations/vscode-copilot.md](docs/integrations/vscode-copilot.md).

## Paid extensions (open-core, separate)

Promtect follows an open-core model: the core is free; a few commercial extensions
target needs that don't belong in a local single-user tool. These are **not** in
this repo and don't phone home from it. Planned tiers:

- **Entropy detection** — catch unknown-format / high-entropy secrets the
  known-format detectors can't shape-match.
- **Compliance (PII / PHI / PCI)** — detection classes for regulated data
  (HIPAA / GDPR / PCI), beyond credentials.
- **Response scanning** — flag secrets the model *echoes or generates* in its
  reply (the core only restores what it masked outbound).
- **Fleet** — central policy and client management for teams.
- **Enterprise** — SSO, RBAC, SIEM export, rotation hooks.

If one of these is the only thing standing between you and adopting Promtect,
say so in an issue — it helps prioritize.
