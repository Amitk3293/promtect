# Roadmap

Where Promtect is and where it's going. Dates are intentionally absent — this is
direction, not a delivery contract. Have a need that's not here? Open an issue.
Public availability is governed by [`PRODUCT-CONTRACT.json`](PRODUCT-CONTRACT.json).

## Principle

**The free core stays free.** Everything that ships in this repo — the proxy, the
96 known-format detector kinds, mask + restore, strict mode, the value-free audit log
and dashboard — is licensed under the Sustainable Use License (fair-code,
source-available), free to use, modify, and self-host, and always will be. Paid
work is a *different class*
of detection and team tooling built on top, never a paywall around what's here.

## Shipped (v0.1)

- Loopback masking proxy, no root CA, no telemetry.
- 96 known-format detector kinds ([detectors.md](docs/detectors.md)), backed by
  99 registry entries where some kinds use more than one bounded pattern.
- Mask outbound + streaming restore inbound; strict mode (`PROMTECT_RESTORE=false`).
- Per-request vault, zeroized memory, single-pass restore.
- Upstream risk classification + `PROMTECT_BLOCK_RISKY` fail-closed.
- Value-free audit log + offline dashboard.
- One-command `promtect guard <tool>`; Ollama is runtime-proven, while Claude,
  Codex, Cursor, OpenRouter, and chaining remain beta until their current client
  journeys pass the provider harness.
- Local + in-browser (WASM) playgrounds.

## Next (free core)

- **More integrations** — broaden the `guard` tool list and the integration guides.
- **More detectors** — keep pace with new provider key formats (community PRs welcome).
- **VS Code Copilot (M3)** — blocked on tools that expose no base-URL override and
  require a local CA. Tracked, deliberately not done yet — see
  [integrations/vscode-copilot.md](docs/integrations/vscode-copilot.md).

## Paid extensions (open-core, separate)

Promtect follows a source-available core model: the core is free; commercial extensions
target needs that don't belong in a local single-user tool. These are **not** in
this repo and don't phone home from it. Current product state:

- **Pro beta** — entropy, PII/PHI/payment, Skills/MCP static scan, and response
  scanning are implemented but not generally available.
- **Team planned** — shared policy, rulebooks, roles, seats, and SIEM have beta
  components but no launch-ready operational product.
- **Enterprise planned** — offline licensing has beta components. SSO/SAML,
  fleet UI, central audit, air-gap distribution, compliance mapping, and a
  contractual SLA are not shipped.

If one of these is the only thing standing between you and adopting Promtect,
say so in an issue — it helps prioritize.
