# ADR-002: Open-Core Repository Architecture (OSS vs Paid)

- **Status:** Accepted
- **Date:** 2026-06-14
- **Deciders:** Owner (founder/eng)
- **Related:** ADR-001 (MCP server), product model memory `promtect-product-model`

## Context

Promtect is an open-core product: a free, open-source local proxy plus paid
Team/Business/Enterprise capabilities. Paid code must not live in the public
repository — both for commercial protection and because Promtect is a security
tool whose trust model depends on the public source being *the whole thing*
users actually run. Mixing proprietary code into the public repo would
undermine "read all the source and verify it yourself."

We must decide: how the two bodies of code are stored, licensed, and composed,
without (a) crippling the free product, (b) leaking paid code, or (c) creating
a brittle integration that forces forking.

## Decision

### Two repositories

1. **`promtect/promtect` — PUBLIC, Apache-2.0.**
   The complete free product: proxy, per-request zeroizing vault, span-based
   mask/restore (streaming), value-free audit, metrics, dashboard, and all
   known-format credential detectors (~70 at launch). It builds an excellent,
   fully-working product on its own — no artificial crippling.

2. **`promtect/promtect-pro` — PRIVATE, commercial license.**
   A Cargo workspace that depends on the public `promtect` crate at a pinned
   version/tag and adds proprietary crates:
   - `promtect-entropy` — generic/unknown-format secret detection
   - `promtect-compliance` — PII / PHI / PCI detection (HIPAA/GDPR gate)
   - `promtect-scan` — scans the LLM *response* for echoed/generated secrets
   - `promtect-fleet` — central policy server + enrolled-client management
   - `promtect-enterprise` — SSO, RBAC, SIEM, secret-rotation hooks
   It produces the `promtect-pro` binary, distributed as a closed, signed
   binary/container, gated by a license key + entitlement check.

### Composition via stable traits (build-time, not runtime)

The public core exposes a small, semver-stable extension surface:
- `trait Detector` — the existing `RegexDetector` generalizes to a trait; the
  registry accepts externally-registered detectors at startup.
- Future: `trait PolicyBackend`, `trait Scanner` (request/response hooks),
  `trait Sink` (audit/SIEM export).

`promtect-pro` implements these traits and registers them into the core
registry. Composition is **build-time** (the pro binary links the core +
pro crates). Rust has no stable ABI, so runtime dynamic plugins are
explicitly rejected as fragile.

### Hard rules

- **Dependency direction is one-way:** core never depends on pro; only pro
  depends on core. Enforced by the fact that core has no knowledge of pro.
- **No paid code, keys, or entitlement secrets in the public repo, ever.**
- Core CI runs `cargo-deny`/license checks so no copyleft-incompatible or
  proprietary dependency can sneak into the Apache-2.0 artifact.
- The pro binary is the only place license enforcement lives; the core never
  phones home and never checks a license (it is free).

### Licensing & contributions

- **Core: Apache-2.0** — permissive + patent grant. Maximizes adoption and is
  trivially vettable by enterprise legal (critical for a tool security teams
  must approve). For a local-first CLI, AGPL's SaaS-loophole protection buys
  little while adding adoption friction; BSL/source-available would break the
  community-contribution flywheel. (See the rejected alternatives.)
- **Pro: proprietary EULA**, private repo.
- **Contributions: CLA required** on the public repo so community contributions
  can be incorporated into pro builds. `Promtect` name/logo are trademarks,
  reserved separately from the code license.

## Why this protects revenue

The moat is **not** the license (Apache is permissive — a fork can take the
core). The moat is that the paid *capabilities* (compliance, fleet, entropy,
response-scanning), the brand, signed builds, update channel, and enterprise
relationships live in the private repo behind an entitlement server. A fork
cannot reproduce those, and the open core feeds rather than competes with the
paid funnel: developers adopt free → bring it to work → security teams see it →
buy enforcement + compliance.

## Migration

- The current repo (formerly `airlock`, now renamed to `promtect`) **becomes
  the public core**. It is private "during development" and goes public at the
  M1/OSS launch.
- `promtect-pro` is created empty now and scaffolded when the first paid
  feature begins (post-OSS-launch milestone). Everything built in the current
  OSS milestone is core/public.
- To avoid a painful later untangle, the trait extension surface, `LICENSE`,
  `NOTICE`, `CONTRIBUTING.md` + CLA, and this ADR are established now.

## Alternatives considered

- **Monorepo with `/pro` under a different license (Grafana-style).** Rejected:
  for a security tool, proprietary code sitting in the public tree erodes the
  "the source you read is the binary you run" trust that is the whole point.
- **Runtime dynamic plugins (.so/.dylib).** Rejected: Rust has no stable ABI;
  fragile across compiler versions, painful to support.
- **AGPL-3.0 core + commercial exception.** Rejected for now: Promtect is
  local-first, so the SaaS-reseller threat AGPL guards against is low, while
  AGPL deters some enterprises from even the free tier. Revisit only if a
  hosted reseller becomes a real threat.
- **BSL / source-available core.** Rejected: not true open source; kills the
  contribution + trust flywheel that drives adoption.

## Consequences

- Engineering discipline required: the core's public API must stay
  semver-stable so pro builds against it without forking. This is a real,
  ongoing cost — the trait surface must be designed deliberately and versioned.
- Two CI pipelines; pro pins core by tag and bumps deliberately.
- Clear, defensible story for users ("the free tool is 100% the public source")
  and for buyers ("paid = compliance + fleet you legally/operationally need").
