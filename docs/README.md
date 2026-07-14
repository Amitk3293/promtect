# Promtect documentation

Promtect is a local proxy that masks recognized matches in supported AI-tool
request bodies before the remaining prompt goes upstream, then restores an
unchanged sentinel in the reply. It installs no root CA and Core contains no
Promtect telemetry or hosted control-plane dependency. Start here.

## Getting started

- **[Main README](../README.md)** — what Promtect is, install, and the 30-second quickstart.
- **[FAQ & troubleshooting](faq.md)** — offline tests, base URLs, modes, and what it does not catch.

## Integrations

- **[Integrations index](integrations/README.md)** — pick your tool and point its base URL at Promtect.
- Per-tool guides: [Claude Code](integrations/claude-code.md) · [Cursor](integrations/cursor.md) · [Codex](integrations/codex.md) · [Ollama](integrations/ollama.md) · [OpenRouter](integrations/openrouter.md) · [Agent harnesses](integrations/harnesses.md) · [OpenClaw](integrations/openclaw.md) · [NanoClaw](integrations/nanoclaw.md) · [Chaining](integrations/chaining.md) · [VS Code Copilot](integrations/vscode-copilot.md)

## Reference

- **[Detector reference](detectors.md)** — every detector, by provider, with the current count.
- **[Architecture](architecture.md)** — the per-request mask, forward, and restore pipeline.
- **[Threat model](../THREAT-MODEL.md)** — what Promtect protects, and what it does not.

## Pro & commercial

- **[Pro overview](pro.md)** — the paid detection layer and how it composes with the free core.
- **[Pricing & editions](../COMMERCIAL.md)** — Free, Pro, Team, Enterprise.
- **[Canonical product contract](product-contract.md)** — versioned prices,
  availability states, terminology, and bounded claims.

## Project

- **[Roadmap](../ROADMAP.md)** · **[Security policy](../SECURITY.md)** · **[Contributing](../CONTRIBUTING.md)** · **[Changelog](../CHANGELOG.md)**
