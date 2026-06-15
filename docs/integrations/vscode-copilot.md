# VS Code Copilot

**Status: not yet supported.**

GitHub Copilot in VS Code talks to `copilot.proxy.github.com` over TLS and does
not expose a base-URL override. Intercepting it requires a local root CA to
terminate TLS, which Promtect deliberately does not do today (the no-CA design
is a core trust property — Promtect makes zero changes to your system trust
store).

A local-CA mode is planned (milestone M3) and will be opt-in. Until then, use
Promtect with tools that support a base-URL override:

- [Claude Code](claude-code.md)
- [Cursor](cursor.md)
- [OpenAI Codex CLI](codex.md)
- [Ollama](ollama.md)
- [OpenRouter](openrouter.md)

If Copilot support matters to you, please open or +1 an issue so we can
prioritise the opt-in CA work.
