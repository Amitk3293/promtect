# Integrations

Mask every secret before it reaches the model. Promtect runs as a local proxy:
start it, point your AI tool's base URL at it, and each API key, token, and
password in your requests is masked before it leaves your machine — then restored
in the reply, or kept masked in strict mode. Pick your tool below.

| Tool | Guide | Mode |
|------|-------|------|
| Claude Code | [claude-code.md](claude-code.md) | `anthropic` (default) |
| Cursor | [cursor.md](cursor.md) | `openai` |
| OpenAI Codex CLI | [codex.md](codex.md) | `openai` |
| Ollama (local models) | [ollama.md](ollama.md) | `ollama` |
| OpenRouter | [openrouter.md](openrouter.md) | `openrouter` |
| Agent harnesses (OpenCode, Crush, Goose, Pi, Hermes) | [harnesses.md](harnesses.md) | `anthropic` / `openai` |
| Aider (`guard aider`) | [harnesses.md](harnesses.md#aider) | `openai` |
| OpenClaw (self-hosted gateway) | [openclaw.md](openclaw.md) | `anthropic` / `openai` |
| NanoClaw (Agents SDK / containers) | [nanoclaw.md](nanoclaw.md) | `anthropic` |
| Chaining (Headroom / LiteLLM / corp proxy) | [chaining.md](chaining.md) | any + `PROMTECT_UPSTREAM` |
| VS Code Copilot | [vscode-copilot.md](vscode-copilot.md) | not yet (needs CA) |

Not listed? **Any** tool that lets you override its model-provider base URL works
the same way: point it at `http://127.0.0.1:8787` and run `promtect` in the
matching mode. See [harnesses.md](harnesses.md) for the pattern.

## How upstream selection works

- `PROMTECT_MODE` picks a known provider: `anthropic` (default), `openai`,
  `ollama`, `openrouter`.
- `PROMTECT_UPSTREAM` overrides the mode with any URL — this is the **chaining
  knob** (put Promtect in front of another proxy). It always wins.

Upstreams are origins only (scheme + host). Promtect forwards your tool's full
request path verbatim, so you point your tool's base URL — including any `/v1`
segment it expects — at Promtect.

## One mode per process

Each Promtect instance talks to one upstream. To protect two tools that use
different providers, run two instances on different ports:

```sh
PROMTECT_PORT=8787 PROMTECT_MODE=anthropic promtect &
PROMTECT_PORT=8788 PROMTECT_MODE=openai    promtect &
```

## Common environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROMTECT_PORT` | `8787` | Port Promtect listens on (loopback). |
| `PROMTECT_MODE` | `anthropic` | Upstream provider preset. |
| `PROMTECT_UPSTREAM` | — | Explicit upstream URL; overrides mode (chaining). |
| `PROMTECT_RESTORE` | `true` | `false` = strict mode (never re-insert secrets). |
| `PROMTECT_AUDIT` | `promtect-audit.jsonl` | Value-free audit log path. |

Stuck? See the [FAQ & troubleshooting](../faq.md). Want the full list of what's
masked? See the [detector reference](../detectors.md).
