# OpenAI Codex CLI

Codex talks the OpenAI API. Run Promtect in `openai` mode and set Codex's base
URL to Promtect.

## Quickest: one command

```sh
promtect guard codex "fix the s3 upload"   # starts the proxy, runs Codex, masks + restores
promtect guard codex --openrouter          # route Codex to OpenRouter (see note below)
```

> `--openrouter`: Codex speaks the OpenAI **Responses** API; OpenRouter exposes
> **Chat Completions**. So you must also set `wire_api = "chat"` with a custom
> provider in `~/.codex/config.toml` for that combo. `guard` prints this reminder.

The rest of this guide is the manual method.

## Start Promtect

```sh
PROMTECT_MODE=openai promtect        # listens on 127.0.0.1:8790
```

## Point Codex at it

```sh
OPENAI_BASE_URL=http://127.0.0.1:8790/v1 codex "add tests for the parser"
```

Your real `OPENAI_API_KEY` is forwarded untouched; only the request body is
masked.

## Notes

- Promtect forwards the full path verbatim
  (`/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Strict mode (`PROMTECT_RESTORE=false`) leaves placeholders in the response.
