# OpenAI Codex CLI

Codex talks the OpenAI API. Run Promtect in `openai` mode and set Codex's base
URL to Promtect.

## Quickest: one command

```sh
promtect guard codex                       # starts the proxy, runs Codex, masks + restores
```

`guard codex` requires API-key authentication through `OPENAI_API_KEY`,
`CODEX_API_KEY`, or a key stored by `codex login --with-api-key`. It rejects
ChatGPT subscription authentication, all runtime `-c`/`--config` and feature
overrides, remote/cloud/server modes, OpenRouter, and local-provider selection
before starting the protected session. Those modes cannot currently satisfy the
fail-closed routing contract. Use normal flags such as `--model` for supported
options. Guard supports the interactive CLI plus the `exec`/`e` and `review`
root commands. Multi-word positional prompts remain supported, but use
`exec <prompt>` for a single-token prompt; unknown root commands and ambiguous
variadic image arguments fail closed. `--help` and `--version` remain local dry
runs and do not require provider authentication. The protected route uses HTTP
Responses transport with WebSockets, automatic provider retries, request
compression, and child-side external proxy variables disabled, so each model
call has one observable upstream attempt.

The rest of this guide is the manual method.

## Start Promtect

```sh
PROMTECT_MODE=openai promtect        # listens on 127.0.0.1:8790
```

## Point Codex at it

```sh
OPENAI_BASE_URL=http://127.0.0.1:8790/v1 codex "add tests for the parser"
```

This manual environment-variable method is not fail closed: a custom Codex
provider can override it. Prefer `promtect guard codex` for supported API-key
sessions.

Your real `OPENAI_API_KEY` is forwarded untouched; only the request body is
masked.

## Notes

- Promtect forwards the full path verbatim
  (`/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Strict mode (`PROMTECT_RESTORE=false`) leaves placeholders in the response.
