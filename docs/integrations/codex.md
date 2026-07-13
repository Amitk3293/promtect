# OpenAI Codex CLI

Codex talks the OpenAI API. Run Promtect in `openai` mode and set Codex's base
URL to Promtect.

## Quickest: one command

```sh
promtect guard codex                       # starts the proxy, runs Codex, masks + restores
```

`guard codex` requires OpenAI API-key authentication. It rejects ChatGPT
subscription authentication, custom provider/routing overrides, OpenRouter, and
request-compression overrides before starting the protected session. Those modes
cannot currently satisfy the fail-closed routing contract. The protected route
uses HTTP Responses transport with WebSockets and automatic provider retries
disabled, so each model call has one observable upstream attempt.

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
