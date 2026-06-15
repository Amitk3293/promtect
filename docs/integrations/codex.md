# OpenAI Codex CLI

Codex talks the OpenAI API. Run Promtect in `openai` mode and set Codex's base
URL to Promtect.

## Start Promtect

```sh
PROMTECT_MODE=openai promtect        # listens on 127.0.0.1:8787
```

## Point Codex at it

```sh
OPENAI_BASE_URL=http://127.0.0.1:8787/v1 codex "add tests for the parser"
```

Your real `OPENAI_API_KEY` is forwarded untouched; only the request body is
masked.

## Notes

- Promtect forwards the full path verbatim
  (`/v1/chat/completions` → `https://api.openai.com/v1/chat/completions`).
- Strict mode (`PROMTECT_RESTORE=false`) leaves placeholders in the response.
