# Cursor

Cursor uses the OpenAI-compatible API. Run Promtect in `openai` mode and set
Cursor's OpenAI base URL to Promtect.

## Start Promtect

```sh
PROMTECT_MODE=openai promtect        # listens on 127.0.0.1:8787
```

## Point Cursor at it

In Cursor: **Settings → Models → OpenAI API Key → Override Base URL** (the exact
label varies by version), set the base URL to:

```
http://127.0.0.1:8787/v1
```

Enter your real OpenAI API key in Cursor as usual — Promtect forwards it
untouched and only masks the request body.

## Notes

- Promtect is path-transparent: Cursor sends `/v1/chat/completions`, which
  Promtect forwards to `https://api.openai.com/v1/chat/completions`.
- If Cursor sends a non-text body (e.g. an image), Promtect forwards it
  unscanned so it is never corrupted.
- To protect both Cursor (OpenAI) and Claude Code (Anthropic) at once, run two
  Promtect instances on different ports — see [README.md](README.md).
