# OpenRouter

OpenRouter routes to 100+ models, many operated outside the US. Promtect masks
your secrets before they leave your machine, regardless of which model the
request is ultimately routed to.

OpenRouter's API lives at `https://openrouter.ai/api/v1`.

## Start Promtect

```sh
PROMTECT_MODE=openrouter promtect    # upstream = https://openrouter.ai
```

## Point your client at Promtect

Set your OpenAI-compatible client's base URL to Promtect, preserving the
`/api/v1` path OpenRouter uses:

```sh
OPENAI_BASE_URL=http://127.0.0.1:8790/api/v1 your-tool ...
```

Or curl:

```sh
curl http://127.0.0.1:8790/api/v1/chat/completions \
  -H "authorization: Bearer $OPENROUTER_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"model":"deepseek/deepseek-r1","messages":[{"role":"user","content":"review my config"}]}'
```

## Notes

- Your `OPENROUTER_API_KEY` is forwarded untouched (auth header is never masked).
- Promtect is path-transparent, so
  `/api/v1/chat/completions` → `https://openrouter.ai/api/v1/chat/completions`.
