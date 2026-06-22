# OpenClaw

OpenClaw is a self-hosted agent gateway, not a one-shot CLI, so you set the base
URL once in its config and run Promtect alongside the gateway as a long-lived
service.

OpenClaw configures providers under `models.providers.<id>` with a `baseUrl` and
an `api` type (no base-URL env var). For Claude models:

```json5
{
  models: {
    providers: {
      promtect: {
        baseUrl: "http://127.0.0.1:8787",
        apiKey: "${ANTHROPIC_API_KEY}",
        api: "anthropic-messages",
        models: [{ id: "claude-opus-4-8", name: "Opus 4.8 (via Promtect)" }],
      },
    },
  },
}
```

For an OpenAI-compatible provider use `api: "openai-completions"` and
`baseUrl: "http://127.0.0.1:8787/v1"`.

Start Promtect in the matching mode and keep it running:

```sh
promtect &                       # anthropic mode (default)
# or: PROMTECT_MODE=openai promtect &
```

## Notes

- For Anthropic-compatible **non-direct** endpoints (host is not the public
  `api.anthropic.com`), OpenClaw suppresses implicit beta headers. If you rely on
  one, re-add it with `models.providers.<id>.headers["anthropic-beta"]`.
- A custom provider needs a non-empty `models[]` array or OpenClaw skips it.
- Your real API key is forwarded untouched; only the request body is masked.
