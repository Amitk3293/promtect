# Chaining Promtect with other proxies

Promtect only masks and restores — it does not care what the upstream does.
Point `PROMTECT_UPSTREAM` at another proxy and Promtect becomes the **first**
hop, so secrets are masked before anything else (token compressor, router,
corporate proxy) ever sees the request.

**Rule:** Promtect must be first in the chain (closest to your tool). It sees
plaintext, masks it, then forwards the clean request onward.

```
your AI tool ──▶ Promtect (mask) ──▶ <other proxy> ──▶ LLM
                         ◀── restore ──┘
```

## Promtect → Headroom (token compression) → Anthropic

```sh
# Headroom on 127.0.0.1:8788; Promtect in front on 18787
PROMTECT_PORT=18787 PROMTECT_UPSTREAM=http://127.0.0.1:8788 promtect &
ANTHROPIC_BASE_URL=http://127.0.0.1:18787 claude "refactor my S3 code"
```

Secrets are masked before Headroom; Headroom compresses an already-clean
context; Promtect restores the real values in the final response.

## Promtect → LiteLLM gateway → many models

```sh
PROMTECT_UPSTREAM=http://localhost:4000 promtect
# point your OpenAI-compatible client at http://127.0.0.1:8790
```

## Promtect → corporate HTTP proxy → Anthropic

```sh
PROMTECT_UPSTREAM=https://api.anthropic.com HTTPS_PROXY=http://corp-proxy:8080 promtect
```

`reqwest` honours `HTTPS_PROXY` for the upstream connection, so the masked
request egresses through your corporate proxy.

## Notes

- `PROMTECT_UPSTREAM` always wins over `PROMTECT_MODE`.
- Trailing slashes are trimmed; Promtect appends your tool's full request path.
