# Agent harnesses (OpenCode, Crush, Goose, Pi, Hermes, Aider)

The 2026 wave of terminal coding agents are all **model-agnostic**: you pick the
provider and, crucially, you can point that provider's **base URL** at anything.
That is all Promtect needs.

The universal rule:

> Set the harness's model-provider base URL to `http://127.0.0.1:8787` and run
> `promtect` in the matching mode. Promtect forwards the full request path
> verbatim, so it works for every harness below without any per-tool code.

Pick the provider type the harness is using and match `PROMTECT_MODE`:

- Anthropic / Claude models → `PROMTECT_MODE=anthropic promtect` (the default),
  base URL `http://127.0.0.1:8787`.
- OpenAI-compatible models → `PROMTECT_MODE=openai promtect`, base URL
  `http://127.0.0.1:8787/v1`.

Each harness stores this differently. The verified knob for each is below.

---

## OpenCode

OpenCode reads its config from `opencode.json` (project or `~/.config/opencode/`).
Override just the provider's `baseURL` — configs merge, so you do not redefine
your models:

```jsonc
// opencode.json  — Claude models
{
  "$schema": "https://opencode.ai/config.json",
  "provider": { "anthropic": { "options": { "baseURL": "http://127.0.0.1:8787/v1" } } }
}
```

For an OpenAI-compatible provider use the same shape with `"baseURL":
"http://127.0.0.1:8787/v1"` and run Promtect in `openai` mode.

```sh
promtect            # anthropic mode (default); openai needs PROMTECT_MODE=openai
opencode
```

> Config precedence: a **project** `opencode.json` overrides a custom config
> passed via `OPENCODE_CONFIG`. Put the `baseURL` in the config OpenCode actually
> loads for the project, or you will silently bypass the proxy.

---

## Crush

Crush reads `crush.json`. A custom provider needs `type`, `base_url`, an
`api_key`, and a non-empty `models` array (custom providers are skipped without
it). The OpenAI-compatible path is the simplest:

```json
{
  "providers": {
    "promtect": {
      "type": "openai-compat",
      "base_url": "http://127.0.0.1:8787/v1",
      "api_key": "$OPENAI_API_KEY",
      "models": [{ "id": "gpt-5.5", "name": "GPT-5.5 (via Promtect)" }]
    }
  },
  "models": { "large": { "model": "gpt-5.5", "provider": "promtect" } }
}
```

Run `PROMTECT_MODE=openai promtect`. For Claude models use `"type": "anthropic"`
with `"base_url": "http://127.0.0.1:8787"` and the default `anthropic` mode.

---

## Goose

Run `goose configure`, choose the **OpenAI** provider, and set the host to
Promtect:

```sh
OPENAI_HOST=http://127.0.0.1:8787      # base path: v1/chat/completions
PROMTECT_MODE=openai promtect
goose
```

For services that aren't built in, Goose custom providers live in
`~/.config/goose/custom_providers/*.json` with a `host` field — set it to
`http://127.0.0.1:8787/v1` and `"engine": "openai"`.

---

## Pi

Pi reads `~/.pi/agent/models.json`. Point the provider's `baseUrl` at Promtect:

```json
{
  "providers": {
    "anthropic": {
      "baseUrl": "http://127.0.0.1:8787",
      "apiKey": "${ANTHROPIC_API_KEY}",
      "api": "anthropic-messages",
      "models": [{ "id": "claude-opus-4-8", "name": "Opus 4.8 (via Promtect)" }]
    }
  }
}
```

Run `promtect` (anthropic mode is the default), then `pi`.

---

## Hermes

Hermes (Nous Research) reads its provider config from `config.yaml`. For a custom
OpenAI-compatible endpoint, set `provider: custom` and point `base_url` at Promtect:

```yaml
# config.yaml
model:
  default: <your-model-id>
  provider: custom
  base_url: http://127.0.0.1:8787/v1
```

```sh
PROMTECT_MODE=openai promtect
hermes
```

For an Anthropic-style endpoint, use `base_url: http://127.0.0.1:8787` and the
default `anthropic` mode. Set keys with `hermes config set`, or edit `config.yaml`
directly.

> **Hermes runs side tasks too.** The `auxiliary` config section (vision,
> embeddings, title generation) can pin its own `provider`/`base_url`. If it points
> elsewhere, that traffic **bypasses Promtect**. Point it at the proxy as well, or
> leave it unset so it inherits the masked `model:` endpoint.

---

## Aider

Aider has a one-command `guard` wrapper (it reads `OPENAI_API_BASE`):

```sh
promtect guard aider --model openai/gpt-5.5     # starts the proxy, runs Aider, masks + restores
```

Manual:

```sh
PROMTECT_MODE=openai promtect
OPENAI_API_BASE=http://127.0.0.1:8787/v1 aider --model openai/gpt-5.5
```

Your real API key is forwarded untouched; only the request body is masked.

> **Aider is multi-provider.** `guard aider` only routes its **OpenAI-compatible**
> traffic (`OPENAI_API_BASE`). If you select an Anthropic, Gemini, or other model,
> aider talks to that provider directly and **bypasses Promtect** — your prompt is
> not masked. Use an `openai/<model>` model, or run a second Promtect in the
> matching mode and set that provider's base URL too.

---

## Verify any of them

```sh
promtect selftest        # → promtect selftest: PASS — no leak
```

Then run a real prompt and check the audit log (`promtect-audit.jsonl`) shows
traffic. If the proxy sees **zero** requests, the harness bypassed it — re-check
the base URL it actually loaded. See the [FAQ](../faq.md) if stuck.
