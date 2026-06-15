# Ollama (local models)

Running local models — including Chinese or uncensored models like DeepSeek,
Qwen, or Mistral derivatives — is exactly when a secret seatbelt matters: these
models often have no privacy guarantees, and you may be running an unfamiliar
build. Promtect masks secrets before *any* model sees them, local or not.

## Quickest: one command

```sh
promtect guard ollama run deepseek-r1      # proxy sits between the ollama CLI and the local server
```

`guard ollama` sets `OLLAMA_HOST` to the proxy and forwards to your local Ollama
server (`http://127.0.0.1:11434`), masking prompts on the way. (Headroom doesn't
compress native Ollama traffic, so `--headroom` is a no-op here.)

The rest of this guide is the manual method / the OpenAI-compatible endpoint.

---

Ollama exposes an OpenAI-compatible endpoint at `http://localhost:11434/v1`.

## Start Promtect

```sh
PROMTECT_MODE=ollama promtect        # upstream = http://localhost:11434
```

## Point your client at Promtect

Any OpenAI-compatible client or SDK:

```sh
OPENAI_BASE_URL=http://127.0.0.1:8787/v1 your-tool ...
```

Or curl directly:

```sh
curl http://127.0.0.1:8787/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"deepseek-r1","messages":[{"role":"user","content":"explain my .env"}]}'
```

## Notes

- Ollama needs no API key; Promtect simply forwards to the local Ollama port.
- Even though the model is local, masking still protects against the model (or a
  future remote backend) ever seeing the raw secret, and produces an audit log.
