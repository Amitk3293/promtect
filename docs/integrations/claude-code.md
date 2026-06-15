# Claude Code

Promtect's default mode. Claude Code talks the Anthropic API.

## Start Promtect

```sh
promtect          # mode defaults to anthropic, listens on 127.0.0.1:8787
```

## Point Claude Code at it

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude "refactor my S3 upload function"
```

Or export it for the session:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

That's it. Secrets in your prompts and files are masked before they reach
Anthropic and restored in the response, so Claude's answers still use your real
values.

## Verify it works (no network needed)

```sh
promtect selftest        # → promtect selftest: PASS — no leak
```

## Notes

- Pass your real Anthropic API key as usual (`ANTHROPIC_API_KEY` / `x-api-key`).
  Promtect forwards the auth header untouched — it only ever masks the body.
- Strict mode: `PROMTECT_RESTORE=false` leaves placeholders in the response (the
  secret is never re-inserted). Use it when policy forbids restoration.
