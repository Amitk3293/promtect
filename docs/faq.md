# FAQ & troubleshooting

Quick answers for getting Promtect working and proving it works. For the full
list of what's detected see [detectors.md](detectors.md); for scope and trust
assumptions see [THREAT-MODEL.md](../THREAT-MODEL.md).

## Getting started

### How do I try it without wiring up a real AI tool?

Three offline ways, fastest first:

```sh
promtect selftest                         # masks a canary, proves no leak, restores it
echo "ship it with $AWS_KEY" | promtect mask   # pipe any text, see what would be masked
promtect playground                       # full proxy round-trip vs a mock upstream, narrated
```

`promtect playground` starts the real proxy in front of a local mock, sends a
request carrying several **fake** secrets, and prints what your tool sent, what
the upstream actually received (masked — the proof), and the restored reply.
Nothing leaves your machine.

## "Is it actually masking?"

### I set the base URL but nothing seems masked

Check, in order:

1. **Is the tool pointed at Promtect?** The base URL must be
   `http://127.0.0.1:8790` (Claude) or `http://127.0.0.1:8790/v1` (OpenAI-style
   tools). Promtect logs `promtect listening on …` and the upstream at startup.
2. **Is the mode right for the tool?** Claude → default; Cursor/Codex →
   `PROMTECT_MODE=openai`; Ollama → `PROMTECT_MODE=ollama`. A mismatch forwards to
   the wrong upstream. See [integrations/](integrations/README.md).
3. **Is the secret a known format?** Promtect masks the known formats in
   [detectors.md](detectors.md). An unknown-format / high-entropy secret with no
   recognizable shape is **not** caught (that's a documented gap — see below).
4. **Is it a non-text body?** Binary, multipart, compressed, or base64 bodies are
   forwarded unscanned by design.

Confirm masking happened by watching the dashboard or the audit log:

```sh
promtect dashboard          # http://127.0.0.1:8799 — live per-detector counts
tail -f promtect-audit.jsonl   # one value-free line per mask/unmask
```

### Will I see the secret in the audit log?

No. The audit log records the detector kind, the **sentinel id**, action, and
timestamps — never the secret value. That's enforced by tests in `src/mask.rs`.

## Modes & configuration

### How do I keep secrets masked even in the response?

Run with `PROMTECT_RESTORE=false` (or `promtect guard <tool> --strict`). In strict
mode the secret is masked outbound and **never** re-inserted — it provably never
touches the response, logs, or terminal. Use it when usable answers matter less
than a hard guarantee the secret never comes back.

### Can I protect two tools at once (e.g. Claude *and* Cursor)?

Yes — one upstream per process, so run two instances on different ports:

```sh
PROMTECT_PORT=8790 PROMTECT_MODE=anthropic promtect &   # Claude → :8790
PROMTECT_PORT=8788 PROMTECT_MODE=openai    promtect &   # Cursor → :8788/v1
```

Point each tool at its own port.

### How do I refuse to send to risky providers?

`PROMTECT_BLOCK_RISKY=true` makes Promtect fail-closed: it refuses to proxy to
high-risk or unverified upstreams (DeepSeek, Kimi, GLM, or any host it can't
vouch for). Promtect prints a one-line risk note for the upstream at startup
regardless.

### Can I put Promtect in front of another proxy (Headroom, LiteLLM, a corp proxy)?

Yes. `PROMTECT_UPSTREAM=<their-url>` is the chaining knob and always wins over
`PROMTECT_MODE`. Promtect must come **first** (closest to the tool) so it masks
before anything else sees the body. See [integrations/chaining.md](integrations/chaining.md).

## Scope

### What does it *not* catch?

By design: unknown-format / high-entropy secrets with no recognizable shape; the
model's **response** (restore only re-inserts what Promtect masked on the way
out); binary / multipart / base64 / compressed bodies; and tools with no base-URL
override (VS Code Copilot, browser chat — these need a root CA, which Promtect
deliberately avoids). Full detail in [THREAT-MODEL.md](../THREAT-MODEL.md).

### A real secret got through — what now?

Treat it as sent: rotate it. Then check whether it was an unknown format (open an
issue or add a detector — [CONTRIBUTING.md](../CONTRIBUTING.md)) or a non-text
body (a documented gap). Either way, rotate first.

## Uninstall / cleanup

Stop the proxy and delete the binary (`brew uninstall promtect` for a Homebrew
install, or remove the local `cargo install` binary).
The only state Promtect writes is `promtect-audit.jsonl`
in the working directory — delete it if you don't want the value-free history.
No system trust store was modified (there's no CA), so there's nothing else to
undo.
