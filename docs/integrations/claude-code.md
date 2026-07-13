# Claude Code

Promtect's default mode. Claude Code talks the Anthropic API.

## Quickest: one command

```sh
promtect guard claude              # first-party individual Max; masks + restores
promtect guard claude --headroom   # also chain Headroom for token compression
```

That's it. The rest of this guide is the manual method (run the proxy yourself).

## Start Promtect (manual)

```sh
promtect          # mode defaults to anthropic, listens on 127.0.0.1:8790
```

## Point Claude Code at it

```sh
ANTHROPIC_BASE_URL=http://127.0.0.1:8790 claude "refactor my S3 upload function"
```

Or export it for the session:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8790
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

- `guard claude` currently supports a verified first-party, individual Claude
  Max profile on the reviewed Claude Code 2.1.207 CLI contract only. It refuses
  unreviewed CLI versions, API-key, Pro, Team, Enterprise, gateway, remote,
  MDM, registry, file-based, drop-in, or unknown profiles before binding because
  Claude's managed settings outrank command-line routing and hooks. API-key users
  can still use the manual proxy method above, without the automatic in-session
  notice. Other unmanaged individual tiers will be added only after their exact
  machine-readable auth contract is verified.
- The manual proxy supports API-key authentication as usual (`ANTHROPIC_API_KEY` /
  `x-api-key`) and forwards the auth header untouched. `guard claude` is narrower:
  it refuses environment authentication overrides and uses only the verified stored
  individual Max credential, so the launched session cannot silently switch tiers.
- `guard claude` removes inherited HTTP proxy variables from the Claude child so
  its loopback Promtect URL cannot be routed through another proxy first. Known
  endpoint- or server-managed settings are rejected before Claude starts;
  use the manual proxy or an unmanaged individual Max profile.
- Named guard accepts interactive Claude sessions, not Claude's separate root
  commands (`ultrareview`, `gateway`, `agents`, update/install, and similar).
  Those commands have independent network or lifecycle behavior that Promtect
  has not verified, so guard rejects them before binding or authentication.
- The unmanaged-profile check is a launch-time preflight, not an operating-system
  sandbox. Promtect cannot prevent a newly installed higher-precedence policy from
  changing a running Claude process; stop Claude and restart the guard before continuing.
- Promtect itself ignores implicit system proxy variables. Chain a trusted
  gateway explicitly with `--upstream` or `--headroom` so the destination is
  visible in the guard banner and risk classification.
- Strict mode: `PROMTECT_RESTORE=false` leaves placeholders in the response (the
  secret is never re-inserted). Use it when policy forbids restoration.
