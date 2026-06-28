# Promtect Pro

The free core in this repo masks known secret formats before your AI coding
tool sends them upstream. That is the floor. Most secrets that leak are not a
named token format, and the request body is not the only surface worth watching.
Pro is the backstop for the rest: it adds detector classes the core cannot
shape-match, scans the Skills your agent loads, and checks what the model sends
back. It runs the same way the core does, locally, no cloud, no CA, no
phone-home.

This doc is what Pro is and how it works. For pricing and tiers, see
[COMMERCIAL.md](../COMMERCIAL.md).

## What Pro adds

Pro layers extra detection passes on top of the core's `detect()`. The free
detectors keep running unchanged; Pro adds:

- **Entropy / unknown-format secrets.** A Shannon-entropy pass catches
  high-randomness strings that no signature names: homegrown key formats,
  rotated tokens, base64 blobs. It is guarded by length and shape checks so a
  long English sentence or a git SHA does not read as a secret. This is the
  catch for the credential you invented in-house that GitGuardian never heard of.
- **Personal and payment data.** Email addresses, phone numbers, credit card
  numbers (Luhn-validated, so a random 16-digit string is not flagged), bank
  account numbers (IBAN, checksum-validated), individual and employer tax IDs
  (ITIN and EIN), and US Social Security numbers (range-guarded against impossible
  groups). This is the data that turns one leak into a GDPR or HIPAA problem, not
  only API keys.
- **Heuristic Skills scanner.** `promtect-pro skills scan <path>` walks
  `SKILL.md` files and flags three things: instruction-injection patterns,
  secret-exfiltration shapes (`curl`, `scp`, `nc`, piping `$VAR` to a remote),
  and dangerous commands. It also records a sha256 of each scanned file so a
  later silent override of a Skill you already trusted shows up as a changed
  hash. This is the newest attack surface in AI tooling and a known-secret
  scanner is blind to it. Be clear on what v1 is: it is heuristic. It catches
  known patterns. An empty result is not proof a Skill is safe, only that none
  of the patterns it knows fired.
- **LLM response scanning (regex v1).** The core only restores what it masked on
  the way out. Pro additionally scans the model's reply for secrets it echoes or
  generates. v1 is regex-based, the same family of signatures as the core, run
  over the inbound stream.

## How composition works

Pro does not replace the core, it wraps it. On each request Pro runs the core
`detect()` and then its own passes (entropy, personal data, response scan), then
merges the results into one match list. That merged list goes through the
**same** pipeline the core already proves correct: the per-request vault, the
end-to-start masking, the streaming restore, and the value-free audit log.

The consequence that matters: a masked email or card number restores in the
reply exactly the way a masked API key does, so the model still gets a usable
answer instead of `[REDACTED]` noise. And because the merged list flows through
the existing audit path, the dashboard and the JSONL log already show the Pro
detector kinds (`entropy`, `pii`, `pci`) next to the core ones, with no secret values
written, no new logging path to trust.

Everything stays local. Same loopback proxy, no root CA, no TLS interception, no
telemetry. Pro changes what gets detected, not where your data goes. The Skills
scanner is a separate offline command and never touches the network.

## Activating Pro

Pro is a closed, license-gated binary, distinct from the source-available core.
It is **fail-closed**: without a valid license the Pro detectors stay off and
the binary falls back to plain core masking. You are never left with detection
silently disabled and no masking at all; the worst case without a license is the
free behavior.

The license is verified **offline**. There is no phone-home, no license server
call, no usage beacon. The check happens on your machine, same trust model as
everything else here.

## Deployment

Same shape as the core, the command is `promtect-pro`:

```
promtect-pro                       # start the proxy (core + Pro detectors when licensed)
ANTHROPIC_BASE_URL=http://127.0.0.1:8790 claude  # point your tool at it
echo "email me at a@b.com" | promtect-pro mask   # mask stdin, see what Pro would catch
promtect-pro skills scan ./skills  # scan SKILL.md / MCP config files for injection / exfil
```

Strict mode still applies (`PROMTECT_RESTORE=false` keeps everything masked,
including Pro-detected personal data). The proxy, dashboard, and audit log behave as
documented in [architecture.md](architecture.md); Pro only adds detector kinds
to the same flow.

## What Pro does not do yet

Honesty over polish, so you can decide with eyes open:

- **The Skills scanner is heuristic.** It matches known injection, exfil, and
  dangerous-command patterns and hash-pins files. It does not understand intent,
  and a clean scan is not a safety guarantee. Treat it as a tripwire, not a
  proof.
- **Response scanning is regex v1.** It catches signature-shaped secrets in the
  reply. It is not entropy-aware or personal-data-aware on the inbound side yet.
- **No fleet, no central plane.** Shared policy across a team, central audit,
  SSO, RBAC, and SIEM export are Team and Enterprise work, not in this binary.
  See [COMMERCIAL.md](../COMMERCIAL.md) and [ROADMAP.md](../ROADMAP.md).

Pro is a backstop. It widens what Promtect catches before your code leaves the
machine. It does not replace reviewing the Skills you install or rotating a key
you suspect leaked. Use it as the layer that catches what slips past your own
vigilance, not as permission to stop being careful.
