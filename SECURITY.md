# Security Policy

Promtect is a security tool. We take vulnerabilities seriously and appreciate
responsible disclosure.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via either:

- GitHub Security Advisories — "Report a vulnerability" on the repository's
  **Security** tab (preferred), or
- email **security@promtect.org**.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof of concept if possible),
- affected version / commit,
- any suggested remediation.

## Our commitment

- We acknowledge your report within **48 hours**.
- We aim to ship a fix for confirmed **critical** issues within **7 days**, and
  to keep you updated on progress for lower-severity issues.
- We will credit you in the advisory unless you prefer to remain anonymous.

## Scope

In scope:

- Secret leakage (a detected secret reaching the upstream unmasked, or a
  sentinel failing to restore correctly).
- The audit log recording a real secret value.
- Memory-safety issues, or secrets not being zeroized.
- Proxy crashes / panics reachable from request input.
- Bypasses of the loopback/no-CA trust model.

Out of scope:

- Secrets in body types Promtect intentionally does not scan (binary/multipart) —
  this is documented behaviour; see the content-type guard.
- Findings that require a non-loopback bind the operator explicitly opted into.

## Supported versions

Promtect is pre-1.0. Security fixes target the latest `main`. Pin to a released
tag for production and watch releases for advisories.
