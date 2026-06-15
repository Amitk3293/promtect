# Contributing to Promtect

Thank you for helping keep secrets out of AI tools. The highest-leverage
contribution is **adding a detector** — every new credential format Promtect
recognises protects more developers.

## Add a detector in ~20 minutes

Detectors live in [`src/detect.rs`](src/detect.rs) in a single `DETECTORS`
registry. Two helpers build an entry:

- `d("kind", r"regex")` — a **token-shaped** secret (the whole match is the
  secret, e.g. a prefixed API key).
- `dg("kind", r"regex", group, guard)` — a **context-keyed** secret where capture
  `group` is the value (e.g. `PASSWORD=<value>`). Set `guard = true` to apply the
  placeholder/code-expression filter.

### Steps

1. **Find the token format.** Check the provider's docs for the exact prefix and
   length (e.g. Groq keys are `gsk_` + 40+ alphanumerics).
2. **Write the regex.** Anchor it with a distinct prefix and `\b` boundaries so it
   won't fire on prose. Test it on [regex101.com](https://regex101.com) (Rust
   flavour). Avoid unbounded nested quantifiers (ReDoS).
3. **Add one line** to the `DETECTORS` vec, grouped under the right category
   comment:
   ```rust
   d("groq_key", r"\bgsk_[A-Za-z0-9]{40,}\b"),
   ```
4. **Add tests.** In `src/detect.rs` tests, add your kind + a *synthetic* token to
   `detects_each_extended_kind`. Add at least one negative case to
   [`tests/false_positive.rs`](tests/false_positive.rs) if your pattern could
   plausibly misfire.
   > ⚠️ **Never commit a real secret.** Use structural fillers like
   > `"A".repeat(40)`. Synthetic only.
5. **Run the gate:**
   ```sh
   cargo test -- detect
   make lint        # fmt + clippy -D warnings
   ```
6. **Open a PR** using the "New detector" template.

## What belongs in the open-source core

All **known-format** credential/key/token detectors are free and OSS, forever.
Detectors that are a *different capability class* — entropy/unknown-format
detection, scanning the model's response, and PII/PHI/PCI compliance — are paid.
Please keep PRs to the known-format kind.

## Code standards

- No `unwrap()` / `expect()` in non-test request-path code — handle or propagate.
- Public items get rustdoc; comments explain *why*, not *what*.
- Every change must pass `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test`, and `cargo audit`.
- Match the style of the surrounding code.

## Reporting bugs / requesting features

Use the issue templates. For security vulnerabilities, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Contributor License Agreement

So that contributions can be included in both the open-source core and paid
Promtect builds, contributors are asked to agree to the project CLA (a bot will
prompt you on your first PR). You retain copyright to your contribution.

By contributing you agree your work is licensed under Apache-2.0.
