# Architecture

A map of how a request flows through Promtect, for contributors and security
auditors. For *what* it protects and what it deliberately doesn't, read
[THREAT-MODEL.md](../THREAT-MODEL.md); this file is the *how*.

## The pipeline

```
 your tool                  Promtect (loopback)                   upstream API
 ─────────                  ───────────────────                   ────────────
 POST body  ──http──▶  detect ─▶ vault ─▶ mask_text  ──https──▶   (sees only
 (plaintext)               │        │         │                    sentinels)
                           │        │         │
                       71 regexes  secret↔   splice               response
                                   sentinel  sentinels                │
                                                                      ▼
 your tool  ◀──http──   StreamRestorer ◀── restore_scan ◀──http── streamed chunks
 (real values)          (chunk-safe)      (sentinel→secret)
```

Every box is one module. Each request gets its **own** `Vault`; nothing is shared
between requests, and nothing is written to disk except the value-free audit log.

## The modules

| Stage | Module | Entry point | Job |
|---|---|---|---|
| Request handler | `src/proxy.rs` | `handle()` (~`proxy.rs:161`) | Buffer body, mint vault, mask, forward, restore |
| Detect | `src/detect.rs` | `detect(text) -> Vec<Match>` | Run 71 regex detectors, de-overlap |
| Vault | `src/vault.rs` | `Vault::sentinel_for` / `secret_for` | Bidirectional secret↔sentinel map, zeroized on drop |
| Mask | `src/mask.rs` | `mask_text(...) -> String` | Splice each secret out for a sentinel |
| Restore (whole) | `src/mask.rs` | `restore_scan(...)` | Single-pass sentinel→secret |
| Restore (stream) | `src/stream.rs` | `StreamRestorer` | Restore across chunk boundaries |
| Audit | `src/audit.rs` | `Audit::record` | Append value-free JSONL |
| Upstream risk | `src/provider.rs` | `classify(url)` | Label upstream Low/Medium/High at startup |
| Dashboard | `src/dashboard.rs` | `app()` | Offline metrics UI over the audit log |

## Walkthrough of one request

1. **Buffer.** `handle()` reads the request body up to `PROMTECT_MAX_BODY_BYTES`
   (default 32 MiB) — over the cap returns `413`, never an OOM. A fresh
   `Arc<Vault>` is created for this request only.
2. **Detect.** If the body is UTF-8 text, `detect::detect` runs every detector in
   the `DETECTORS` registry and returns non-overlapping `Match` spans (byte
   offsets), sorted and de-overlapped by `dedupe_overlaps` so the same bytes are
   never masked twice.
3. **Mask.** `mask::mask_text` walks matches **end-to-start** and `replace_range`s
   each secret with `vault.sentinel_for(kind, value)` → `«promtect:aws_key:0001»`.
   Splicing from the end keeps earlier byte offsets valid as the string mutates.
   The same value always maps to the same sentinel within a request; each unique
   sentinel is audited once (not once per occurrence).
4. **Forward.** The masked body is re-originated as HTTPS to the upstream via
   `reqwest`. **Auth headers (`x-api-key`, `Authorization`) are forwarded
   verbatim** — Promtect touches the body only.
5. **Restore (streaming).** As the response streams back, `StreamRestorer` feeds
   chunks through `restore_scan`, swapping each known sentinel for its real
   secret. A sentinel split across two chunks is held in a look-back buffer
   bounded by `Vault::max_sentinel_len`, so restore is byte-for-byte identical to
   restoring the whole buffer at once. In strict mode (`PROMTECT_RESTORE=false`)
   this step is skipped and sentinels stay in the output.

## Invariants that make it safe

- **One vault per request.** A sentinel minted for request A cannot resolve in
  request B — cross-request bleed is impossible by construction (`secret_for`
  only knows this vault's map).
- **Single-pass restore, no cascade.** `restore_scan` rebuilds the string in one
  scan rather than a chain of `str::replace`, so a secret whose value happens to
  equal another sentinel's literal text is never re-expanded (see
  `restore_does_not_cascade` in `src/mask.rs`).
- **Memory-only, zeroized.** The vault holds secrets in RAM and `zeroize`s every
  entry on `Drop` (`vault.rs:76`). Nothing is persisted.
- **Poison-tolerant.** `Vault::lock` recovers a poisoned mutex instead of
  panicking, so one request's failure can't crash later requests.
- **Round-trip proven.** `restore(mask(x)) == x` is a property test
  (`tests/property.rs`), and the streaming restorer is proven equal to
  whole-buffer restore at every chunk boundary.
- **Value-free audit.** The audit log records timestamp, action, detector kind,
  sentinel id, request id — **never the secret value** (`tests` in `src/mask.rs`
  assert the secret never appears in the log).

## Adding a detector

One line in the `DETECTORS` vec in `src/detect.rs` (`d(...)` for a token-shaped
secret, `dg(...)` for a captured group with a placeholder guard), plus a row in
[detectors.md](detectors.md) and a synthetic test case. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
