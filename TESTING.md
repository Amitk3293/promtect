# Testing Strategy

Airlock AI uses a layered test suite. Each layer has a distinct scope and cost.
CI enforces all of them on every push and pull request.

---

## Philosophy

Tests are first-class. Every change keeps the whole suite green **and** adds or
updates tests for the behavior it changes (test-driven by default). CI enforces
`cargo fmt --check`, `cargo clippy -D warnings`, and the full test suite on every
push and pull request. Coverage is reported on every run but is never used to
gate a build — the goal is visibility, not bureaucracy.

---

## The Layers

### L1 — Unit tests (`src/**` `#[cfg(test)]`)

Each module owns its tests in a `#[cfg(test)]` block alongside the production
code. These are the cheapest tests to write and the fastest to run; they cover
the smallest units in isolation.

| Area | What is tested |
|---|---|
| Detectors (`detect.rs`) | Per-provider positive and negative cases (true hit / no false-positive) |
| Vault (`vault.rs`) | Zeroize-on-drop and round-trip storage |
| Masker (`mask.rs`) | Span-level splice — correct sentinel substitution and index arithmetic |
| Audit (`audit.rs`) | Log entries are value-free (no secret value ever written) |
| Net (`net.rs`) | `is_loopback` classification |

**Run:** `cargo test`

---

### L2 — Integration tests (`tests/integration.rs`, `tests/proxy_integration.rs`)

These tests spin up the proxy with a mock upstream and drive it over real HTTP.
They verify behavior that spans the full request/response pipeline.

| Test | What is verified |
|---|---|
| Canary no-leak | A planted AWS key reaches the mock upstream only as a sentinel |
| Auth-header passthrough | The upstream sees the original `Authorization` header unchanged |
| Multi-secret round-trip | Multiple secrets in one body are all masked and then restored |
| Response restore | Sentinels in the upstream response are replaced with the real values |
| 502 on upstream error | A dead upstream produces a clean 502, not a panic |
| Stable sentinel | The same secret in the same request always maps to the same sentinel |

**Run:** `cargo test --test proxy_integration`

---

### L3 — Property tests (`tests/property.rs`)

Uses [proptest](https://github.com/proptest-rs/proptest) to exercise the core
invariants over thousands of randomly generated inputs. These catch edge cases
that hand-crafted inputs miss.

| Invariant | Claim |
|---|---|
| Round-trip identity | `restore(mask(x)) == x` for all inputs |
| No-leak | A body that has been masked never contains the planted secret |

**Run:** `cargo test --test property`

---

### L4 — Smoke test (`scripts/smoke.sh` / `make smoke`)

Compiles and runs the real binary against a dead upstream. Verifies that:

- The binary starts and terminates without error.
- A planted key in the request body is absent from what reaches the upstream.
- The audit log is written and contains no secret value.

This is the closest test to the real deployment path and exercises the binary
as a user would encounter it.

**Run:** `make smoke`

---

### L5 — Coverage (`make coverage`, CI report-only)

`cargo llvm-cov` instruments the binary with LLVM coverage and prints a line/
branch summary. The CI `coverage` job runs this on every push. The result is
informational — low coverage on a module is a signal to add tests, not a build
failure.

**Run locally:** `make coverage` (requires `cargo install cargo-llvm-cov`)
**Run HTML report:** `make coverage-html` → opens `target/llvm-cov/html/index.html`

---

## Adding to the Suite — the Contract

- **New detector** → add at least one positive case and one negative case
  (no false-positive) to the `#[cfg(test)]` block in `src/detect.rs`.
- **Changed proxy behavior** → update or extend `tests/proxy_integration.rs` to
  cover the new behavior path.
- **New invariant** → prefer a property test in `tests/property.rs` over a
  single-example integration test; property tests cover the whole input space.
- **Never weaken an assertion** to make a test pass — fix the code instead.
  A relaxed assertion is a hidden regression.

---

## Commands Cheat-Sheet

```sh
make test                           # run the full test suite
make lint                           # cargo fmt --check + clippy -D warnings
make coverage                       # text coverage summary (needs cargo-llvm-cov)
make smoke                          # smoke-test the compiled binary

cargo test --test proxy_integration # L2 proxy integration tests only
cargo test --test property          # L3 property tests only
cargo run -- selftest               # binary-level canary (no network)
```
