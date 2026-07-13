# Docker provider and real-CLI harness

This credential-free black-box harness proves Promtect's current provider wire
behavior without contacting a provider. Build steps may download the pinned CLI
artifacts; runtime uses a Docker `internal: true` network with no default route.

```sh
make provider-harness
```

The runtime containers mount neither the repository nor the host home, `.env`,
Git metadata, provider configuration, or credentials. The runner's working
directory is an empty `/synthetic` directory. Requests contain only the fixed
AWS example canary `AKIAIOSFODNN7EXAMPLE` and fixed dummy authorization values.
The real-CLI observer retains only path, byte count, SHA-256, and masking flags;
it never retains a CLI request body.

## Pinned clients (retrieved 2026-07-13)

| Client | Pin | Runtime check | Current source |
|---|---:|---|---|
| OpenAI Codex | `0.144.3` | `codex --version` | [release](https://github.com/openai/codex/releases/tag/rust-v0.144.3) |
| Claude Code | `2.1.207` | `claude --version` | [setup](https://code.claude.com/docs/en/setup) |
| Ollama | `0.31.2` | `ollama --version` | [release](https://github.com/ollama/ollama/releases/tag/v0.31.2) |
| Aider | `0.86.2` | `aider --version` | [PyPI](https://pypi.org/project/aider-chat/0.86.2/) |

The harness pins every base-image index digest, commits npm integrity metadata
and the complete Python dependency resolution, and verifies each Ollama Linux
archive against the architecture-specific SHA-256 published with v0.31.2 before
extracting its standalone CLI binary. The Python lock permits only the exact
CPython 3.11 wheels selected on Debian Bookworm for `linux/amd64` and
`linux/arm64`; installation forces pip hash checking and rejects source
distributions. Apt packages still resolve from the Debian repository at build
time, so the build is not claimed to be byte-for-byte deterministic. Claude's
npm installer remains version-pinned even though current documentation
recommends the native installer.

### Regenerating the Python lock

Run these commands from the repository root. They resolve the direct pin in
`requirements.in` independently in digest-pinned Python 3.11 Bookworm
containers on both supported Linux architectures. The generator refuses to
write a lock if the dependency names or versions differ between targets and
records only the SHA-256 of the wheels actually selected on those targets.

```sh
rm -rf tests/provider-harness/.requirements-wheels
mkdir -p tests/provider-harness/.requirements-wheels/amd64 \
  tests/provider-harness/.requirements-wheels/arm64

docker run --rm --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/provider-harness:/work" -w /work \
  python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 \
  python -m pip download --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --dest .requirements-wheels/amd64 \
    --requirement requirements.in

docker run --rm --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/provider-harness:/work" -w /work \
  python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 \
  python -m pip download --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --dest .requirements-wheels/arm64 \
    --requirement requirements.in

docker run --rm --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/provider-harness:/work" -w /work \
  python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 \
  python generate_requirements_lock.py .requirements-wheels/amd64 \
    .requirements-wheels/arm64 requirements.lock

for platform in linux/amd64 linux/arm64; do
  docker run --rm --platform "$platform" \
    -v "$PWD/tests/provider-harness:/work:ro" \
    python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 \
    python -m pip install --disable-pip-version-check --no-cache-dir \
      --only-binary=:all: --require-hashes --requirement /work/requirements.lock
done

rm -rf tests/provider-harness/.requirements-wheels
```

Review dependency-version changes before committing the regenerated lock. A
newly published transitive dependency may legitimately change resolution, but
it must never enter the harness without a visible lock diff and new hashes.

## Protocol and failure expectations

| Scenario | Expected observable result |
|---|---|
| Anthropic Messages SSE | Upstream sees a sentinel, never the canary; one-byte chunks restore to the exact expected SSE bytes. |
| OpenAI Responses SSE | Same invariant for Responses events. |
| Ollama NDJSON | Same invariant for native newline-delimited JSON. |
| Altered sentinel | Unknown token remains byte-exact; plaintext is not reinserted. |
| Compressed request | Fixed, value-free HTTP 415; mock request count does not increase. |
| Compressed response | `Content-Encoding: gzip` and encoded bytes pass through unchanged; sentinel is not restored. |
| Refused upstream | Fixed, value-free HTTP 502; mock request count does not increase. |
| Read timeout | Client sees an interrupted response and only the prefix emitted before the sentinel opened. |
| Upstream interruption | Same observable result as timeout. |

The timeout/interruption result is a known runtime gap tracked by
[#86](https://github.com/Amitk3293/promtect/issues/86): although the stream
adapter yields retained partial-sentinel bytes before its error, the real
Axum/Hyper boundary drops that final chunk when aborting the downstream stream.
The harness labels this `OBSERVED`; it does not call it successful restoration.

## Real CLI controls and known gaps

The harness executes each pinned CLI against provider-shaped mock responses and
requires the observer to see a masked canary and the CLI to receive the
response-only `masked:<canary>` marker after restoration. Codex uses an explicit
custom provider with Responses transport and WebSockets disabled. Aider uses
CLI-precedence `--openai-api-base`.

Those explicit controls do not hide the automatic `guard` gap tracked by
[#87](https://github.com/Amitk3293/promtect/issues/87):

- Codex 0.144.3 routes a custom provider using its documented `base_url`.
  Current `guard codex` sets only `OPENAI_BASE_URL`, which does not override an
  existing direct custom-provider URL. The harness runs a controlled A/B pair
  with identical home, auth, environment, prompt, and flags. The protected URL
  produces a masked request and restored response; the direct URL sends the
  canary to an internal tripwire, which records only metadata and returns 422.
  The direct run must fail specifically from that 422, so setup or auth errors
  cannot satisfy the known-gap assertion.

The harness also adversarially sets a stale `AIDER_OPENAI_API_BASE` while
providing the two variables current `guard aider` injects. Aider 0.86.2's
`openai/` path still reaches Promtect via `OPENAI_BASE_URL`; the suspected bypass
was not reproduced. That remains a negative regression because legacy LiteLLM
paths may use the other variable.

The correct controls prove provider compatibility; they are not evidence that
the current automatic guard wiring is safe.
