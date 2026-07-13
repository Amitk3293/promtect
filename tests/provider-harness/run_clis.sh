#!/bin/sh
set -eu

CODEX_VERSION=0.144.3
CLAUDE_VERSION=2.1.207
OLLAMA_VERSION=0.31.2
AIDER_VERSION=0.86.2
SECRET=AKIAIOSFODNN7EXAMPLE
PROMPT="Return this fixed synthetic canary exactly once: ${SECRET}"
PROXY=http://promtect-cli:8790

observer_count() {
  python3 -c 'import json,urllib.request; print(len(json.load(urllib.request.urlopen("http://mock-provider:9000/__observations", timeout=5))))'
}

assert_codex_observation_window() {
  start=$1
  end=$2
  source=$3
  plaintext=$4
  sentinel=$5
  python3 - "$start" "$end" "$source" "$plaintext" "$sentinel" <<'PY'
import json
import sys
import urllib.request

start, end = map(int, sys.argv[1:3])
source, plaintext, sentinel = sys.argv[3], sys.argv[4] == "true", sys.argv[5] == "true"
with urllib.request.urlopen("http://mock-provider:9000/__observations", timeout=5) as response:
    observations = json.load(response)
window = observations[start:end]
assert len(window) == 1, f"expected exactly one Codex provider observation, got {window!r}"
matches = [
    item
    for item in window
    if item.get("source") == source and item.get("path") == "/v1/responses"
]
assert len(matches) == 1, (
    f"expected exactly one Codex Responses observation from {source}, got {matches!r}; "
    f"window={window!r}"
)
match = matches[0]
assert match.get("plaintext_canary_seen") is plaintext, match
assert match.get("sentinel_seen") is sentinel, match
assert match.get("content_encoding_seen") is None, match
assert "body" not in match, "real CLI body must not be retained"
PY
}

run_codex_base_url_control() {
  base_url=$1
  output_file=$2
  HOME=/tmp/codex-base-url CODEX_HOME=/tmp/codex-base-url \
    CODEX_API_KEY=fixed-dummy-key OPENAI_BASE_URL="${PROXY}/v1" \
    codex exec --skip-git-repo-check --sandbox read-only -C /synthetic \
      -c 'model_provider="promtect-routing-control"' \
      -c 'model_providers.promtect-routing-control.name="Promtect routing control"' \
      -c "model_providers.promtect-routing-control.base_url=\"${base_url}\"" \
      -c 'model_providers.promtect-routing-control.wire_api="responses"' \
      -c 'model_providers.promtect-routing-control.env_key="CODEX_API_KEY"' \
      -c 'model_providers.promtect-routing-control.requires_openai_auth=false' \
      -c 'model_providers.promtect-routing-control.supports_websockets=false' \
      -c 'model_providers.promtect-routing-control.request_max_retries=0' \
      -c 'model_providers.promtect-routing-control.stream_max_retries=0' \
      "$PROMPT" > "$output_file" 2>&1
}

assert_version() {
  name=$1
  expected=$2
  shift 2
  observed=$("$@" 2>&1)
  case "$observed" in
    *"$expected"*) printf 'PASS version: %s %s\n' "$name" "$expected" ;;
    *) printf 'FAIL version: %s expected %s, observed %s\n' "$name" "$expected" "$observed" >&2; exit 1 ;;
  esac
}

assert_output_restored() {
  name=$1
  output_file=$2
  if ! grep -Fq "masked:${SECRET}" "$output_file"; then
    printf 'FAIL CLI control: %s did not return the restored synthetic canary\n' "$name" >&2
    sed -n '1,80p' "$output_file" >&2
    exit 1
  fi
  printf 'PASS CLI control: %s routed through Promtect and received restored output\n' "$name"
}

assert_version Codex "$CODEX_VERSION" codex --version
assert_version "Claude Code" "$CLAUDE_VERSION" claude --version
assert_version Ollama "$OLLAMA_VERSION" ollama --version
assert_version Aider "$AIDER_VERSION" aider --version

mkdir -p /tmp/codex-base-url /tmp/codex-guard /tmp/claude /tmp/ollama /tmp/aider

# Codex A/B routing control. The two invocations share the same home, auth,
# environment, prompt, and flags; only the documented custom-provider base_url
# changes. OPENAI_BASE_URL points at Promtect in both arms, reproducing the
# current guard environment without relying on external network failure.
ab_before=$(observer_count)
if ! run_codex_base_url_control "${PROXY}/v1" /tmp/codex-protected.out; then
  printf 'FAIL Codex A/B protected arm: Codex exited nonzero\n' >&2
  sed -n '1,120p' /tmp/codex-protected.out >&2
  exit 1
fi
ab_protected_after=$(observer_count)
assert_codex_observation_window "$ab_before" "$ab_protected_after" real-cli false true
assert_output_restored "Codex A/B protected arm" /tmp/codex-protected.out

if run_codex_base_url_control \
  http://mock-provider:9000/codex-base-url-control/v1 \
  /tmp/codex-direct.out; then
  printf 'FAIL Codex A/B direct arm: mock tripwire unexpectedly accepted plaintext\n' >&2
  exit 1
fi
ab_direct_after=$(observer_count)
assert_codex_observation_window \
  "$ab_protected_after" "$ab_direct_after" codex-base-url-control true false
if ! grep -Fq 'unsafe harness request rejected' /tmp/codex-direct.out; then
  printf 'FAIL Codex A/B direct arm: nonzero exit was not the mock tripwire response\n' >&2
  sed -n '1,120p' /tmp/codex-direct.out >&2
  exit 1
fi
printf 'PASS Codex routing control: direct custom provider bypasses environment-only routing and hits tripwire\n'

# Exercise the shipped one-command path, not just manually configured provider
# routing. The guard must force the built-in provider through its ephemeral
# proxy, disable request compression, mask upstream, and restore the response.
guard_before=$(observer_count)
if ! HOME=/tmp/codex-guard CODEX_HOME=/tmp/codex-guard \
  OPENAI_API_KEY=fixed-dummy-key CODEX_API_KEY=fixed-dummy-key \
  promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
    -c 'model="synthetic-model"' \
    exec --skip-git-repo-check --sandbox read-only -C /synthetic "$PROMPT" \
    > /tmp/codex-guard.out 2>&1; then
  printf 'FAIL Codex guard: protected real-CLI execution exited nonzero\n' >&2
  sed -n '1,160p' /tmp/codex-guard.out >&2
  exit 1
fi
guard_after=$(observer_count)
assert_codex_observation_window "$guard_before" "$guard_after" guard-codex false true
assert_output_restored "Codex guard" /tmp/codex-guard.out
if ! grep -Fq 'Codex config check: protected Responses route accepted, WebSockets and request compression disabled' /tmp/codex-guard.out; then
  printf 'FAIL Codex guard: fail-closed config check was not reported\n' >&2
  exit 1
fi
printf 'PASS Codex guard: real CLI masked/restored with request compression absent\n'
for comm in /proc/[0-9]*/comm; do
  process_name=
  if [ -r "$comm" ]; then
    IFS= read -r process_name < "$comm" || true
  fi
  if [ "$process_name" = promtect ]; then
    printf 'FAIL Codex guard: Promtect process remained after guard returned\n' >&2
    exit 1
  fi
done
printf 'PASS Codex guard: teardown left no Promtect process\n'

HOME=/tmp/claude CLAUDE_CONFIG_DIR=/tmp/claude \
  ANTHROPIC_BASE_URL="$PROXY" ANTHROPIC_API_KEY=fixed-dummy-key \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  claude --print --output-format text "$PROMPT" > /tmp/claude.out 2>&1
assert_output_restored "Claude Code" /tmp/claude.out

if ! HOME=/tmp/ollama OLLAMA_HOST="$PROXY" \
  ollama run synthetic-model "$PROMPT" > /tmp/ollama.out 2>&1; then
  printf 'FAIL CLI control: Ollama exited nonzero\n' >&2
  sed -n '1,120p' /tmp/ollama.out >&2
  exit 1
fi
assert_output_restored Ollama /tmp/ollama.out

# Pin and execute Aider with CLI-precedence routing so a stale parent
# AIDER_OPENAI_API_BASE cannot win. Automatic guard precedence is tracked in #87.
if ! HOME=/tmp/aider OPENAI_API_KEY=fixed-dummy-key \
  OPENAI_API_BASE="${PROXY}/v1" OPENAI_BASE_URL="${PROXY}/v1" \
  AIDER_OPENAI_API_BASE="${PROXY}/v1" \
  aider --model openai/synthetic-model \
  --openai-api-base "${PROXY}/v1" --message "$PROMPT" \
  --no-git --no-auto-commits --no-analytics --no-check-update \
  --no-show-release-notes --no-browser --disable-playwright \
  > /tmp/aider.out 2>&1; then
  printf 'FAIL CLI control: Aider exited nonzero\n' >&2
  sed -n '1,160p' /tmp/aider.out >&2
  exit 1
fi
assert_output_restored Aider /tmp/aider.out

# Negative regression for the Aider precedence concern in #87. This reproduces
# guard's injected OpenAI variables plus a stale AIDER_OPENAI_API_BASE. Current
# Aider's openai/ path must still use OPENAI_BASE_URL and reach Promtect.
mkdir -p /tmp/aider-gap
before=$(observer_count)
if ! HOME=/tmp/aider-gap OPENAI_API_KEY=fixed-dummy-key \
  OPENAI_API_BASE="${PROXY}/v1" OPENAI_BASE_URL="${PROXY}/v1" \
  AIDER_OPENAI_API_BASE=http://mock-provider:65534/v1 \
  aider --model openai/synthetic-model --message "$PROMPT" --timeout 2 \
    --no-git --no-auto-commits --no-analytics --no-check-update \
    --no-show-release-notes --no-browser --disable-playwright \
    > /tmp/aider-gap.out 2>&1; then
  printf 'FAIL Aider precedence regression: stale environment prevented protected execution\n' >&2
  exit 1
fi
after=$(observer_count)
if [ "$after" -le "$before" ]; then
  printf 'FAIL Aider precedence regression: stale environment bypassed Promtect\n' >&2
  exit 1
fi
assert_output_restored "Aider stale-environment regression" /tmp/aider-gap.out

python3 /harness/verify_cli_observations.py
