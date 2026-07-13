#!/bin/sh
set -eu

CODEX_VERSION=0.144.3
CLAUDE_VERSION=2.1.207
OLLAMA_VERSION=0.31.2
AIDER_VERSION=0.86.2
SECRET=AKIAIOSFODNN7EXAMPLE
PROMPT="Return this fixed synthetic canary exactly once: ${SECRET}"
PROXY=http://promtect-cli:8790

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

mkdir -p /tmp/codex /tmp/claude /tmp/ollama /tmp/aider

# Official custom-provider control. Codex 0.144.3 does not read
# OPENAI_BASE_URL, so the protected control explicitly selects a Responses
# provider and disables its WebSocket transport until guard wiring is fixed in
# #87.
if ! HOME=/tmp/codex CODEX_HOME=/tmp/codex CODEX_API_KEY=fixed-dummy-key \
  codex exec --skip-git-repo-check --sandbox read-only -C /synthetic \
    -c 'model_provider="promtect"' \
    -c 'model_providers.promtect.name="Promtect harness"' \
    -c "model_providers.promtect.base_url=\"${PROXY}/v1\"" \
    -c 'model_providers.promtect.wire_api="responses"' \
    -c 'model_providers.promtect.env_key="CODEX_API_KEY"' \
    -c 'model_providers.promtect.requires_openai_auth=false' \
    -c 'model_providers.promtect.supports_websockets=false' \
    -c 'model_providers.promtect.request_max_retries=0' \
    -c 'model_providers.promtect.stream_max_retries=0' \
    "$PROMPT" > /tmp/codex.out 2>&1; then
  printf 'FAIL CLI control: Codex exited nonzero\n' >&2
  sed -n '1,120p' /tmp/codex.out >&2
  exit 1
fi
assert_output_restored Codex /tmp/codex.out

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

observer_count() {
  python3 -c 'import json,urllib.request; print(len(json.load(urllib.request.urlopen("http://mock-provider:9000/__observations", timeout=5))))'
}

# Deterministic evidence for #87: current Codex ignores OPENAI_BASE_URL. The
# internal-only network makes the attempted default route unreachable; success
# or an observer request would invalidate the known-gap evidence.
before=$(observer_count)
if HOME=/tmp/codex-gap CODEX_HOME=/tmp/codex-gap CODEX_API_KEY=fixed-dummy-key \
  OPENAI_BASE_URL="${PROXY}/v1" \
  codex exec --skip-git-repo-check --sandbox read-only -C /synthetic \
    "$PROMPT" > /tmp/codex-gap.out 2>&1; then
  printf 'FAIL known-gap evidence: Codex unexpectedly honored OPENAI_BASE_URL\n' >&2
  exit 1
fi
after=$(observer_count)
if [ "$before" != "$after" ]; then
  printf 'FAIL known-gap evidence: Codex OPENAI_BASE_URL run reached the observer\n' >&2
  exit 1
fi
printf 'KNOWN GAP #87: Codex ignored OPENAI_BASE_URL; internal network blocked the bypass\n'

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
