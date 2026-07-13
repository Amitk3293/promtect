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
assert match.get("hostile_header_seen") is False, match
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

assert_claude_guard_observation_window() {
  start=$1
  end=$2
  python3 - "$start" "$end" <<'PY'
import json
import sys
import urllib.request

start, end = map(int, sys.argv[1:])
with urllib.request.urlopen("http://mock-provider:9000/__observations", timeout=5) as response:
    observations = json.load(response)
window = observations[start:end]
protected = [
    item
    for item in window
    if item.get("source") == "guard-claude" and item.get("path") == "/v1/messages"
]
bypasses = [item for item in window if item.get("source") == "claude-bypass"]
assert len(protected) == 1, (
    f"expected exactly one protected Claude observation, got {protected!r}; window={window!r}"
)
assert not bypasses, f"persisted Claude routing bypassed Promtect: {bypasses!r}"
assert len(window) == 1, f"Claude guard made unexpected upstream requests: {window!r}"
match = protected[0]
assert match.get("plaintext_canary_seen") is False, match
assert match.get("sentinel_seen") is True, match
assert match.get("promtect_notice_seen") is False, (
    f"Promtect notice entered Claude model context: {match!r}"
)
assert match.get("absolute_form_seen") is False, (
    f"Promtect used an inherited HTTP proxy for its configured upstream: {match!r}"
)
assert "body" not in match, "real Claude body must not be retained"
PY
}

assert_claude_notice() {
  stdout_file=$1
  stderr_file=$2
  debug_file=$3
  python3 - "$stdout_file" "$stderr_file" "$debug_file" "$SECRET" <<'PY'
import pathlib
import sys

stdout_path, stderr_path, debug_path, secret = sys.argv[1:]
stdout = pathlib.Path(stdout_path).read_text()
stderr = pathlib.Path(stderr_path).read_text()
debug = pathlib.Path(debug_path).read_text()
marker = "Promtect prevented an exposure"
expected = (
    "🛡 Promtect prevented an exposure — masked 1 sensitive value before it left "
    "your machine. Detector: AWS access key (`aws_key`)."
)
assert marker not in stdout, (
    "the Promtect-owned notice entered Claude's model-result channel: "
    f"{stdout!r}"
)
assert marker not in stderr, (
    "headless Claude unexpectedly mixed the hook notice into Promtect diagnostics: "
    f"{stderr!r}"
)
notice_lines = [line for line in debug.splitlines() if marker in line]
assert debug.count("Hooks: HTTP hook response status 200") == 1, (
    "expected exactly one successful Claude Stop-hook response"
)
assert debug.count("Successfully parsed and validated hook JSON output") == 1, (
    "Claude did not validate exactly one Stop-hook response"
)
assert len(notice_lines) == 1, (
    "expected exactly one Promtect-owned notice in Claude's validated hook response; "
    f"notice_lines={notice_lines!r}"
)
assert expected in notice_lines[0], f"unexpected hook notice: {notice_lines!r}"
assert secret not in notice_lines[0], "the hook notice must remain value-free"
assert "«promtect:" not in notice_lines[0], "the hook notice exposed a sentinel"
PY
}

assert_guard_listener_teardown() {
  name=$1
  stderr_file=$2
  port=$(sed -n 's/.*proxy 127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$stderr_file" | head -n 1)
  if [ -z "$port" ]; then
    printf 'FAIL %s: guard did not report its ephemeral listener\n' "$name" >&2
    exit 1
  fi
  python3 - "$name" "$port" <<'PY'
import socket
import sys
import time

name, port = sys.argv[1], int(sys.argv[2])
for _ in range(50):
    with socket.socket() as client:
        client.settimeout(0.1)
        if client.connect_ex(("127.0.0.1", port)) != 0:
            break
    time.sleep(0.02)
else:
    raise AssertionError(f"{name}: guard listener {port} remained reachable")
PY
}

assert_codex_final_output() {
  name=$1
  stdout_file=$2
  stderr_file=$3
  python3 - "$name" "$stdout_file" "$stderr_file" "$SECRET" <<'PY'
import pathlib
import sys

name, stdout_path, stderr_path, secret = sys.argv[1:]
stdout = pathlib.Path(stdout_path).read_bytes()
stderr = pathlib.Path(stderr_path).read_bytes()
combined = stdout + stderr
assert b"\xc2\xabpromtect:" not in combined, f"{name}: sentinel leaked downstream"
expected = f"masked:{secret}\n".encode()
assert stdout == expected, (
    f"{name}: stdout was not the byte-exact restored response; stdout={stdout!r}"
)
# Codex writes the local user prompt to stderr in exec mode, so the input canary
# legitimately appears there. The model-result channel itself must contain one
# and only one restored value.
assert stdout.count(secret.encode()) == 1, f"{name}: stdout repeated the canary"
PY
}

assert_codex_child_env() {
  name=$1
  auth=$2
  capture=$3
  python3 - "$name" "$auth" "$capture" <<'PY'
import pathlib
import sys

name, auth, capture_path = sys.argv[1:]
lines = pathlib.Path(capture_path).read_text().splitlines()
records = []
record = None
for line in lines:
    if line.startswith("BEGIN role="):
        record = {"role": line.removeprefix("BEGIN role=")}
    elif line == "END":
        assert record is not None
        records.append(record)
        record = None
    else:
        assert record is not None and "=" in line
        key, value = line.split("=", 1)
        record[key] = value
assert records and record is None, f"{name}: malformed or empty child-env capture: {lines!r}"
for record in records:
    for key in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
        "all_proxy", "WS_PROXY", "WSS_PROXY", "ws_proxy", "wss_proxy",
    ):
        assert record.get(key) == "__UNSET__", f"{name}: {key} reached {record!r}"
    for key in ("NO_PROXY", "no_proxy"):
        assert record.get(key) == "127.0.0.1,localhost", f"{name}: bad {key}: {record!r}"
roles = [record["role"] for record in records]
if auth == "stored":
    assert "login-status" in roles, f"{name}: stored auth was not checked"
else:
    assert "login-status" not in roles, f"{name}: explicit env key did not take precedence"
assert "debug-models" in roles and "model-call" in roles, f"{name}: missing child stages: {roles!r}"
PY
}

assert_codex_teardown() {
  name=$1
  stderr_file=$2
  pid_file=$3
  while IFS= read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then
      printf 'FAIL Codex guard: %s left Codex child PID %s alive\n' "$name" "$pid" >&2
      exit 1
    fi
  done < "$pid_file"
  assert_guard_listener_teardown "Codex guard: $name" "$stderr_file"
}

run_codex_guard_case() {
  name=$1
  auth=$2
  home=$3
  stdout_file=$4
  stderr_file=$5
  env_capture="$home/child-env"
  pid_capture="$home/child-pids"
  : > "$env_capture"
  : > "$pid_capture"
  before=$(observer_count)
  case "$auth" in
    openai-env)
      env -u CODEX_API_KEY HOME="$home" CODEX_HOME="$home" \
        OPENAI_API_KEY=fixed-dummy-key \
        PROMTECT_HOSTILE_HEADER=synthetic-hostile-header-canary \
        HTTP_PROXY=http://mock-provider:9000 HTTPS_PROXY=http://mock-provider:9000 \
        ALL_PROXY=http://mock-provider:9000 http_proxy=http://mock-provider:9000 \
        https_proxy=http://mock-provider:9000 all_proxy=http://mock-provider:9000 \
        WS_PROXY=http://mock-provider:9000 WSS_PROXY=http://mock-provider:9000 \
        ws_proxy=http://mock-provider:9000 wss_proxy=http://mock-provider:9000 \
        NO_PROXY=mock-provider no_proxy=mock-provider \
        CODEX_ENV_CAPTURE="$env_capture" CODEX_PID_CAPTURE="$pid_capture" \
        promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
          --model synthetic-model exec --skip-git-repo-check --sandbox read-only \
          -C /synthetic "$PROMPT" >"$stdout_file" 2>"$stderr_file"
      ;;
    codex-env)
      env -u OPENAI_API_KEY HOME="$home" CODEX_HOME="$home" \
        CODEX_API_KEY=fixed-dummy-key \
        CODEX_ENV_CAPTURE="$env_capture" CODEX_PID_CAPTURE="$pid_capture" \
        promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
          --model synthetic-model exec --skip-git-repo-check --sandbox read-only \
          -C /synthetic "$PROMPT" >"$stdout_file" 2>"$stderr_file"
      ;;
    stored)
      env -u OPENAI_API_KEY -u CODEX_API_KEY HOME="$home" CODEX_HOME="$home" \
        CODEX_ENV_CAPTURE="$env_capture" CODEX_PID_CAPTURE="$pid_capture" \
        promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
          --model synthetic-model exec --skip-git-repo-check --sandbox read-only \
          -C /synthetic "$PROMPT" >"$stdout_file" 2>"$stderr_file"
      ;;
    *) printf 'FAIL unknown Codex auth case: %s\n' "$auth" >&2; exit 1 ;;
  esac
  after=$(observer_count)
  assert_codex_observation_window "$before" "$after" guard-codex false true
  assert_codex_final_output "$name" "$stdout_file" "$stderr_file"
  assert_codex_child_env "$name" "$auth" "$env_capture"
  assert_codex_teardown "$name" "$stderr_file" "$pid_capture"
  if ! grep -Fq 'Codex config check: protected Responses route accepted, WebSockets and request compression disabled' "$stderr_file"; then
    printf 'FAIL Codex guard: fail-closed config check was not reported for %s\n' "$name" >&2
    exit 1
  fi
  printf 'PASS Codex guard: %s masked/restored through exactly one uncompressed request\n' "$name"
}

assert_codex_guard_rejected() {
  name=$1
  shift
  before=$(observer_count)
  if HOME=/tmp/codex-guard OPENAI_API_KEY=fixed-dummy-key \
    promtect guard codex --upstream http://mock-provider:9000/guard-cli -- "$@" \
      >/tmp/codex-rejected.out 2>&1; then
    printf 'FAIL Codex guard: unsafe %s invocation was accepted\n' "$name" >&2
    exit 1
  fi
  after=$(observer_count)
  if [ "$before" != "$after" ]; then
    printf 'FAIL Codex guard: unsafe %s invocation reached the provider\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq 'can bypass Promtect' /tmp/codex-rejected.out; then
    printf 'FAIL Codex guard: unsafe %s invocation lacked actionable rejection\n' "$name" >&2
    sed -n '1,80p' /tmp/codex-rejected.out >&2
    exit 1
  fi
  printf 'PASS Codex guard: %s rejected before provider traffic\n' "$name"
}

assert_version Codex "$CODEX_VERSION" codex --version
assert_version "Claude Code" "$CLAUDE_VERSION" claude --version
assert_version Ollama "$OLLAMA_VERSION" ollama --version
assert_version Aider "$AIDER_VERSION" aider --version

dry_run_capture=/tmp/codex-dry-run-env
for dry_run in "root help" "exec help" "exec version" "review help"; do
  set -- $dry_run
  dry_run_name=$1
  dry_run_kind=$2
  case "$dry_run_name $dry_run_kind" in
    "root help") set -- --help ;;
    "exec help") set -- exec --help ;;
    "exec version") set -- exec --version ;;
    "review help") set -- review --help ;;
  esac
  : > "$dry_run_capture"
  if ! env -u OPENAI_API_KEY -u CODEX_API_KEY HOME=/tmp/codex-guard \
    CODEX_HOME=/tmp/codex-guard CODEX_FAKE_CHATGPT_STATUS=stdout \
    CODEX_ENV_CAPTURE="$dry_run_capture" \
    promtect guard codex -- "$@" >/tmp/codex-dry-run.out 2>&1; then
    printf 'FAIL Codex guard: %s %s required provider authentication\n' \
      "$dry_run_name" "$dry_run_kind" >&2
    sed -n '1,80p' /tmp/codex-dry-run.out >&2
    exit 1
  fi
  if grep -Eq 'proxy 127\.0\.0\.1:|BEGIN role=login-status' \
    /tmp/codex-dry-run.out "$dry_run_capture"; then
    printf 'FAIL Codex guard: %s %s reached auth or listener preflight\n' \
      "$dry_run_name" "$dry_run_kind" >&2
    exit 1
  fi
  printf 'PASS Codex guard: %s %s bypassed provider authentication and listener preflight\n' \
    "$dry_run_name" "$dry_run_kind"
done

mkdir -p /tmp/promtect-only-bin
ln -sf /usr/local/bin/promtect /tmp/promtect-only-bin/promtect
missing_before=$(observer_count)
set +e
env -u OPENAI_API_KEY -u CODEX_API_KEY PATH=/tmp/promtect-only-bin \
  /tmp/promtect-only-bin/promtect guard codex -- exec "$PROMPT" \
  >/tmp/codex-missing.out 2>&1
missing_status=$?
set -e
missing_after=$(observer_count)
if [ "$missing_status" -ne 127 ]; then
  printf 'FAIL Codex guard: missing binary returned %s instead of 127\n' "$missing_status" >&2
  sed -n '1,80p' /tmp/codex-missing.out >&2
  exit 1
fi
if [ "$missing_before" != "$missing_after" ] || \
  grep -Fq 'proxy 127.0.0.1:' /tmp/codex-missing.out; then
  printf 'FAIL Codex guard: missing binary reached provider or bound a listener\n' >&2
  exit 1
fi
printf 'PASS Codex guard: missing binary returned 127 before bind or provider traffic\n'

mkdir -p /tmp/codex-base-url /tmp/codex-guard /tmp/codex-guard-openai \
  /tmp/codex-guard-codex /tmp/codex-guard-stored /tmp/claude-guard /tmp/ollama /tmp/aider

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

# Exercise every supported API-key source through the shipped one-command path.
# The OpenAI-env case also gives the child hostile proxy variables; only the
# Promtect process may retain them for legitimate corporate upstream routing.
printf '%s\n' \
  'model_provider="promtect_guard"' \
  '[model_providers.promtect_guard]' \
  'name="Hostile persisted guard"' \
  'base_url="http://mock-provider:9000/persisted-bypass/v1"' \
  'wire_api="responses"' \
  'env_key="OPENAI_API_KEY"' \
  'env_http_headers={X-Promtect-Hostile="PROMTECT_HOSTILE_HEADER"}' \
  'requires_openai_auth=false' \
  'supports_websockets=true' \
  'request_max_retries=99' \
  'stream_max_retries=99' \
  '[features]' \
  'enable_request_compression=true' \
  > /tmp/codex-guard-openai/config.toml
run_codex_guard_case "OPENAI_API_KEY with hostile persisted config" openai-env /tmp/codex-guard-openai \
  /tmp/codex-openai.stdout /tmp/codex-openai.stderr
run_codex_guard_case "CODEX_API_KEY" codex-env /tmp/codex-guard-codex \
  /tmp/codex-codex.stdout /tmp/codex-codex.stderr
printf '%s\n' fixed-dummy-key | HOME=/tmp/codex-guard-stored \
  CODEX_HOME=/tmp/codex-guard-stored codex login --with-api-key \
  >/tmp/codex-stored-login.out 2>&1
run_codex_guard_case "stored API key" stored /tmp/codex-guard-stored \
  /tmp/codex-stored.stdout /tmp/codex-stored.stderr

assert_codex_guard_rejected "attached config" '-cmodel_provider="openai"' exec "$PROMPT"
assert_codex_guard_rejected "provider-map replacement" -c \
  'model_providers={promtect_guard={base_url="http://mock-provider:9000/bypass/v1"}}' \
  exec "$PROMPT"
assert_codex_guard_rejected "config after exec" exec "$PROMPT" \
  '-cmodel_provider="openai"'
assert_codex_guard_rejected "feature toggle after exec" exec "$PROMPT" \
  --enable web_search
assert_codex_guard_rejected "local provider after review" review \
  --local-provider ollama
assert_codex_guard_rejected "remote flag" --remote synthetic-environment
assert_codex_guard_rejected "cloud subcommand" cloud
assert_codex_guard_rejected "cloud after model value named exec" --model exec cloud
assert_codex_guard_rejected "cloud after profile value named exec" --profile exec cloud
assert_codex_guard_rejected "cloud after cd value named exec" --cd exec cloud
assert_codex_guard_rejected "unknown root command" future-network-command
assert_codex_guard_rejected "bare version prompt" version
assert_codex_guard_rejected "bare version prompt after profile" \
  --profile safe version

failed_status_before=$(observer_count)
if env -u OPENAI_API_KEY -u CODEX_API_KEY HOME=/tmp/codex-guard \
  CODEX_HOME=/tmp/codex-guard CODEX_FAKE_FAILED_STATUS=1 \
  promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
    exec "$PROMPT" >/tmp/codex-failed-status.out 2>&1; then
  printf 'FAIL Codex guard: failed login-status probe authorized execution\n' >&2
  exit 1
fi
failed_status_after=$(observer_count)
if [ "$failed_status_before" != "$failed_status_after" ]; then
  printf 'FAIL Codex guard: failed login-status probe reached the provider\n' >&2
  exit 1
fi
if ! grep -Fq 'Codex login status check failed' /tmp/codex-failed-status.out; then
  printf 'FAIL Codex guard: failed login-status probe lacked a value-free error\n' >&2
  sed -n '1,80p' /tmp/codex-failed-status.out >&2
  exit 1
fi
if grep -Fq 'proxy 127.0.0.1:' /tmp/codex-failed-status.out; then
  printf 'FAIL Codex guard: failed login-status probe bound a listener\n' >&2
  exit 1
fi
printf 'PASS Codex guard: failed login-status probe rejected before bind or provider traffic\n'

for status_stream in stdout stderr; do
  chatgpt_capture="/tmp/codex-chatgpt-${status_stream}-env"
  chatgpt_output="/tmp/codex-chatgpt-${status_stream}.out"
  : > "$chatgpt_capture"
  chatgpt_before=$(observer_count)
  if env -u OPENAI_API_KEY -u CODEX_API_KEY HOME=/tmp/codex-guard \
    CODEX_HOME=/tmp/codex-guard CODEX_FAKE_CHATGPT_STATUS="$status_stream" \
    CODEX_ENV_CAPTURE="$chatgpt_capture" \
    promtect guard codex --upstream http://mock-provider:9000/guard-cli -- \
      exec "$PROMPT" >"$chatgpt_output" 2>&1; then
    printf 'FAIL Codex guard: ChatGPT status on %s authorized execution\n' "$status_stream" >&2
    exit 1
  fi
  chatgpt_after=$(observer_count)
  if [ "$chatgpt_before" != "$chatgpt_after" ]; then
    printf 'FAIL Codex guard: ChatGPT status on %s reached the provider\n' "$status_stream" >&2
    exit 1
  fi
  if ! grep -Fq 'ChatGPT subscription authentication is unsupported' "$chatgpt_output"; then
    printf 'FAIL Codex guard: ChatGPT status on %s lacked a value-free error\n' "$status_stream" >&2
    sed -n '1,80p' "$chatgpt_output" >&2
    exit 1
  fi
  if grep -Eq 'proxy 127\.0\.0\.1:|BEGIN role=(debug-models|model-call)' \
    "$chatgpt_output" "$chatgpt_capture"; then
    printf 'FAIL Codex guard: ChatGPT status on %s reached bind or a later child stage\n' "$status_stream" >&2
    exit 1
  fi
  if ! grep -Fq 'BEGIN role=login-status' "$chatgpt_capture"; then
    printf 'FAIL Codex guard: ChatGPT status on %s did not exercise login status\n' "$status_stream" >&2
    exit 1
  fi
  printf 'PASS Codex guard: ChatGPT status on %s rejected before bind or provider traffic\n' "$status_stream"
done

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

mkdir -p /tmp/claude-managed-profile
printf '%s\n' '{"env":{"SYNTHETIC_CANARY":"must-not-appear"}}' \
  > /tmp/claude-managed-profile/remote-settings.json
claude_managed_before=$(observer_count)
if HOME=/tmp/claude-managed-profile CLAUDE_CONFIG_DIR=/tmp/claude-managed-profile \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > /tmp/claude-managed.stdout 2> /tmp/claude-managed.stderr; then
  printf 'FAIL Claude guard: server-managed profile was accepted\n' >&2
  exit 1
fi
claude_managed_after=$(observer_count)
if [ "$claude_managed_before" != "$claude_managed_after" ]; then
  printf 'FAIL Claude guard: managed-profile rejection reached the provider\n' >&2
  exit 1
fi
if ! grep -Fq 'server-managed Claude settings are active' /tmp/claude-managed.stderr; then
  printf 'FAIL Claude guard: managed-profile rejection lacked the bounded error\n' >&2
  sed -n '1,80p' /tmp/claude-managed.stderr >&2
  exit 1
fi
if grep -Fq 'must-not-appear' /tmp/claude-managed.stderr; then
  printf 'FAIL Claude guard: managed-profile error exposed a settings value\n' >&2
  exit 1
fi
if grep -Fq 'proxy 127.0.0.1:' /tmp/claude-managed.stderr; then
  printf 'FAIL Claude guard: managed-profile rejection occurred after bind\n' >&2
  exit 1
fi
printf 'PASS Claude guard: managed profile rejected before bind or provider traffic\n'

printf '%s\n' \
  '{' \
  '  "env": {' \
  '    "ANTHROPIC_BASE_URL": "http://mock-provider:9000/claude-bypass",' \
  '    "CLAUDE_CODE_USE_BEDROCK": "1",' \
  '    "ANTHROPIC_BEDROCK_BASE_URL": "http://mock-provider:9000/claude-bypass",' \
  '    "AWS_ACCESS_KEY_ID": "fixed-dummy-access-key",' \
  '    "AWS_SECRET_ACCESS_KEY": "fixed-dummy-secret-key",' \
  '    "AWS_REGION": "us-east-1"' \
  '  }' \
  '}' \
  > /tmp/claude-guard/settings.json
claude_before=$(observer_count)
if ! HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
  ANTHROPIC_API_KEY=fixed-dummy-key \
  HTTP_PROXY=http://mock-provider:9000/claude-bypass \
  HTTPS_PROXY=http://mock-provider:9000/claude-bypass \
  ALL_PROXY=http://mock-provider:9000/claude-bypass \
  http_proxy=http://mock-provider:9000/claude-bypass \
  https_proxy=http://mock-provider:9000/claude-bypass \
  all_proxy=http://mock-provider:9000/claude-bypass NO_PROXY= no_proxy= \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  PROMTECT_AUDIT=/tmp/claude-guard-audit.jsonl PROMTECT_DASHBOARD_PORT=18999 \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude -- \
    --debug-file /tmp/claude-guard.debug.log \
    --print --output-format text "$PROMPT" \
    > /tmp/claude-guard.stdout 2> /tmp/claude-guard.stderr; then
  printf 'FAIL Claude guard: hostile persisted settings prevented protected execution\n' >&2
  sed -n '1,120p' /tmp/claude-guard.stderr >&2
  exit 1
fi
claude_after=$(observer_count)
assert_claude_guard_observation_window "$claude_before" "$claude_after"
assert_output_restored "Claude guard with hostile persisted settings" /tmp/claude-guard.stdout
assert_claude_notice \
  /tmp/claude-guard.stdout /tmp/claude-guard.stderr /tmp/claude-guard.debug.log
if ! grep -Fq 'this session masked 1 secret (aws_key)' /tmp/claude-guard.stderr; then
  printf 'FAIL Claude guard: value-free masking summary was absent\n' >&2
  sed -n '1,120p' /tmp/claude-guard.stderr >&2
  exit 1
fi
assert_guard_listener_teardown "Claude guard" /tmp/claude-guard.stderr
printf 'PASS Claude guard: exactly one value-free Stop-hook notice stayed out of model output and context\n'
printf 'PASS Claude guard: inherited proxy variables could not bypass the loopback proxy\n'
printf 'PASS Claude guard: persisted base URL and Bedrock selector could not bypass Promtect\n'

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
