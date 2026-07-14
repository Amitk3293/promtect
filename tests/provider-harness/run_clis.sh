#!/bin/sh
set -eu

CODEX_VERSION=0.144.3
CLAUDE_VERSION=2.1.207
OLLAMA_VERSION=0.31.2
AIDER_VERSION=0.86.2
SECRET=AKIAIOSFODNN7EXAMPLE
PROMPT="Return this fixed synthetic canary exactly once: ${SECRET}"
CLAUDE_FOUR_PROMPT='Treat these as fixed synthetic canaries and return only a short acknowledgement:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ANTHROPIC_API_KEY=sk-ant-demo0000000000000000000000000000
GITHUB_TOKEN=ghp_000000000000000000000000000000000000
STRIPE_SECRET_KEY=sk_test_000000000000000000000000'
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
assert len(protected) == 2, (
    f"expected exactly two protected Claude observations, got {protected!r}; window={window!r}"
)
assert not bypasses, f"persisted Claude routing bypassed Promtect: {bypasses!r}"
assert len(window) == 2, f"Claude guard made unexpected upstream requests: {window!r}"
for match in protected:
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

assert_claude_single_observation_window() {
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
assert len(window) == 1, f"Claude made unexpected upstream requests: {window!r}"
match = window[0]
assert match.get("source") == "guard-claude", match
assert match.get("path") == "/v1/messages", match
assert match.get("plaintext_canary_seen") is False, match
assert match.get("sentinel_seen") is True, match
assert match.get("promtect_notice_seen") is False, (
    f"Promtect notice entered Claude model context: {match!r}"
)
assert "body" not in match, "Claude body must not be retained"
PY
}

assert_claude_notice() {
  stdout_file=$1
  stderr_file=$2
  debug_file=$3
  python3 - "$stdout_file" "$stderr_file" "$debug_file" "$SECRET" <<'PY'
import pathlib
import json
import re
import sys

stdout_path, stderr_path, debug_path, secret = sys.argv[1:]
stdout = pathlib.Path(stdout_path).read_text()
stderr = pathlib.Path(stderr_path).read_text()
debug = pathlib.Path(debug_path).read_text()
marker = "Promtect prevented an exposure"
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
message = json.loads(notice_lines[0])["systemMessage"]
count = re.search(r"masked (\d+) sensitive values", message)
assert count and int(count.group(1)) >= 4, f"unexpected hook notice count: {message!r}"
for detector in (
    "Anthropic API key (`anthropic_key`)",
    "AWS access key (`aws_key`)",
    "GitHub token (`github_token`)",
    "Stripe API key (`stripe_key`)",
):
    assert detector in message, f"missing detector in hook notice: {message!r}"
assert secret not in message, "the hook notice must remain value-free"
assert "«promtect:" not in message, "the hook notice exposed a sentinel"
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

assert_process_gone() {
  name=$1
  pid=$2
  python3 - "$name" "$pid" <<'PY'
import pathlib
import sys
import time

name, raw_pid = sys.argv[1:]
pid = int(raw_pid)

def live():
    path = pathlib.Path(f"/proc/{pid}/stat")
    try:
        stat = path.read_text()
    except FileNotFoundError:
        return False
    close = stat.rfind(")")
    return close < 0 or stat[close + 2 :].split()[0] != "Z"

for _ in range(100):
    if not live():
        break
    time.sleep(0.02)
else:
    raise AssertionError(f"{name}: process {pid} remained alive")
PY
}

assert_ports_reusable() {
  name=$1
  proxy_port=$2
  dashboard_port=$3
  python3 - "$name" "$proxy_port" "$dashboard_port" <<'PY'
import socket
import sys

name = sys.argv[1]
ports = [int(value) for value in sys.argv[2:]]
sockets = []
try:
    for port in ports:
        listener = socket.socket()
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        sockets.append(listener)
finally:
    for listener in sockets:
        listener.close()
assert len(sockets) == len(ports), f"{name}: ports were not immediately reusable: {ports!r}"
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
python3 /harness/test_guard_job_control.py

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

assert_claude_version_rejected() {
  mode=$1
  expected_error=$2
  stderr_file="/tmp/claude-version-${mode}.stderr"
  version_marker="/tmp/claude-version-${mode}.called"
  auth_marker="/tmp/claude-version-${mode}-auth.called"
  pid_file="/tmp/claude-version-${mode}.pid"
  rm -f "$stderr_file" "$version_marker" "$auth_marker" "$pid_file"
  observations_before=$(observer_count)
  status=0
  HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
    PROMTECT_CLAUDE_VERSION_MODE="$mode" \
    PROMTECT_CLAUDE_VERSION_MARKER="$version_marker" \
    PROMTECT_CLAUDE_VERSION_PID="$pid_file" \
    PROMTECT_CLAUDE_AUTH_STATUS_MARKER="$auth_marker" \
    PROMTECT_AUDIT="/tmp/claude-version-${mode}-audit.jsonl" \
    PROMTECT_DASHBOARD_PORT=18998 \
    promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > "/tmp/claude-version-${mode}.stdout" 2> "$stderr_file" || status=$?
  if [ "$status" -ne 1 ]; then
    printf 'FAIL Claude guard: %s version preflight returned %s instead of 1\n' \
      "$mode" "$status" >&2
    exit 1
  fi
  if [ ! -e "$version_marker" ] || [ -e "$auth_marker" ]; then
    printf 'FAIL Claude guard: %s version preflight did not stop before auth status\n' \
      "$mode" >&2
    exit 1
  fi
  observations_after=$(observer_count)
  if [ "$observations_before" -ne "$observations_after" ]; then
    printf 'FAIL Claude guard: %s version preflight reached the provider\n' "$mode" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_error" "$stderr_file" \
    || grep -Eq 'proxy 127\.0\.0\.1:|dashboard: http://127\.0\.0\.1:' "$stderr_file"; then
    printf 'FAIL Claude guard: %s version preflight was not bounded before bind\n' \
      "$mode" >&2
    sed -n '1,80p' "$stderr_file" >&2
    exit 1
  fi
  if [ "$(wc -c < "$stderr_file")" -gt 4096 ]; then
    printf 'FAIL Claude guard: %s version error output was unbounded\n' "$mode" >&2
    exit 1
  fi
  if [ -e "$pid_file" ]; then
    assert_process_gone "Claude guard $mode version preflight" "$(cat "$pid_file")"
  fi
  printf 'PASS Claude guard: %s version preflight failed before auth, bind, or provider\n' \
    "$mode"
}

assert_claude_version_rejected nonzero 'Claude version preflight failed'
assert_claude_version_rejected oversized 'Claude version preflight output exceeded its safety limit'
assert_claude_version_rejected hanging 'Claude version preflight timed out'

printf '%s\n' \
  '{' \
  '  "env": {' \
  '    "ANTHROPIC_BASE_URL": "http://mock-provider:9000/claude-bypass",' \
  '    "ANTHROPIC_API_KEY": "fixed-dummy-persisted-key",' \
  '    "CLAUDE_CODE_SAFE_MODE": "1",' \
  '    "CLAUDE_CODE_USE_BEDROCK": "1",' \
  '    "CLAUDE_CODE_USE_VERTEX": "1",' \
  '    "CLAUDE_CODE_USE_FOUNDRY": "1",' \
  '    "CLAUDE_CODE_USE_MANTLE": "1",' \
  '    "CLAUDE_CODE_USE_ANTHROPIC_AWS": "1",' \
  '    "CLAUDE_CODE_USE_GATEWAY": "1",' \
  '    "ANTHROPIC_UNIX_SOCKET": "/tmp/promtect-bypass.sock",' \
  '    "ANTHROPIC_BEDROCK_BASE_URL": "http://mock-provider:9000/claude-bypass",' \
  '    "AWS_ACCESS_KEY_ID": "fixed-dummy-access-key",' \
  '    "AWS_SECRET_ACCESS_KEY": "fixed-dummy-secret-key",' \
  '    "AWS_REGION": "us-east-1"' \
  '  }' \
  '}' \
  > /tmp/claude-guard/settings.json
printf '%s\n' \
  '{"claudeAiOauth":{"accessToken":"fixed-dummy-oauth-token","refreshToken":"fixed-dummy-refresh-token","expiresAt":4102444800000,"scopes":["user:inference"]}}' \
  > /tmp/claude-guard/.credentials.json

assert_claude_env_auth_rejected() {
  auth_var=$1
  auth_value=$2
  stderr_file=$3
  rm -f /tmp/claude-auth-status.called "$stderr_file"
  observations_before=$(observer_count)
  status=0
  env "$auth_var=$auth_value" \
    HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
    PROMTECT_CLAUDE_AUTH_STATUS_MARKER=/tmp/claude-auth-status.called \
    PROMTECT_AUDIT=/tmp/claude-auth-reject-audit.jsonl \
    PROMTECT_DASHBOARD_PORT=18998 \
    promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > /tmp/claude-auth-reject.stdout 2> "$stderr_file" || status=$?
  if [ "$status" -ne 1 ]; then
    printf 'FAIL Claude guard: %s override returned %s instead of 1\n' "$auth_var" "$status" >&2
    exit 1
  fi
  if [ -e /tmp/claude-auth-status.called ]; then
    printf 'FAIL Claude guard: %s override reached auth status preflight\n' "$auth_var" >&2
    exit 1
  fi
  observations_after=$(observer_count)
  if [ "$observations_before" -ne "$observations_after" ]; then
    printf 'FAIL Claude guard: %s override reached the provider\n' "$auth_var" >&2
    exit 1
  fi
  if ! grep -Fq "$auth_var" "$stderr_file" \
    || ! grep -Fq 'verified stored individual Max credential' "$stderr_file"; then
    printf 'FAIL Claude guard: %s rejection was not actionable\n' "$auth_var" >&2
    exit 1
  fi
  if { [ -n "$auth_value" ] && grep -Fq "$auth_value" "$stderr_file"; } \
    || grep -Fq 'proxy 127.0.0.1:' "$stderr_file" \
    || grep -Fq 'dashboard: http://127.0.0.1:' "$stderr_file"; then
    printf 'FAIL Claude guard: %s rejection leaked a value or bound a listener\n' "$auth_var" >&2
    exit 1
  fi
  if [ "$(wc -c < "$stderr_file")" -gt 4096 ]; then
    printf 'FAIL Claude guard: %s rejection output was unbounded\n' "$auth_var" >&2
    exit 1
  fi
  printf 'PASS Claude guard: %s environment auth rejected before bind and auth status\n' "$auth_var"
}

assert_claude_env_auth_rejected \
  ANTHROPIC_API_KEY fixed-synthetic-api-key /tmp/claude-auth-api.stderr
assert_claude_env_auth_rejected \
  CLAUDE_CODE_OAUTH_TOKEN fixed-synthetic-oauth-token /tmp/claude-auth-oauth.stderr
assert_claude_env_auth_rejected \
  ANTHROPIC_API_KEY '' /tmp/claude-auth-empty.stderr

assert_claude_runtime_override_rejected() {
  runtime_var=$1
  stderr_file=$2
  rm -f /tmp/claude-auth-status.called "$stderr_file"
  observations_before=$(observer_count)
  status=0
  env "$runtime_var=" \
    HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
    PROMTECT_CLAUDE_AUTH_STATUS_MARKER=/tmp/claude-auth-status.called \
    PROMTECT_AUDIT=/tmp/claude-runtime-reject-audit.jsonl \
    PROMTECT_DASHBOARD_PORT=18998 \
    promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > /tmp/claude-runtime-reject.stdout 2> "$stderr_file" || status=$?
  if [ "$status" -ne 1 ]; then
    printf 'FAIL Claude guard: %s override returned %s instead of 1\n' \
      "$runtime_var" "$status" >&2
    exit 1
  fi
  if [ -e /tmp/claude-auth-status.called ]; then
    printf 'FAIL Claude guard: %s override reached auth status preflight\n' \
      "$runtime_var" >&2
    exit 1
  fi
  observations_after=$(observer_count)
  if [ "$observations_before" -ne "$observations_after" ]; then
    printf 'FAIL Claude guard: %s override reached the provider\n' "$runtime_var" >&2
    exit 1
  fi
  if ! grep -Fq "$runtime_var" "$stderr_file" \
    || ! grep -Fq 'cannot verify protected routing and the automatic notice' "$stderr_file"; then
    printf 'FAIL Claude guard: %s rejection was not actionable\n' "$runtime_var" >&2
    sed -n '1,80p' "$stderr_file" >&2
    exit 1
  fi
  if grep -Eq 'proxy 127\.0\.0\.1:|dashboard: http://127\.0\.0\.1:' "$stderr_file"; then
    printf 'FAIL Claude guard: %s rejection occurred after a listener bind\n' \
      "$runtime_var" >&2
    exit 1
  fi
  if [ "$(wc -c < "$stderr_file")" -gt 4096 ]; then
    printf 'FAIL Claude guard: %s rejection output was unbounded\n' "$runtime_var" >&2
    exit 1
  fi
  printf 'PASS Claude guard: %s rejected before auth status, bind, or provider traffic\n' \
    "$runtime_var"
}

for runtime_var in \
  CLAUDE_CODE_SAFE_MODE \
  CLAUDE_CODE_SIMPLE \
  CLAUDE_CODE_MANAGED_SETTINGS_PATH \
  CLAUDE_CODE_REMOTE_SETTINGS_PATH \
  CLAUDE_CODE_MOCK_REMOTE_SETTINGS \
  CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST \
  CLAUDE_CODE_HOST_AUTH_ENV_VAR \
  CLAUDE_CODE_HOST_CREDS_FILE
do
  assert_claude_runtime_override_rejected \
    "$runtime_var" "/tmp/claude-runtime-${runtime_var}.stderr"
done

assert_claude_arg_rejected() {
  name=$1
  shift
  stderr_file="/tmp/claude-arg-rejected-${name}.stderr"
  rm -f /tmp/claude-auth-status.called "$stderr_file"
  observations_before=$(observer_count)
  status=0
  HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
    PROMTECT_CLAUDE_AUTH_STATUS_MARKER=/tmp/claude-auth-status.called \
    promtect guard claude --upstream http://mock-provider:9000/guard-claude -- \
      "$@" > "/tmp/claude-arg-rejected-${name}.stdout" 2> "$stderr_file" || status=$?
  if [ "$status" -eq 0 ]; then
    printf 'FAIL Claude guard: unsafe %s argument was accepted\n' "$name" >&2
    exit 1
  fi
  if [ -e /tmp/claude-auth-status.called ]; then
    printf 'FAIL Claude guard: unsafe %s argument reached auth status\n' "$name" >&2
    exit 1
  fi
  observations_after=$(observer_count)
  if [ "$observations_before" -ne "$observations_after" ]; then
    printf 'FAIL Claude guard: unsafe %s argument reached the provider\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq 'protected routing or automatic notice' "$stderr_file" \
    || grep -Eq 'proxy 127\.0\.0\.1:|dashboard: http://127\.0\.0\.1:' "$stderr_file"; then
    printf 'FAIL Claude guard: unsafe %s argument was not rejected before bind\n' "$name" >&2
    sed -n '1,80p' "$stderr_file" >&2
    exit 1
  fi
  printf 'PASS Claude guard: unsafe %s argument rejected before auth, bind, or provider\n' \
    "$name"
}

assert_claude_arg_rejected managed-settings-separated --managed-settings '{}'
assert_claude_arg_rejected managed-settings-attached '--managed-settings={}'
assert_claude_arg_rejected ultrareview ultrareview
assert_claude_arg_rejected tmux-attached '--tmux=classic'
assert_claude_arg_rejected worktree-attached '--worktree=demo'
assert_claude_arg_rejected worktree-short -w demo
assert_claude_arg_rejected remote-control-attached '--remote-control=demo'

assert_claude_auth_status_rejected() {
  mode=$1
  expected_error=$2
  stderr_file="/tmp/claude-auth-status-${mode}.stderr"
  marker_file="/tmp/claude-auth-status-${mode}.called"
  pid_file="/tmp/claude-auth-status-${mode}.pid"
  rm -f "$stderr_file" "$marker_file" "$pid_file"
  observations_before=$(observer_count)
  HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
    PROMTECT_CLAUDE_AUTH_STATUS_MODE="$mode" \
    PROMTECT_CLAUDE_AUTH_STATUS_MARKER="$marker_file" \
    PROMTECT_CLAUDE_AUTH_STATUS_PID="$pid_file" \
    PROMTECT_AUDIT="/tmp/claude-auth-status-${mode}-audit.jsonl" \
    PROMTECT_DASHBOARD_PORT=18998 \
    promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > "/tmp/claude-auth-status-${mode}.stdout" 2> "$stderr_file" &
  guard_pid=$!
  completed=0
  for _ in $(seq 1 160); do
    if ! kill -0 "$guard_pid" 2>/dev/null; then
      completed=1
      break
    fi
    sleep 0.05
  done
  if [ "$completed" -ne 1 ]; then
    kill -TERM "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
    printf 'FAIL Claude guard: %s auth status was not bounded to eight seconds\n' "$mode" >&2
    exit 1
  fi
  status=0
  wait "$guard_pid" || status=$?
  if [ "$status" -ne 1 ]; then
    printf 'FAIL Claude guard: %s auth status returned %s instead of 1\n' \
      "$mode" "$status" >&2
    exit 1
  fi
  if [ ! -e "$marker_file" ]; then
    printf 'FAIL Claude guard: %s fixture did not reach auth status\n' "$mode" >&2
    exit 1
  fi
  observations_after=$(observer_count)
  if [ "$observations_before" -ne "$observations_after" ]; then
    printf 'FAIL Claude guard: %s auth status reached the provider\n' "$mode" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_error" "$stderr_file"; then
    printf 'FAIL Claude guard: %s auth status lacked its bounded error\n' "$mode" >&2
    sed -n '1,80p' "$stderr_file" >&2
    exit 1
  fi
  if grep -Eq 'proxy 127\.0\.0\.1:|dashboard: http://127\.0\.0\.1:' "$stderr_file"; then
    printf 'FAIL Claude guard: %s auth status reached a listener bind\n' "$mode" >&2
    exit 1
  fi
  if [ "$(wc -c < "$stderr_file")" -gt 4096 ]; then
    printf 'FAIL Claude guard: %s auth status error output was unbounded\n' "$mode" >&2
    exit 1
  fi
  if [ -e "$pid_file" ]; then
    assert_process_gone "Claude guard $mode auth status" "$(cat "$pid_file")"
  fi
  printf 'PASS Claude guard: %s auth status failed closed before bind or provider traffic\n' \
    "$mode"
}

assert_claude_auth_status_rejected malformed 'Claude auth status did not return valid JSON'
assert_claude_auth_status_rejected nonzero 'Claude auth preflight failed'
assert_claude_auth_status_rejected oversized 'Claude auth preflight output exceeded its safety limit'
assert_claude_auth_status_rejected hanging 'Claude auth preflight timed out'

claude_before=$(observer_count)
rm -f /tmp/claude-guard-hold.ready /tmp/claude-guard-hold.release \
  /tmp/claude-guard-second.debug.log
HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
  HTTP_PROXY=http://mock-provider:9000/claude-bypass \
  HTTPS_PROXY=http://mock-provider:9000/claude-bypass \
  ALL_PROXY=http://mock-provider:9000/claude-bypass \
  http_proxy=http://mock-provider:9000/claude-bypass \
  https_proxy=http://mock-provider:9000/claude-bypass \
  all_proxy=http://mock-provider:9000/claude-bypass NO_PROXY= no_proxy= \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  PROMTECT_CLAUDE_TWO_TURN=1 \
  PROMTECT_CLAUDE_SECOND_PROMPT="$CLAUDE_FOUR_PROMPT" \
  PROMTECT_CLAUDE_HOLD_READY=/tmp/claude-guard-hold.ready \
  PROMTECT_CLAUDE_HOLD_RELEASE=/tmp/claude-guard-hold.release \
  PROMTECT_AUDIT=/tmp/claude-guard-audit.jsonl PROMTECT_DASHBOARD_PORT=18999 \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude -- \
    --debug-file /tmp/claude-guard.debug.log \
    --print --output-format text "$CLAUDE_FOUR_PROMPT" \
    > /tmp/claude-guard.stdout 2> /tmp/claude-guard.stderr &
claude_guard_pid=$!
for _ in $(seq 1 400); do
  if [ -e /tmp/claude-guard-hold.ready ]; then
    break
  fi
  if ! kill -0 "$claude_guard_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if [ ! -e /tmp/claude-guard-hold.ready ]; then
  printf 'FAIL Claude guard: hostile persisted settings prevented protected execution\n' >&2
  sed -n '1,120p' /tmp/claude-guard.stderr >&2
  wait "$claude_guard_pid" 2>/dev/null || true
  exit 1
fi

dashboard_port=$(sed -n 's/.*dashboard: http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' \
  /tmp/claude-guard.stderr | head -n 1)
python3 - "$dashboard_port" <<'PY'
import json
import sys
import urllib.request

port = int(sys.argv[1])
with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/metrics", timeout=5) as response:
    metrics = json.load(response)
expected = {"aws_key", "anthropic_key", "github_token", "stripe_key"}
assert metrics["secrets_masked_total"] == 8, metrics
assert metrics["restore_enabled"] is True, metrics
assert {kind for kind in expected if metrics["by_detector"].get(kind) == 2} == expected, metrics
PY
touch /tmp/claude-guard-hold.release
if ! wait "$claude_guard_pid"; then
  printf 'FAIL Claude guard: two-turn protected execution exited nonzero\n' >&2
  sed -n '1,160p' /tmp/claude-guard.stderr >&2
  exit 1
fi
claude_after=$(observer_count)
assert_claude_guard_observation_window "$claude_before" "$claude_after"
assert_output_restored "Claude guard with hostile persisted settings" /tmp/claude-guard.stdout
assert_claude_notice \
  /tmp/claude-guard.stdout /tmp/claude-guard.stderr /tmp/claude-guard.debug.log
assert_claude_notice \
  /tmp/claude-guard.stdout /tmp/claude-guard.stderr /tmp/claude-guard-second.debug.log
if ! grep -Fq 'this session masked 8 secrets' /tmp/claude-guard.stderr; then
  printf 'FAIL Claude guard: value-free masking summary was absent\n' >&2
  sed -n '1,120p' /tmp/claude-guard.stderr >&2
  exit 1
fi
assert_guard_listener_teardown "Claude guard" /tmp/claude-guard.stderr
printf 'PASS Claude guard: two value-free Stop-hook notices stayed out of both model turns\n'
printf 'PASS Claude guard: live dashboard reported all four detector kinds and eight masks\n'
printf 'PASS Claude guard: inherited proxy variables could not bypass the loopback proxy\n'
printf 'PASS Claude guard: persisted base URL, socket, and provider selectors could not bypass Promtect\n'

rm -f /tmp/claude-stream-signal.ready /tmp/claude-stream-signal.prefix \
  /tmp/claude-stream-signal-audit.jsonl /tmp/claude-stream-signal.stdout \
  /tmp/claude-stream-signal.stderr
claude_stream_before=$(observer_count)
HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  PROMTECT_CLAUDE_STREAM_SIGNAL=1 \
  PROMTECT_AUDIT=/tmp/claude-stream-signal-audit.jsonl \
  PROMTECT_DASHBOARD_PORT=18993 \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude \
    --port 18992 -- --version \
    > /tmp/claude-stream-signal.stdout 2> /tmp/claude-stream-signal.stderr &
claude_stream_guard_pid=$!
for _ in $(seq 1 200); do
  if [ -e /tmp/claude-stream-signal.ready ]; then
    break
  fi
  if ! kill -0 "$claude_stream_guard_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if [ ! -e /tmp/claude-stream-signal.ready ]; then
  printf 'FAIL Claude guard: split-sentinel shutdown fixture did not reach an in-flight response\n' >&2
  sed -n '1,120p' /tmp/claude-stream-signal.stderr >&2
  wait "$claude_stream_guard_pid" 2>/dev/null || true
  exit 1
fi
kill -TERM "$claude_stream_guard_pid"
claude_stream_status=0
wait "$claude_stream_guard_pid" || claude_stream_status=$?
if [ "$claude_stream_status" -eq 0 ]; then
  printf 'FAIL Claude guard: signaled split-sentinel fixture exited successfully\n' >&2
  exit 1
fi
claude_stream_after=$(observer_count)
assert_claude_single_observation_window \
  "$claude_stream_before" "$claude_stream_after"
python3 - /tmp/claude-stream-signal-audit.jsonl \
  /tmp/claude-stream-signal.prefix "$SECRET" <<'PY'
import json
import pathlib
import sys

audit_path, prefix_path, secret = sys.argv[1:]
raw = pathlib.Path(audit_path).read_text()
assert secret not in raw, "stream shutdown audit retained the synthetic canary"
events = [json.loads(line) for line in raw.splitlines() if line.strip()]
cancelled = [event for event in events if event.get("action") == "stream_cancelled"]
assert cancelled, f"signaled in-flight response lacked stream_cancelled evidence: {events!r}"
assert all(event.get("detector") == "downstream" for event in cancelled), cancelled
prefix = pathlib.Path(prefix_path).read_bytes()
assert b"promtect:" not in prefix and secret.encode() not in prefix, prefix
PY
assert_ports_reusable "Claude guard split-sentinel shutdown" 18992 18993
printf 'PASS Claude guard: signaled split-sentinel response recorded value-free cancellation evidence\n'

rm -f /tmp/claude-normal-exit.ready /tmp/claude-normal-exit.helper.pid \
  /tmp/claude-normal-exit.settings /tmp/claude-normal-exit.stdout \
  /tmp/claude-normal-exit.stderr
claude_normal_before=$(observer_count)
HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  PROMTECT_CLAUDE_EXIT_WITH_HELPER=1 \
  PROMTECT_CLAUDE_HELPER_PID=/tmp/claude-normal-exit.helper.pid \
  PROMTECT_CLAUDE_SETTINGS_PATH=/tmp/claude-normal-exit.settings \
  PROMTECT_CLAUDE_HELPER_READY=/tmp/claude-normal-exit.ready \
  PROMTECT_AUDIT=/tmp/claude-normal-exit-audit.jsonl \
  PROMTECT_DASHBOARD_PORT=18997 \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude \
    --port 18996 -- --version \
    > /tmp/claude-normal-exit.stdout 2> /tmp/claude-normal-exit.stderr
claude_normal_after=$(observer_count)
if [ ! -e /tmp/claude-normal-exit.ready ] \
  || [ ! -s /tmp/claude-normal-exit.helper.pid ] \
  || [ ! -s /tmp/claude-normal-exit.settings ]; then
  printf 'FAIL Claude guard: normal-exit descendant fixture did not run\n' >&2
  sed -n '1,120p' /tmp/claude-normal-exit.stderr >&2
  exit 1
fi
if [ "$claude_normal_before" -ne "$claude_normal_after" ]; then
  printf 'FAIL Claude guard: normal-exit fixture unexpectedly reached the provider\n' >&2
  exit 1
fi
claude_normal_helper_pid=$(cat /tmp/claude-normal-exit.helper.pid)
claude_normal_settings=$(cat /tmp/claude-normal-exit.settings)
assert_process_gone "Claude guard normal-exit helper" "$claude_normal_helper_pid"
if [ -e "$claude_normal_settings" ] || [ -d "$(dirname "$claude_normal_settings")" ]; then
  printf 'FAIL Claude guard: owner-only temporary settings survived normal child exit\n' >&2
  exit 1
fi
assert_guard_listener_teardown "Claude guard normal child exit" \
  /tmp/claude-normal-exit.stderr
assert_ports_reusable "Claude guard normal child exit" 18996 18997
printf 'PASS Claude guard: normal child exit stopped its helper and released proxy/dashboard ports\n'

rm -f /tmp/claude-sigterm.ready /tmp/claude-sigterm.child.pid \
  /tmp/claude-sigterm.grandchild.pid \
  /tmp/claude-sigterm.settings /tmp/claude-sigterm.stdout /tmp/claude-sigterm.stderr
HOME=/tmp/claude-guard CLAUDE_CONFIG_DIR=/tmp/claude-guard \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_UPDATES=1 \
  PROMTECT_CLAUDE_HOLD_ONLY=1 \
  PROMTECT_CLAUDE_HOLD_PID=/tmp/claude-sigterm.child.pid \
  PROMTECT_CLAUDE_HOLD_GRANDCHILD_PID=/tmp/claude-sigterm.grandchild.pid \
  PROMTECT_CLAUDE_SETTINGS_PATH=/tmp/claude-sigterm.settings \
  PROMTECT_CLAUDE_HOLD_READY=/tmp/claude-sigterm.ready \
  PROMTECT_AUDIT=/tmp/claude-sigterm-audit.jsonl PROMTECT_DASHBOARD_PORT=18999 \
  promtect guard claude --upstream http://mock-provider:9000/guard-claude -- --version \
    > /tmp/claude-sigterm.stdout 2> /tmp/claude-sigterm.stderr &
claude_sigterm_guard_pid=$!
for _ in $(seq 1 200); do
  if [ -e /tmp/claude-sigterm.ready ]; then
    break
  fi
  if ! kill -0 "$claude_sigterm_guard_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if [ ! -e /tmp/claude-sigterm.ready ]; then
  printf 'FAIL Claude guard: SIGTERM fixture did not start\n' >&2
  sed -n '1,120p' /tmp/claude-sigterm.stderr >&2
  wait "$claude_sigterm_guard_pid" 2>/dev/null || true
  exit 1
fi
claude_sigterm_child_pid=$(cat /tmp/claude-sigterm.child.pid)
claude_sigterm_grandchild_pid=$(cat /tmp/claude-sigterm.grandchild.pid)
claude_sigterm_settings=$(cat /tmp/claude-sigterm.settings)
kill -TERM "$claude_sigterm_guard_pid"
claude_sigterm_status=0
wait "$claude_sigterm_guard_pid" || claude_sigterm_status=$?
if [ "$claude_sigterm_status" -ne 143 ]; then
  printf 'FAIL Claude guard: SIGTERM returned %s instead of child termination status 143\n' \
    "$claude_sigterm_status" >&2
  sed -n '1,120p' /tmp/claude-sigterm.stderr >&2
  exit 1
fi
python3 - "$claude_sigterm_child_pid" "$claude_sigterm_grandchild_pid" <<'PY'
import pathlib
import sys
import time

def live(pid):
    path = pathlib.Path(f"/proc/{pid}/stat")
    try:
        stat = path.read_text()
    except FileNotFoundError:
        return False
    close = stat.rfind(")")
    return close < 0 or stat[close + 2 :].split()[0] != "Z"

pids = [int(value) for value in sys.argv[1:]]
for _ in range(50):
    if not any(live(pid) for pid in pids):
        break
    time.sleep(0.02)
else:
    raise AssertionError(f"guarded Claude process tree survived SIGTERM: {pids!r}")
PY
if [ -e "$claude_sigterm_settings" ] || [ -d "$(dirname "$claude_sigterm_settings")" ]; then
  printf 'FAIL Claude guard: owner-only temporary settings survived Promtect SIGTERM\n' >&2
  exit 1
fi
if ! grep -Fq 'shutdown requested; stopping the guarded tool' /tmp/claude-sigterm.stderr; then
  printf 'FAIL Claude guard: SIGTERM shutdown was not reported\n' >&2
  exit 1
fi
assert_guard_listener_teardown "Claude guard SIGTERM" /tmp/claude-sigterm.stderr
printf 'PASS Claude guard: SIGTERM stopped child and grandchild, listeners, and temporary settings\n'

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
