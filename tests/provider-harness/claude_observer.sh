#!/bin/sh
set -eu

if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  if [ -n "${PROMTECT_CLAUDE_AUTH_STATUS_MARKER:-}" ]; then
    : > "$PROMTECT_CLAUDE_AUTH_STATUS_MARKER"
  fi
  case "${PROMTECT_CLAUDE_AUTH_STATUS_MODE:-valid}" in
    valid)
      printf '%s\n' '{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","apiProvider":"firstParty","organizationType":null}'
      exit 0
      ;;
    malformed)
      printf '%s\n' 'not-json synthetic auth status'
      exit 0
      ;;
    nonzero)
      printf '%s\n' 'synthetic auth status failure' >&2
      exit 42
      ;;
    oversized)
      python3 - <<'PY'
import sys

sys.stdout.write("x" * (64 * 1024 + 1))
PY
      exit 0
      ;;
    hanging)
      if [ -n "${PROMTECT_CLAUDE_AUTH_STATUS_PID:-}" ]; then
        printf '%s\n' "$$" > "$PROMTECT_CLAUDE_AUTH_STATUS_PID"
      fi
      exec sleep 300
      ;;
    *)
      printf 'unknown synthetic auth status mode\n' >&2
      exit 2
      ;;
  esac
fi

# The named guard pins the installed Claude version before auth or listener
# setup. Fixture modes apply only to the later guard-owned --settings launch.
if [ "${1:-}" = "--version" ] && [ "$#" -eq 1 ]; then
  exec /opt/provider-clis/node_modules/.bin/claude "$@"
fi

if [ "${PROMTECT_CLAUDE_STREAM_SIGNAL:-}" = "1" ]; then
  exec python3 - "${ANTHROPIC_BASE_URL:?missing guarded Claude base URL}" <<'PY'
import http.client
import json
import pathlib
import sys
import urllib.parse

base = urllib.parse.urlparse(sys.argv[1])
connection = http.client.HTTPConnection(base.hostname, base.port, timeout=30)
body = json.dumps(
    {
        "model": "synthetic-model",
        "max_tokens": 64,
        "messages": [
            {
                "role": "user",
                "content": "Return this fixed synthetic canary: AKIAIOSFODNN7EXAMPLE",
            }
        ],
    }
).encode()
connection.request(
    "POST",
    "/v1/messages?scenario=timeout",
    body=body,
    headers={"content-type": "application/json"},
)
response = connection.getresponse()
if response.status != 200:
    raise SystemExit(f"synthetic streaming fixture returned {response.status}")
first = response.read(1)
if not first:
    raise SystemExit("synthetic streaming fixture returned no safe prefix")
pathlib.Path("/tmp/claude-stream-signal.prefix").write_bytes(first)
pathlib.Path("/tmp/claude-stream-signal.ready").touch()
while response.read(1):
    pass
PY
fi

if [ "${PROMTECT_CLAUDE_EXIT_WITH_HELPER:-}" = "1" ]; then
  if [ "${1:-}" != "--settings" ] || [ -z "${2:-}" ]; then
    printf 'Claude observer expected guard-owned --settings path\n' >&2
    exit 1
  fi
  sleep 300 &
  helper=$!
  printf '%s\n' "$helper" > "${PROMTECT_CLAUDE_HELPER_PID:?missing helper PID path}"
  printf '%s\n' "$2" > "${PROMTECT_CLAUDE_SETTINGS_PATH:?missing settings path capture}"
  : > "${PROMTECT_CLAUDE_HELPER_READY:?missing helper-ready path}"
  exit 0
fi

if [ "${PROMTECT_CLAUDE_HOLD_ONLY:-}" = "1" ]; then
  if [ "${1:-}" != "--settings" ] || [ -z "${2:-}" ]; then
    printf 'Claude observer expected guard-owned --settings path\n' >&2
    exit 1
  fi
  printf '%s\n' "$$" > "${PROMTECT_CLAUDE_HOLD_PID:?missing hold PID path}"
  sleep 300 &
  grandchild=$!
  printf '%s\n' "$grandchild" > "${PROMTECT_CLAUDE_HOLD_GRANDCHILD_PID:?missing grandchild PID path}"
  printf '%s\n' "$2" > "${PROMTECT_CLAUDE_SETTINGS_PATH:?missing settings path capture}"
  : > "${PROMTECT_CLAUDE_HOLD_READY:?missing hold-ready path}"
  wait "$grandchild"
  exit $?
fi

if [ "${PROMTECT_CLAUDE_TWO_TURN:-}" = "1" ]; then
  /opt/provider-clis/node_modules/.bin/claude "$@"
  first_status=$?
  if [ "$first_status" -ne 0 ]; then
    exit "$first_status"
  fi
  if [ "${1:-}" != "--settings" ] || [ -z "${2:-}" ]; then
    printf 'Claude observer expected guard-owned --settings path\n' >&2
    exit 1
  fi
  /opt/provider-clis/node_modules/.bin/claude \
    --settings "$2" \
    --debug-file /tmp/claude-guard-second.debug.log \
    --continue --print --output-format text \
    "${PROMTECT_CLAUDE_SECOND_PROMPT:?missing second prompt}"
  second_status=$?
  : > "${PROMTECT_CLAUDE_HOLD_READY:?missing hold-ready path}"
  while [ ! -e "${PROMTECT_CLAUDE_HOLD_RELEASE:?missing hold-release path}" ]; do
    sleep 0.05
  done
  exit "$second_status"
fi

exec /opt/provider-clis/node_modules/.bin/claude "$@"
