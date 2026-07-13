#!/bin/sh
set -eu

if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  if [ -n "${PROMTECT_CLAUDE_AUTH_STATUS_MARKER:-}" ]; then
    : > "$PROMTECT_CLAUDE_AUTH_STATUS_MARKER"
  fi
  printf '%s\n' '{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","apiProvider":"firstParty","organizationType":null}'
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
