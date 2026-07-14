#!/bin/sh
set -eu

role=model-call
previous=
for arg in "$@"; do
  if [ "$previous $arg" = "login status" ]; then role=login-status; fi
  if [ "$previous $arg" = "debug models" ]; then role=debug-models; fi
  previous=$arg
done

if [ -n "${CODEX_ENV_CAPTURE-}" ]; then
  {
    printf 'BEGIN role=%s\n' "$role"
    for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy \
      WS_PROXY WSS_PROXY ws_proxy wss_proxy NO_PROXY no_proxy; do
      eval "value=\${$key-__UNSET__}"
      printf '%s=%s\n' "$key" "$value"
    done
    printf 'END\n'
  } >> "$CODEX_ENV_CAPTURE"
fi

if [ -n "${CODEX_PID_CAPTURE-}" ]; then
  printf '%s\n' "$$" >> "$CODEX_PID_CAPTURE"
fi

if [ "${CODEX_FAKE_FAILED_STATUS-}" = 1 ] && [ "$role" = login-status ]; then
  printf 'Logged in using an API key\n'
  exit 1
fi

if [ "${CODEX_FAKE_CHATGPT_STATUS-}" = stdout ] && [ "$role" = login-status ]; then
  printf 'Logged in using ChatGPT\n'
  exit 0
fi

if [ "${CODEX_FAKE_CHATGPT_STATUS-}" = stderr ] && [ "$role" = login-status ]; then
  printf 'Logged in using ChatGPT\n' >&2
  exit 0
fi

if [ -n "${CODEX_FAKE_OVERSIZED_STATUS-}" ] && [ "$role" = login-status ]; then
  stream=${CODEX_FAKE_OVERSIZED_STATUS}
  case "$stream" in
    stdout|stderr) ;;
    *) printf 'unknown oversized status stream\n' >&2; exit 2 ;;
  esac
  exec python3 - "$stream" <<'PY'
import sys
import time

stream = sys.stdout if sys.argv[1] == "stdout" else sys.stderr
stream.write("x" * (64 * 1024 + 1))
stream.flush()
time.sleep(300)
PY
fi

exec /opt/provider-clis/node_modules/.bin/codex "$@"
