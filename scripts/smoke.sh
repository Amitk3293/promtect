#!/usr/bin/env bash
# Proves the built binary masks secrets and writes a value-free audit log.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-18787}"
AUDIT="$(mktemp -t promtect-smoke.XXXXXX.jsonl)"
LOG="$(mktemp -t promtect-smoke-log.XXXXXX)"
PID=""
trap 'kill "$PID" 2>/dev/null || true; rm -f "$AUDIT" "$LOG"' EXIT

cargo build -q
PROMTECT_UPSTREAM=http://127.0.0.1:9 PROMTECT_AUDIT="$AUDIT" PROMTECT_PORT="$PORT" \
  ./target/debug/promtect >"$LOG" 2>&1 &
PID=$!
disown "$PID" 2>/dev/null || true # keep job-control "Terminated" noise out of CI output

# Wait for the proxy to actually accept connections (up to ~20s) instead of racing
# curl against startup. If the proxy exits early, fail with its log — a clear
# signal, not a mystery empty curl code.
ready=""
for _ in $(seq 1 40); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "FAIL: proxy exited before binding"; cat "$LOG"; exit 1
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then exec 3>&- 3<&-; ready=1; break; fi
  sleep 0.5
done
[ -n "$ready" ] || { echo "FAIL: proxy never bound on ${PORT}"; cat "$LOG"; exit 1; }

code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/messages" -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}' || true)
echo "http_code=$code (expect 502, dead upstream)"
# Assert the proxy's HTTP-forwarding contract: a dead upstream must produce a
# clean 502, not a 200/hang/panic. This catches regressions where the proxy
# swallows the error or returns a wrong status.
[ "$code" = "502" ] || { echo "FAIL: expected 502 from dead upstream, got '$code'"; cat "$LOG"; exit 1; }
grep -q '"action":"mask"' "$AUDIT" && echo "PASS: mask event logged" || { echo "FAIL: no mask event"; exit 1; }
if grep -q 'AKIAIOSFODNN7EXAMPLE' "$AUDIT"; then echo "FAIL: secret leaked into audit"; exit 1; else echo "PASS: no secret in audit"; fi
