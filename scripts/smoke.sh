#!/usr/bin/env bash
# Proves the built binary masks secrets and writes a value-free audit log.
set -euo pipefail
PORT="${PORT:-18787}"
AUDIT="$(mktemp -t airlock-smoke.XXXXXX.jsonl)"
cargo build -q
AIRLOCK_UPSTREAM=http://127.0.0.1:9 AIRLOCK_AUDIT="$AUDIT" AIRLOCK_PORT="$PORT" \
  ./target/debug/airlock >/tmp/airlock-smoke.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -f "$AUDIT"' EXIT
code=$(curl -s --retry 15 --retry-connrefused --retry-delay 1 -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/messages" -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}')
echo "http_code=$code (expect 502, dead upstream)"
grep -q '"action":"mask"' "$AUDIT" && echo "PASS: mask event logged" || { echo "FAIL: no mask event"; exit 1; }
if grep -q 'AKIAIOSFODNN7EXAMPLE' "$AUDIT"; then echo "FAIL: secret leaked into audit"; exit 1; else echo "PASS: no secret in audit"; fi
