#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
else
  compose=(docker-compose)
fi

cleanup() {
  "${compose[@]}" -f docker-compose.yml down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" -f docker-compose.yml up --build --abort-on-container-exit --exit-code-from browser
