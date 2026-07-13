#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

if command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  compose() { docker compose "$@"; }
fi

cleanup() {
  compose -f "$COMPOSE_FILE" down --volumes --remove-orphans
}
trap cleanup EXIT INT TERM

compose -f "$COMPOSE_FILE" up \
  --build --abort-on-container-exit --exit-code-from runner
