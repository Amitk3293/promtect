#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
base="$root/tests/provider-harness/docker-compose.yml"
interactive="$root/tests/provider-harness/docker-compose.interactive.yml"
project="promtect-claude-interactive-$$"
credential_volume="${project}_claude-auth"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  if ! docker-compose -p "$project" -f "$base" -f "$interactive" \
    down --volumes --remove-orphans >/dev/null; then
    cleanup_failed=1
  fi
  if docker volume inspect "$credential_volume" >/dev/null 2>&1; then
    if ! docker volume rm "$credential_volume" >/dev/null; then
      cleanup_failed=1
    fi
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    printf 'WARNING: credential cleanup failed; remove Docker volume %s manually\n' \
      "$credential_volume" >&2
    if [ "$status" -eq 0 ]; then
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker-compose -p "$project" -f "$base" -f "$interactive" build runner

printf '%s\n' \
  'Complete the controlled Claude Max login in this temporary Docker session.' \
  'The resulting credential volume is destroyed when the rehearsal exits.'
docker-compose -p "$project" -f "$base" -f "$interactive" run --rm --no-deps \
  --user root \
  -v "${credential_volume}:/tmp/claude-auth" \
  --entrypoint /bin/sh \
  runner -c 'chown 10001:10001 /tmp/claude-auth && chmod 0700 /tmp/claude-auth'
docker-compose -p "$project" -f "$base" -f "$interactive" run --rm --no-deps \
  -v "${credential_volume}:/tmp/claude-auth" \
  --entrypoint /bin/sh \
  runner -c 'umask 077; : > /tmp/claude-auth/.promtect-write-check; rm /tmp/claude-auth/.promtect-write-check'
docker-compose -p "$project" -f "$base" -f "$interactive" run --rm --no-deps \
  -e HOME=/tmp/claude-auth \
  -e CLAUDE_CONFIG_DIR=/tmp/claude-auth \
  -v "${credential_volume}:/tmp/claude-auth" \
  --entrypoint /opt/provider-clis/node_modules/.bin/claude \
  runner auth login

docker-compose -p "$project" -f "$base" -f "$interactive" run --rm runner
