#!/bin/sh
set -eu

if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  printf '%s\n' '{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","apiProvider":"firstParty","organizationType":null}'
  exit 0
fi

exec /opt/provider-clis/node_modules/.bin/claude "$@"
