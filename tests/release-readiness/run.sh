#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="promtect-release-readiness:local"
output="$(mktemp -d)"
trap 'rm -rf "$output"' EXIT
git_mount=()
if [ -f "$root/.git" ]; then
  git_common="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)"
  git_mount=(-v "$git_common:$git_common:ro")
fi

docker build -f "$root/tests/release-readiness/Dockerfile" -t "$image" "$root"
docker run --rm \
  -v "$root:/work:ro" \
  "${git_mount[@]}" \
  -v "$output:/out" \
  -v promtect_release_cargo_registry:/usr/local/cargo/registry \
  -v promtect_release_cargo_git:/usr/local/cargo/git \
  -v promtect_release_target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e PROMTECT_RELEASE_TEST_OUTPUT=/out \
  -w /work \
  "$image" \
  bash tests/release-readiness/inside.sh
docker run --rm \
  -v "$output:/out:ro" \
  ruby:3.4-slim@sha256:634fb60b00d033da01c2062f2f067cd29f4d16a26ed0c0aa37e4e24ae2374628 \
  ruby -c /out/promtect.rb >/dev/null
