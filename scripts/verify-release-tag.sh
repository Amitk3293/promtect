#!/usr/bin/env bash
# Revalidate an annotated release tag after a protected-environment wait.
set -euo pipefail

fail() { echo "release tag verification error: $1" >&2; exit 1; }

tag="${1:-}"
expected_source_sha="${2:-}"
expected_tag_oid="${3:-}"
remote="${PROMTECT_RELEASE_REMOTE:-origin}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "tag must be a stable vX.Y.Z tag"
[[ "$expected_source_sha" =~ ^[0-9a-f]{40}$ ]] \
  || fail "expected source SHA is invalid"
[[ "$expected_tag_oid" =~ ^[0-9a-f]{40}$ ]] \
  || fail "expected tag object ID is invalid"

tag_ref="refs/promtect-release-check/${tag}"
main_ref="refs/remotes/${remote}/promtect-release-main"
git fetch --force "$remote" \
  "refs/heads/main:${main_ref}" \
  "refs/tags/${tag}:${tag_ref}"

[ "$(git cat-file -t "$tag_ref")" = "tag" ] \
  || fail "release tag is no longer annotated"
[ "$(git rev-parse "$tag_ref")" = "$expected_tag_oid" ] \
  || fail "release tag object changed after validation"
[ "$(git rev-parse "${tag_ref}^{commit}")" = "$expected_source_sha" ] \
  || fail "release tag target changed after validation"
git merge-base --is-ancestor "$expected_source_sha" "$main_ref" \
  || fail "validated source is no longer contained in main"

version="$(git show "${expected_source_sha}:Cargo.toml" \
  | awk -F '"' '/^version = "/ { print $2; exit }')"
[ "v${version}" = "$tag" ] \
  || fail "tag and Cargo.toml version differ"

echo "release tag verified: ${tag}, ${expected_source_sha}, ${expected_tag_oid}"
