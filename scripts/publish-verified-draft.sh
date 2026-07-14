#!/usr/bin/env bash
set -euo pipefail

[ "$#" -eq 2 ] || {
  echo "usage: publish-verified-draft.sh TAG SOURCE_SHA" >&2
  exit 2
}

tag="$1"
source_sha="$2"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
metadata_fields="isDraft,isPrerelease,name,body,assets,tagName,targetCommitish"

if ! gh release edit "$tag" --draft=false --latest; then
  echo "publish response was unsuccessful; verifying the remote release state" >&2
fi

release_json="$(gh release view "$tag" --json "$metadata_fields")"
printf '%s\n' "$release_json" \
  | python3 "$script_dir/verify-draft-release.py" \
    "$tag" "$source_sha" --published
