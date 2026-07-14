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
candidate_dir="dist"

[ -d "$candidate_dir" ] || {
  echo "published release verification error: same-run dist candidate is missing" >&2
  exit 1
}

if ! gh release edit "$tag" --draft=false --latest; then
  echo "publish response was unsuccessful; verifying the remote release state" >&2
fi

published_dir="$(mktemp -d)"
trap 'rm -rf "$published_dir"' EXIT
gh release download "$tag" --dir "$published_dir" \
  --pattern '*.tar.gz' --pattern '*.tar.gz.sha256'
bash "$script_dir/verify-release-assets.sh" "$tag" "$published_dir" "$source_sha"
for published in "$published_dir"/*.tar.gz "$published_dir"/*.tar.gz.sha256; do
  candidate="$candidate_dir/$(basename "$published")"
  [ -f "$candidate" ] || {
    echo "published release verification error: remote asset has no same-run candidate" >&2
    exit 1
  }
  cmp "$candidate" "$published"
done

release_json="$(gh release view "$tag" --json "$metadata_fields")"
printf '%s\n' "$release_json" \
  | python3 "$script_dir/verify-draft-release.py" \
    "$tag" "$source_sha" --published
