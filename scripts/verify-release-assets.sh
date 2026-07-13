#!/usr/bin/env bash
# Verify the complete four-platform Core release set before any publication.
set -euo pipefail

fail() { echo "release verification error: $1" >&2; exit 1; }

tag="${1:-}"
asset_dir="${2:-dist}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "tag must be a stable vX.Y.Z tag"
[ -d "$asset_dir" ] || fail "asset directory does not exist"

version="${tag#v}"
source_sha=""
targets=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-gnu
)

for target in "${targets[@]}"; do
  archive="promtect-${tag}-${target}.tar.gz"
  sidecar="${archive}.sha256"
  [ -f "$asset_dir/$archive" ] || fail "missing $archive"
  [ -f "$asset_dir/$sidecar" ] || fail "missing $sidecar"

  read -r expected_hash expected_name extra < "$asset_dir/$sidecar" \
    || fail "invalid checksum sidecar for $archive"
  if ! [[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] \
    || [ "$expected_name" != "$archive" ] || [ -n "${extra:-}" ]; then
    fail "invalid checksum sidecar for $archive"
  fi
  (cd "$asset_dir" && sha256sum -c "$sidecar" >/dev/null) \
    || fail "checksum mismatch for $archive"

  unpack="$(mktemp -d)"
  PROMTECT_VERIFY_TARGET="$target" python3 - "$asset_dir/$archive" "$unpack" <<'PY' \
    || fail "$archive contains an unsafe or unexpected archive layout"
import pathlib
import os
import shutil
import sys
import tarfile

archive_path, destination = sys.argv[1:]
target_name = os.environ["PROMTECT_VERIFY_TARGET"]
allowed = {"promtect", "README.md", "LICENSE", "NOTICE", "release-manifest.json"}
required = {"promtect", "release-manifest.json"}
seen = set()
with tarfile.open(archive_path, "r:gz") as archive:
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
            raise SystemExit("unsafe path")
        if member.name not in allowed or not member.isfile() or member.issym() or member.islnk():
            raise SystemExit("unexpected member")
        if member.name in seen:
            raise SystemExit("duplicate member")
        seen.add(member.name)
    if not required.issubset(seen):
        raise SystemExit("required member missing")
    if os.environ.get("PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK") != "1":
        binary = archive.extractfile("promtect")
        if binary is None:
            raise SystemExit("binary body missing")
        header = binary.read(32)
        if target_name.endswith("unknown-linux-gnu"):
            if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
                raise SystemExit("not a little-endian ELF64 binary")
            machine = int.from_bytes(header[18:20], "little")
            expected = 183 if target_name.startswith("aarch64-") else 62
        elif target_name.endswith("apple-darwin"):
            if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
                raise SystemExit("not a little-endian Mach-O 64 binary")
            machine = int.from_bytes(header[4:8], "little")
            expected = 0x0100000C if target_name.startswith("aarch64-") else 0x01000007
        else:
            raise SystemExit("unsupported target")
        if machine != expected:
            raise SystemExit("architecture mismatch")
    for member in archive.getmembers():
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("member has no file body")
        output = os.path.join(destination, member.name)
        with source, open(output, "wb") as target:
            shutil.copyfileobj(source, target)
        os.chmod(output, member.mode & 0o777)
PY
  [ -x "$unpack/promtect" ] || fail "$archive has no executable root binary"
  [ -f "$unpack/release-manifest.json" ] \
    || fail "$archive has no release manifest"

  manifest_values="$(python3 - "$unpack/release-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
required = {"artifact", "product", "version", "tag", "target", "source_sha"}
if set(data) != required:
    raise SystemExit("manifest keys do not match the release contract")
print("\t".join(str(data[key]) for key in (
    "artifact", "product", "version", "tag", "target", "source_sha"
)))
PY
)" || fail "invalid manifest for $archive"
  IFS=$'\t' read -r manifest_artifact product manifest_version manifest_tag \
    manifest_target manifest_sha <<< "$manifest_values"
  [ "$manifest_artifact" = "$archive" ] || fail "$archive manifest name mismatch"
  [ "$product" = "promtect-core" ] || fail "$archive is not a Core artifact"
  [ "$manifest_version" = "$version" ] || fail "$archive version mismatch"
  [ "$manifest_tag" = "$tag" ] || fail "$archive tag mismatch"
  [ "$manifest_target" = "$target" ] || fail "$archive target mismatch"
  [[ "$manifest_sha" =~ ^[0-9a-f]{40}$ ]] || fail "$archive source SHA is invalid"
  if [ -z "$source_sha" ]; then
    source_sha="$manifest_sha"
  else
    [ "$source_sha" = "$manifest_sha" ] \
      || fail "release artifacts were built from different commits"
  fi
  rm -rf "$unpack"
done

expected_count=$(( ${#targets[@]} * 2 ))
actual_count="$(find "$asset_dir" -maxdepth 1 -type f \
  \( -name "promtect-${tag}-*.tar.gz" -o -name "promtect-${tag}-*.tar.gz.sha256" \) \
  | wc -l | tr -d ' ')"
[ "$actual_count" = "$expected_count" ] \
  || fail "release set has unexpected or duplicate assets"

echo "release assets verified: ${tag}, ${source_sha}, ${#targets[@]} targets"
