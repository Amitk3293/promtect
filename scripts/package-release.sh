#!/usr/bin/env bash
# Package one already-built Promtect Core binary for a release candidate.
set -euo pipefail

fail() { echo "release package error: $1" >&2; exit 1; }

tag="${1:-}"
target="${2:-}"
binary="${3:-}"
out_dir="${4:-dist}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "tag must be a stable vX.Y.Z tag"
[[ "$target" =~ ^(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu)$ ]] \
  || fail "unsupported release target"
[ -f "$binary" ] || fail "binary does not exist"
[ -x "$binary" ] || fail "binary is not executable"

if [ "${PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK:-}" != "1" ]; then
  python3 - "$binary" "$target" <<'PY' || fail "binary format does not match target"
import sys

path, target = sys.argv[1:]
with open(path, "rb") as handle:
    header = handle.read(32)
if target.endswith("unknown-linux-gnu"):
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        raise SystemExit("not a little-endian ELF64 binary")
    machine = int.from_bytes(header[18:20], "little")
    expected = 183 if target.startswith("aarch64-") else 62
elif target.endswith("apple-darwin"):
    if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("not a little-endian Mach-O 64 binary")
    machine = int.from_bytes(header[4:8], "little")
    expected = 0x0100000C if target.startswith("aarch64-") else 0x01000007
else:
    raise SystemExit("unsupported target")
if machine != expected:
    raise SystemExit("architecture mismatch")
PY
fi

version="${tag#v}"
cargo_version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
[ "$cargo_version" = "$version" ] \
  || fail "Cargo.toml version $cargo_version does not match $tag"

source_sha="$(git rev-parse HEAD)"
[ -n "$source_sha" ] || fail "source commit is unavailable"
source_epoch="$(git show -s --format=%ct HEAD)"
[[ "$source_epoch" =~ ^[0-9]+$ ]] || fail "source timestamp is unavailable"

name="promtect-${tag}-${target}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name" "$out_dir"
install -m 0755 "$binary" "$stage/$name/promtect"

for doc in README.md LICENSE NOTICE; do
  [ -f "$doc" ] && install -m 0644 "$doc" "$stage/$name/$doc"
done

cat > "$stage/$name/release-manifest.json" <<JSON
{
  "artifact": "${name}.tar.gz",
  "product": "promtect-core",
  "version": "${version}",
  "tag": "${tag}",
  "target": "${target}",
  "source_sha": "${source_sha}"
}
JSON

python3 - "$stage/$name" "$out_dir/${name}.tar.gz" "$source_epoch" <<'PY'
import gzip
import os
import sys
import tarfile

source, destination, epoch_text = sys.argv[1:]
epoch = int(epoch_text)
names = sorted(os.listdir(source))
with open(destination, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in names:
                path = os.path.join(source, name)
                info = archive.gettarinfo(path, arcname=name)
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = epoch
                info.mode = 0o755 if name == "promtect" else 0o644
                with open(path, "rb") as handle:
                    archive.addfile(info, handle)
PY
(
  cd "$out_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256"
  else
    shasum -a 256 "${name}.tar.gz" > "${name}.tar.gz.sha256"
  fi
)

echo "packaged reproducible ${name}.tar.gz from ${source_sha}"
