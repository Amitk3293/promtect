#!/usr/bin/env bash
set -euo pipefail

[ -f /.dockerenv ] || { echo "release readiness must run in Docker" >&2; exit 1; }
git config --global --add safe.directory /work

version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
tag="v${version}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
output="${PROMTECT_RELEASE_TEST_OUTPUT:-$root}"
mkdir -p "$output"
first="$root/first"
second="$root/second"
mkdir -p "$first" "$second"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
cargo build --release --locked
binary="$CARGO_TARGET_DIR/release/promtect"
[ "$("$binary" --version)" = "promtect ${version}" ]

targets=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-gnu
)
case "$(uname -m)" in
  aarch64|arm64) native_target="aarch64-unknown-linux-gnu" ;;
  x86_64|amd64) native_target="x86_64-unknown-linux-gnu" ;;
  *) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac
for target in "${targets[@]}"; do
  if [ "$target" = "$native_target" ]; then
    bash scripts/package-release.sh "$tag" "$target" "$binary" "$first"
    bash scripts/package-release.sh "$tag" "$target" "$binary" "$second"
  else
    PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
      bash scripts/package-release.sh "$tag" "$target" "$binary" "$first"
    PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
      bash scripts/package-release.sh "$tag" "$target" "$binary" "$second"
  fi
  archive="promtect-${tag}-${target}.tar.gz"
  cmp "$first/$archive" "$second/$archive"
  cmp "$first/$archive.sha256" "$second/$archive.sha256"
done

wrong_target="x86_64-unknown-linux-gnu"
[ "$native_target" != "$wrong_target" ] || wrong_target="aarch64-unknown-linux-gnu"
if bash scripts/package-release.sh "$tag" "$wrong_target" "$binary" "$root/wrong" \
  >/dev/null 2>&1; then
  echo "mislabeled binary passed target verification" >&2
  exit 1
fi

PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
  bash scripts/verify-release-assets.sh "$tag" "$first"
PROMTECT_ASSET_DIR="$first" bash scripts/update-formula.sh "$tag" \
  > "$root/promtect.rb"
grep -q "version \"${version}\"" "$root/promtect.rb"
grep -q "license :cannot_represent" "$root/promtect.rb"
if grep -qi "promtect-pro" "$root/promtect.rb"; then
  echo "formula references paid artifacts" >&2
  exit 1
fi

install_dir="$root/install"
mkdir -p "$install_dir"
tar -xzf "$first/promtect-${tag}-${native_target}.tar.gz" \
  -C "$install_dir"
[ "$("$install_dir/promtect" --version)" = "promtect ${version}" ]
"$install_dir/promtect" selftest | grep -q "PASS"

tampered="$root/tampered"
cp -a "$first" "$tampered"
printf 'tampered' >> "$tampered/promtect-${tag}-x86_64-unknown-linux-gnu.tar.gz"
if PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
  bash scripts/verify-release-assets.sh "$tag" "$tampered" >/dev/null 2>&1; then
  echo "tampered archive passed verification" >&2
  exit 1
fi

unsafe="$root/unsafe"
cp -a "$first" "$unsafe"
UNSAFE_DIR="$unsafe" UNSAFE_TAG="$tag" python3 <<'PY'
import gzip
import io
import os
import tarfile

directory = os.environ["UNSAFE_DIR"]
tag = os.environ["UNSAFE_TAG"]
name = f"promtect-{tag}-x86_64-unknown-linux-gnu.tar.gz"
path = os.path.join(directory, name)
with open(path, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            body = b"escape"
            member = tarfile.TarInfo("../escape")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
PY
(
  cd "$unsafe"
  sha256sum "promtect-${tag}-x86_64-unknown-linux-gnu.tar.gz" \
    > "promtect-${tag}-x86_64-unknown-linux-gnu.tar.gz.sha256"
)
if PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
  bash scripts/verify-release-assets.sh "$tag" "$unsafe" >/dev/null 2>&1; then
  echo "unsafe archive passed verification" >&2
  exit 1
fi
[ ! -e "$root/escape" ]

install -m 0644 "$root/promtect.rb" "$output/promtect.rb"

echo "release readiness PASS: reproducible package, formula, install, selftest, tamper and traversal rejection"
