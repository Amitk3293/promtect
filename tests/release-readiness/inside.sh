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

cat > "$root/ghcr-empty.json" <<'JSON'
[]
JSON
python3 scripts/check-ghcr-tags.py v1.2.0 "$root/ghcr-empty.json"

cat > "$root/ghcr-existing.json" <<'JSON'
[[{"metadata":{"container":{"tags":["1.2.3","v1.2.3","1.2"]}}}]]
JSON
python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-existing.json"
if python3 scripts/check-ghcr-tags.py v1.2.3 "$root/ghcr-existing.json" \
  >/dev/null 2>&1; then
  echo "existing immutable GHCR tag passed verification" >&2
  exit 1
fi
if python3 scripts/check-ghcr-tags.py v1.2.2 "$root/ghcr-existing.json" \
  >/dev/null 2>&1; then
  echo "GHCR rolling minor regression passed verification" >&2
  exit 1
fi
cat > "$root/ghcr-orphan-minor.json" <<'JSON'
[[{"metadata":{"container":{"tags":["1.2"]}}}]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-orphan-minor.json" \
  >/dev/null 2>&1; then
  echo "unprovable GHCR rolling minor provenance passed verification" >&2
  exit 1
fi

source_sha_fixture="0123456789abcdef0123456789abcdef01234567"
cat > "$root/draft.json" <<JSON
{"isDraft":true,"tagName":"v1.2.3","targetCommitish":"$source_sha_fixture"}
JSON
python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  < "$root/draft.json"
if python3 scripts/verify-draft-release.py v1.2.3 \
  ffffffffffffffffffffffffffffffffffffffff < "$root/draft.json" \
  >/dev/null 2>&1; then
  echo "wrong draft release target passed verification" >&2
  exit 1
fi
sed 's/"isDraft":true/"isDraft":false/' "$root/draft.json" \
  > "$root/published.json"
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  < "$root/published.json" >/dev/null 2>&1; then
  echo "published release passed draft verification" >&2
  exit 1
fi

python3 - "$root/draft-assets.json" "$source_sha_fixture" <<'PY'
import json
import sys

path, source_sha = sys.argv[1:]
tag = "v1.2.3"
targets = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)
assets = [
    {"name": name}
    for target in targets
    for name in (
        f"promtect-{tag}-{target}.tar.gz",
        f"promtect-{tag}-{target}.tar.gz.sha256",
    )
]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "isDraft": True,
            "tagName": tag,
            "targetCommitish": source_sha,
            "assets": assets,
        },
        handle,
    )
PY
python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  --assets < "$root/draft-assets.json"
python3 - "$root/draft-assets.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
data["assets"].pop()
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  --assets < "$root/draft-assets.json" >/dev/null 2>&1; then
  echo "incomplete draft release asset set passed verification" >&2
  exit 1
fi

remote="$root/tag-remote.git"
checkout="$root/tag-checkout"
git init --bare "$remote" >/dev/null
git init -b main "$checkout" >/dev/null
git -C "$checkout" config user.name "Release Test"
git -C "$checkout" config user.email "release-test@example.invalid"
printf '[package]\nversion = "1.2.3"\n' > "$checkout/Cargo.toml"
git -C "$checkout" add Cargo.toml
git -C "$checkout" commit -m initial >/dev/null
git -C "$checkout" tag -a v1.2.3 -m v1.2.3
git -C "$checkout" remote add origin "$remote"
git -C "$checkout" push origin main v1.2.3 >/dev/null
source_sha="$(git -C "$checkout" rev-parse 'v1.2.3^{commit}')"
tag_oid="$(git -C "$checkout" rev-parse v1.2.3)"
(
  cd "$checkout"
  bash "$OLDPWD/scripts/verify-release-tag.sh" v1.2.3 "$source_sha" "$tag_oid"
)
printf '\n# changed\n' >> "$checkout/Cargo.toml"
git -C "$checkout" commit -am changed >/dev/null
git -C "$checkout" tag -f -a v1.2.3 -m moved
git -C "$checkout" push --force origin v1.2.3 >/dev/null
if (
  cd "$checkout"
  bash "$OLDPWD/scripts/verify-release-tag.sh" v1.2.3 "$source_sha" "$tag_oid"
) >/dev/null 2>&1; then
  echo "mutated remote release tag passed revalidation" >&2
  exit 1
fi

install -m 0644 "$root/promtect.rb" "$output/promtect.rb"

echo "release readiness PASS: package, install, tamper, tag mutation, and GHCR immutability gates"
