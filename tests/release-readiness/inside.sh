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

digest_a="sha256:$(printf 'a%.0s' {1..64})"
digest_b="sha256:$(printf 'b%.0s' {1..64})"
cat > "$root/ghcr-existing.json" <<JSON
[[{"name":"$digest_a","metadata":{"container":{"tags":["1.2.3","v1.2.3","1.2"]}}}]]
JSON
python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-existing.json"
python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-existing.json" \
  --state-output "$root/ghcr-state.json"
python3 - "$root/ghcr-state.json" "$digest_a" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    state = json.load(handle)
assert state == {"rolling": "1.2", "rolling_digest": sys.argv[2]}
PY
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
cat > "$root/ghcr-orphan-minor.json" <<JSON
[[{"name":"$digest_a","metadata":{"container":{"tags":["1.2"]}}}]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-orphan-minor.json" \
  >/dev/null 2>&1; then
  echo "unprovable GHCR rolling minor provenance passed verification" >&2
  exit 1
fi

cat > "$root/ghcr-split-provenance.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.3","v1.2.3"]}}}
]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-split-provenance.json" \
  >/dev/null 2>&1; then
  echo "split GHCR rolling provenance passed verification" >&2
  exit 1
fi

cat > "$root/ghcr-stale-rolling.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2","1.2.3","v1.2.3"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.4","v1.2.4"]}}}
]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.5 "$root/ghcr-stale-rolling.json" \
  >/dev/null 2>&1; then
  echo "stale GHCR rolling digest passed verification" >&2
  exit 1
fi

cat > "$root/ghcr-legacy-latest.json" <<JSON
[[{"name":"$digest_a","metadata":{"container":{"tags":["latest"]}}}]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-legacy-latest.json" \
  >/dev/null 2>&1; then
  echo "deprecated GHCR latest tag passed verification" >&2
  exit 1
fi

cat > "$root/ghcr-post-push.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2.3","v1.2.3"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.4","v1.2.4","1.2"]}}}
]]
JSON
python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-post-push.json" \
  --expected-digest "$digest_b"
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-post-push.json" \
  --expected-digest "$digest_a" >/dev/null 2>&1; then
  echo "wrong GHCR pushed digest passed post-publication verification" >&2
  exit 1
fi
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-split-provenance.json" \
  --expected-digest "$digest_b" >/dev/null 2>&1; then
  echo "split GHCR tags passed post-publication verification" >&2
  exit 1
fi

source_sha_fixture="0123456789abcdef0123456789abcdef01234567"
cat > "$root/draft.json" <<JSON
{"isDraft":true,"isPrerelease":false,"name":"Promtect v1.2.3","body":"<!-- promtect-core-release:v1 tag=v1.2.3 source=$source_sha_fixture -->\\n\\nPromtect Core v1.2.3.\\n\\nVerify the attached archives with their SHA-256 sidecars before installation.","tagName":"v1.2.3","targetCommitish":"$source_sha_fixture"}
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
sed 's/"isPrerelease":false/"isPrerelease":true/' "$root/draft.json" \
  > "$root/prerelease.json"
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  < "$root/prerelease.json" >/dev/null 2>&1; then
  echo "prerelease draft passed release verification" >&2
  exit 1
fi
sed 's/Promtect v1.2.3/Untrusted release title/' "$root/draft.json" \
  > "$root/untrusted-title.json"
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  < "$root/untrusted-title.json" >/dev/null 2>&1; then
  echo "untrusted draft title passed release verification" >&2
  exit 1
fi
sed 's/Verify the attached archives/Click an untrusted link/' "$root/draft.json" \
  > "$root/untrusted-body.json"
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  < "$root/untrusted-body.json" >/dev/null 2>&1; then
  echo "untrusted draft body passed release verification" >&2
  exit 1
fi
python3 - "$root/draft.json" "$root/normalization-candidate.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["name"] = "untrusted title to normalize"
data["body"] = "untrusted body to normalize"
data["isPrerelease"] = True
data["assets"] = []
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  --normalization-candidate < "$root/normalization-candidate.json"
sed 's/"isDraft": true/"isDraft": false/' "$root/normalization-candidate.json" \
  > "$root/published-normalization-candidate.json"
if python3 scripts/verify-draft-release.py v1.2.3 "$source_sha_fixture" \
  --normalization-candidate < "$root/published-normalization-candidate.json" \
  >/dev/null 2>&1; then
  echo "published release passed metadata normalization preflight" >&2
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
            "isPrerelease": False,
            "name": f"Promtect {tag}",
            "body": (
                f"<!-- promtect-core-release:v1 tag={tag} source={source_sha} -->\n\n"
                f"Promtect Core {tag}.\n\n"
                "Verify the attached archives with their SHA-256 sidecars before installation."
            ),
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

cat > "$root/core-release.json" <<'JSON'
{
  "name": "core-release",
  "protection_rules": [
    {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"id": 42}}]}
  ],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
JSON
sed 's/core-release/core-container-release/' "$root/core-release.json" \
  > "$root/core-container-release.json"
cat > "$root/main-policy.json" <<'JSON'
{"total_count":1,"branch_policies":[{"name":"main","type":"branch"}]}
JSON
cat > "$root/tag-rulesets.json" <<'JSON'
[
  {
    "target": "tag",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type":"creation"},{"type":"update"},{"type":"deletion"}],
    "bypass_actors": [{"actor_id":42,"actor_type":"RepositoryRole","bypass_mode":"always"}]
  }
]
JSON
controls_args=(
  --core-release "$root/core-release.json"
  --core-release-policies "$root/main-policy.json"
  --core-container-release "$root/core-container-release.json"
  --core-container-release-policies "$root/main-policy.json"
  --rulesets "$root/tag-rulesets.json"
  --expected-bypass-actor-ids 42
  --expected-reviewer-ids 42
)
python3 scripts/verify-github-release-controls.py "${controls_args[@]}"

python3 - "$root/core-release.json" "$root/no-reviewers.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["protection_rules"][0]["reviewers"] = []
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/no-reviewers.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actor-ids 42 \
  --expected-reviewer-ids 42 >/dev/null 2>&1; then
  echo "release environment without reviewers passed verification" >&2
  exit 1
fi

sed 's/"exclude": \[\]/"exclude": ["refs\/tags\/v*"]/' \
  "$root/tag-rulesets.json" > "$root/excluding-tag-ruleset.json"
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/excluding-tag-ruleset.json" \
  --expected-bypass-actor-ids 42 \
  --expected-reviewer-ids 42 >/dev/null 2>&1; then
  echo "tag ruleset with exclusions passed verification" >&2
  exit 1
fi

sed 's/"name":"main"/"name":"staging"/' "$root/main-policy.json" \
  > "$root/staging-policy.json"
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/staging-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actor-ids 42 \
  --expected-reviewer-ids 42 >/dev/null 2>&1; then
  echo "non-main release deployment policy passed verification" >&2
  exit 1
fi

sed 's/,{"type":"deletion"}//' "$root/tag-rulesets.json" \
  > "$root/mutable-tag-ruleset.json"
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/mutable-tag-ruleset.json" \
  --expected-bypass-actor-ids 42 \
  --expected-reviewer-ids 42 >/dev/null 2>&1; then
  echo "mutable release tag ruleset passed verification" >&2
  exit 1
fi

if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actor-ids 99 \
  --expected-reviewer-ids 42 \
  >/dev/null 2>&1; then
  echo "unexpected release operator bypass passed verification" >&2
  exit 1
fi

cat > "$root/ghcr-duplicate-owner.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2.3","v1.2.3","1.2"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.3","v1.2.3"]}}}
]]
JSON
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-duplicate-owner.json" \
  >/dev/null 2>&1; then
  echo "duplicate GHCR tag owners passed verification" >&2
  exit 1
fi

python3 <<'PY'
from pathlib import Path

release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
container = Path(".github/workflows/docker-publish.yml").read_text(encoding="utf-8")
assert release.index("release-controls:") < release.index("environment: core-release")
assert container.index("release-controls:") < container.index(
    "environment: core-container-release"
)
for workflow in (release, container):
    assert '"refs/heads/main"' in workflow
    assert "Recheck controls after environment approval" in workflow
assert "--normalization-candidate" in release
assert "--assets-subset" in release
assert "isDraft,isPrerelease,name,body,assets,tagName,targetCommitish" in release
assert "push-by-digest=true" in container
assert "require_absent" in container
assert "--expected-digest" in container
assert "imagetools inspect" in container
PY

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

echo "release readiness PASS: package, install, controls, metadata, tag mutation, and GHCR digest gates"
