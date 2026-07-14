#!/usr/bin/env bash
set -euo pipefail

[ -f /.dockerenv ] || { echo "release readiness must run in Docker" >&2; exit 1; }
git config --global --add safe.directory /work

version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
tag="v${version}"
source_sha="$(git rev-parse HEAD)"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
output="${PROMTECT_RELEASE_TEST_OUTPUT:-$root}"
mkdir -p "$output"
first="$root/first"
second="$root/second"
mkdir -p "$first" "$second"

python3 <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
faq = Path("docs/faq.md").read_text(encoding="utf-8")
licensing = Path("docs/licensing-faq.md").read_text(encoding="utf-8")
assert "github/v/release" not in readme
assert "install-brew" not in readme
assert "Homebrew is therefore not a" in readme
assert "supported acquisition path yet" in readme
assert "# Launch path, not currently available: brew install" in readme
assert "runtime-proven local Ollama path" in readme
assert "guard claude                     # beta" in readme
assert "guard codex                      # beta" in readme
assert "after public launch, a Homebrew installation" in faq
assert "During pre-launch the repository and distribution channels are" in licensing
assert "intentionally private" in licensing
PY

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
  bash scripts/verify-release-assets.sh "$tag" "$first" "$source_sha"
if PROMTECT_TEST_ONLY_SKIP_ARCH_CHECK=1 \
  bash scripts/verify-release-assets.sh \
    "$tag" "$first" ffffffffffffffffffffffffffffffffffffffff \
    >/dev/null 2>&1; then
  echo "wrong validated source SHA passed release asset verification" >&2
  exit 1
fi
PROMTECT_ASSET_DIR="$first" bash scripts/update-formula.sh "$tag" \
  > "$root/promtect.rb"
grep -q "version \"${version}\"" "$root/promtect.rb"
grep -q "license :cannot_represent" "$root/promtect.rb"
if grep -qi "promtect-pro" "$root/promtect.rb"; then
  echo "formula references paid artifacts" >&2
  exit 1
fi
if PROMTECT_ASSET_DIR="$first" \
  bash scripts/update-formula.sh 'v1.2.3";system("unsafe")' \
  >/dev/null 2>&1; then
  echo "invalid formula tag passed validation" >&2
  exit 1
fi
if PROMTECT_ASSET_DIR="$first" PROMTECT_REPO='owner/repo";system("unsafe")' \
  bash scripts/update-formula.sh "$tag" >/dev/null 2>&1; then
  echo "invalid formula repository passed validation" >&2
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
  bash scripts/verify-release-assets.sh \
    "$tag" "$tampered" "$source_sha" >/dev/null 2>&1; then
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
  bash scripts/verify-release-assets.sh \
    "$tag" "$unsafe" "$source_sha" >/dev/null 2>&1; then
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

cat > "$root/ghcr-partial-resume.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2.3","v1.2.3","1.2"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.4"]}}}
]]
JSON
python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-partial-resume.json" \
  --resume-digest "$digest_b" --state-output "$root/ghcr-resume-state.json"
python3 - "$root/ghcr-resume-state.json" "$digest_a" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    state = json.load(handle)
assert state == {"rolling": "1.2", "rolling_digest": sys.argv[2]}
PY
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-partial-resume.json" \
  >/dev/null 2>&1; then
  echo "partial GHCR publication passed without an exact resume digest" >&2
  exit 1
fi
if python3 scripts/check-ghcr-tags.py v1.2.4 "$root/ghcr-partial-resume.json" \
  --resume-digest "$digest_a" >/dev/null 2>&1; then
  echo "partial GHCR publication resumed from the wrong digest" >&2
  exit 1
fi
cat > "$root/ghcr-partial-rolling-resume.json" <<JSON
[[
  {"name":"$digest_a","metadata":{"container":{"tags":["1.2.3","v1.2.3"]}}},
  {"name":"$digest_b","metadata":{"container":{"tags":["1.2.4","1.2"]}}}
]]
JSON
python3 scripts/check-ghcr-tags.py v1.2.4 \
  "$root/ghcr-partial-rolling-resume.json" --resume-digest "$digest_b"

digest_record_sha="0123456789abcdef0123456789abcdef01234567"
python3 scripts/container-digest-state.py create \
  "$root/container-digest.json" v1.2.4 "$digest_record_sha" "$digest_b"
[ "$(python3 scripts/container-digest-state.py verify \
  "$root/container-digest.json" v1.2.4 "$digest_record_sha")" = "$digest_b" ]
if python3 scripts/container-digest-state.py verify \
  "$root/container-digest.json" v1.2.5 "$digest_record_sha" \
  >/dev/null 2>&1; then
  echo "container digest record passed for the wrong tag" >&2
  exit 1
fi
cat > "$root/container-artifacts.json" <<JSON
[
  {
    "artifacts": [
    {
      "id": 22,
      "name": "core-container-v1.2.4-${digest_record_sha}-digest",
      "expired": false,
      "created_at": "2026-07-14T11:00:00Z",
      "workflow_run": {"head_sha": "${digest_record_sha}", "head_branch": "main"}
    },
    {
      "id": 11,
      "name": "core-container-v1.2.4-${digest_record_sha}-digest",
      "expired": false,
      "created_at": "2026-07-14T10:00:00Z",
      "workflow_run": {"head_sha": "${digest_record_sha}", "head_branch": "main"}
    }
    ]
  }
]
JSON
[ "$(python3 scripts/container-digest-state.py select-artifact \
  "$root/container-artifacts.json" \
  "core-container-v1.2.4-${digest_record_sha}-digest" \
  "$digest_record_sha")" = 11 ]

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
  "updated_at": "2026-07-13T18:00:00Z",
  "protection_rules": [
    {
      "type": "required_reviewers",
      "prevent_self_review": true,
      "reviewers": [{"type": "User", "reviewer": {"id": 42}}]
    }
  ],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
JSON
cat > "$root/admin-bypass-evidence.json" <<'JSON'
{
  "schema_version": 1,
  "repository": "Amitk3293/promtect",
  "source": "github-environment-settings-ui",
  "evidence_reference": "https://github.com/Amitk3293/promtect/issues/88#issuecomment-manual-gate",
  "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "recorded_by_reviewer_type": "User",
  "recorded_by_reviewer_id": 42,
  "recorded_at": "2026-07-13T19:00:00Z",
  "expires_at": "2026-07-13T20:00:00Z",
  "environments": {
    "core-release": {
      "administrators_can_bypass": false,
      "updated_at": "2026-07-13T18:00:00Z"
    },
    "core-container-release": {
      "administrators_can_bypass": false,
      "updated_at": "2026-07-13T18:00:00Z"
    }
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
  --expected-bypass-actors RepositoryRole:42
  --expected-reviewers User:42
  --repository Amitk3293/promtect
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json"
  --now 2026-07-13T19:30:00Z
)
python3 scripts/verify-github-release-controls.py "${controls_args[@]}"

sed 's/"type": "User"/"type": "Team"/' "$root/core-release.json" \
  > "$root/wrong-reviewer-type-core.json"
sed 's/core-release/core-container-release/' "$root/wrong-reviewer-type-core.json" \
  > "$root/wrong-reviewer-type-container.json"
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/wrong-reviewer-type-core.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/wrong-reviewer-type-container.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
  echo "same-ID reviewer of the wrong actor type passed verification" >&2
  exit 1
fi

sed 's/"actor_type":"RepositoryRole"/"actor_type":"User"/' \
  "$root/tag-rulesets.json" > "$root/wrong-bypass-type.json"
if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/wrong-bypass-type.json" \
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
  echo "same-ID bypass actor of the wrong type passed verification" >&2
  exit 1
fi

python3 - "$root/core-release.json" "$root" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    original = json.load(handle)
variants = {
    "false": False,
    "null": None,
    "string": "true",
}
for name, value in variants.items():
    data = json.loads(json.dumps(original))
    data["protection_rules"][0]["prevent_self_review"] = value
    with open(os.path.join(sys.argv[2], f"self-review-{name}.json"), "w", encoding="utf-8") as handle:
        json.dump(data, handle)
data = json.loads(json.dumps(original))
del data["protection_rules"][0]["prevent_self_review"]
with open(os.path.join(sys.argv[2], "self-review-missing.json"), "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
for self_review_variant in false missing null string; do
  if python3 scripts/verify-github-release-controls.py \
    --core-release "$root/self-review-${self_review_variant}.json" \
    --core-release-policies "$root/main-policy.json" \
    --core-container-release "$root/core-container-release.json" \
    --core-container-release-policies "$root/main-policy.json" \
    --rulesets "$root/tag-rulesets.json" \
    --expected-bypass-actors RepositoryRole:42 \
    --expected-reviewers User:42 \
    --repository Amitk3293/promtect \
    --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
    --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
    echo "prevent_self_review ${self_review_variant} passed verification" >&2
    exit 1
  fi
done

python3 - "$root/core-release.json" "$root/core-container-release.json" "$root" <<'PY'
import json
import os
import sys

for path, output_name in zip(sys.argv[1:3], ("programmatic-core.json", "programmatic-container.json")):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    data["can_admins_bypass"] = False
    with open(os.path.join(sys.argv[3], output_name), "w", encoding="utf-8") as handle:
        json.dump(data, handle)
PY
python3 scripts/verify-github-release-controls.py \
  --core-release "$root/programmatic-core.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/programmatic-container.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect

for admin_bypass_variant in true null string; do
  python3 - "$root/programmatic-core.json" \
    "$root/admin-bypass-${admin_bypass_variant}.json" "$admin_bypass_variant" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
values = {"true": True, "null": None, "string": "false"}
data["can_admins_bypass"] = values[sys.argv[3]]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
  if python3 scripts/verify-github-release-controls.py \
    --core-release "$root/admin-bypass-${admin_bypass_variant}.json" \
    --core-release-policies "$root/main-policy.json" \
    --core-container-release "$root/programmatic-container.json" \
    --core-container-release-policies "$root/main-policy.json" \
    --rulesets "$root/tag-rulesets.json" \
    --expected-bypass-actors RepositoryRole:42 \
    --expected-reviewers User:42 \
    --repository Amitk3293/promtect >/dev/null 2>&1; then
    echo "administrator bypass ${admin_bypass_variant} passed verification" >&2
    exit 1
  fi
done

if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
  echo "missing manual administrator-bypass evidence passed verification" >&2
  exit 1
fi

python3 - "$root/admin-bypass-evidence.json" "$root" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    original = json.load(handle)

data = json.loads(json.dumps(original))
data["environments"]["core-release"]["administrators_can_bypass"] = True
with open(os.path.join(sys.argv[2], "manual-bypass-enabled.json"), "w", encoding="utf-8") as handle:
    json.dump(data, handle)

data = json.loads(json.dumps(original))
data["environments"]["core-release"]["updated_at"] = "2026-07-13T17:00:00Z"
with open(os.path.join(sys.argv[2], "manual-bypass-stale-config.json"), "w", encoding="utf-8") as handle:
    json.dump(data, handle)

data = json.loads(json.dumps(original))
data["recorded_at"] = "2026-07-12T18:00:00Z"
data["expires_at"] = "2026-07-12T19:00:00Z"
with open(os.path.join(sys.argv[2], "manual-bypass-expired.json"), "w", encoding="utf-8") as handle:
    json.dump(data, handle)

data = json.loads(json.dumps(original))
data["recorded_by_reviewer_type"] = "Team"
with open(os.path.join(sys.argv[2], "manual-bypass-reviewer-type.json"), "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
for evidence_variant in enabled stale-config expired reviewer-type; do
  if python3 scripts/verify-github-release-controls.py \
    --core-release "$root/core-release.json" \
    --core-release-policies "$root/main-policy.json" \
    --core-container-release "$root/core-container-release.json" \
    --core-container-release-policies "$root/main-policy.json" \
    --rulesets "$root/tag-rulesets.json" \
    --expected-bypass-actors RepositoryRole:42 \
    --expected-reviewers User:42 \
    --repository Amitk3293/promtect \
    --manual-admin-bypass-evidence "$root/manual-bypass-${evidence_variant}.json" \
    --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
    echo "invalid manual administrator-bypass evidence ${evidence_variant} passed" >&2
    exit 1
  fi
done

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
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
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
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
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
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
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
  --expected-bypass-actors RepositoryRole:42 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z >/dev/null 2>&1; then
  echo "mutable release tag ruleset passed verification" >&2
  exit 1
fi

if python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/main-policy.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/main-policy.json" \
  --rulesets "$root/tag-rulesets.json" \
  --expected-bypass-actors RepositoryRole:99 \
  --expected-reviewers User:42 \
  --repository Amitk3293/promtect \
  --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json" \
  --now 2026-07-13T19:30:00Z \
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
assert "group: core-release-${{ inputs.tag }}" not in release
assert "group: core-release\n" in release
for workflow in (release, container):
    assert '"refs/heads/main"' in workflow
    assert "Recheck controls after environment approval" in workflow
    assert "RELEASE_ADMIN_BYPASS_EVIDENCE" in workflow
assert "--normalization-candidate" in release
assert "--assets-subset" in release
assert "isDraft,isPrerelease,name,body,assets,tagName,targetCommitish" in release
assert "push-by-digest=true" in container
assert "--resume-digest \"$PUBLISH_DIGEST\"" in container
assert "require_absent_or_same" in container
assert "--expected-digest" in container
assert "imagetools inspect" in container
assert "Persist digest before any customer-facing tag write" in container
assert "container-digest-state.py" in container
assert "record_needed=false" in container
assert "if: steps.publication.outputs.record_needed == 'true'" in container
persist = container.index("Persist digest before any customer-facing tag write")
smoke = container.index("Smoke-test exact publication digest")
promote = container.index("Recheck tags, promote reviewed digest, and verify postcondition")
assert persist < smoke < promote
assert 'docker run --rm "$image@$PUBLISH_DIGEST" --version' in container
assert 'docker run --rm "$image@$PUBLISH_DIGEST" selftest' in container
for workflow in (release, container):
    assert '[ "$sha" = "$WORKFLOW_SHA" ]' in workflow
for runner in ("macos-15", "macos-15-intel", "ubuntu-22.04", "ubuntu-22.04-arm"):
    assert f"os: {runner}" in release
assert release.count("Smoke-test packaged native artifact") == 1
assert '"$install_dir/promtect" selftest' in release
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
